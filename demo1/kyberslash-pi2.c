#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include "kem.h"
#include "poly.h"
#include "polyvec.h"
#include "indcpa.h"
#include "reduce.h"
#include "randombytes.h"

#define EVE_CPU 0
#define BOB_CPU 3

static int pipe_eve_to_bob[2];
static int pipe_bob_to_eve[2];
static int pipe_bob_to_judge[2];
static int pipe_eve_to_judge[2];

static void writeall(int fd, const void *x, long long n) {
  while (n > 0) {
    ssize_t w = n < 65536 ? n : 65536;
    w = write(fd, x, w);
    if (w < 1) _exit(111);
    x = w + (char *)x;
    n -= w;
  }
}

static void readall(int fd, void *x, long long n) {
  while (n > 0) {
    ssize_t r = n < 65536 ? n : 65536;
    r = read(fd, x, r);
    if (r < 1) _exit(111);
    x = r + (char *)x;
    n -= r;
  }
}

static int fddev = -1;

static long long ticks(void) {
  int64_t result;

  if (read(fddev, &result, sizeof result) != sizeof result) return 0;
  return result;
}

static void ticks_enable(void) {
  if (fddev == -1) {
    static struct perf_event_attr attr;

    memset(&attr, 0, sizeof attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(struct perf_event_attr);
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    fddev = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (fddev == -1) {
      printf("perf_event_open failed, aborting\n");
      exit(111);
    }

    ioctl(fddev, PERF_EVENT_IOC_RESET, 0);
    ioctl(fddev, PERF_EVENT_IOC_ENABLE, 0);
  }
}

// ----- bob

uint8_t bob_pk[CRYPTO_PUBLICKEYBYTES];
uint8_t bob_sk_bytes[CRYPTO_SECRETKEYBYTES];
polyvec bob_sk;

static void bob_keypair(void) {
  crypto_kem_keypair(bob_pk, bob_sk_bytes);
  polyvec_frombytes(&bob_sk, bob_sk_bytes);
  polyvec_invntt_tomont(&bob_sk);
  for (long long j = 0; j < KYBER_K; ++j)
    for (long long i = 0; i < KYBER_N; ++i) bob_sk.vec[j].coeffs[i] = montgomery_reduce(bob_sk.vec[j].coeffs[i]);
  printf("pk ");
  for (long long i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i) printf("%02x", bob_pk[i]);
  printf("\n");
  fflush(stdout);
}

uint8_t bob_ct[CRYPTO_CIPHERTEXTBYTES];
uint8_t bob_ss[CRYPTO_BYTES];

static void bob(void) {
  long long t;

  ticks_enable();
  bob_keypair();
  writeall(pipe_bob_to_judge[1], (void *)&bob_sk, sizeof bob_sk);
  writeall(pipe_bob_to_eve[1], (void *)bob_pk, sizeof bob_pk);

  for (;;) {
    t = ticks();
    writeall(pipe_bob_to_eve[1], (void *)&t, sizeof t);
    readall(pipe_eve_to_bob[0], (void *)bob_ct, sizeof bob_ct);
    crypto_kem_dec(bob_ss, bob_ct, bob_sk_bytes);
  }
}

// ----- eve

static long long timestamp(void) {
  long long result;
  readall(pipe_bob_to_eve[0], (void *)&result, sizeof result);
  return result;
}

static void send_ciphertext(const uint8_t *ct) { writeall(pipe_eve_to_bob[1], (void *)ct, CRYPTO_CIPHERTEXTBYTES); }

polyvec pkvec;
polyvec matrix[KYBER_K];

static void eve_unpackpk(void) {
  polyvec_frombytes(&pkvec, bob_pk);
  polyvec_invntt_tomont(&pkvec);
  for (long long j = 0; j < KYBER_K; ++j)
    for (long long i = 0; i < KYBER_N; ++i) pkvec.vec[j].coeffs[i] = montgomery_reduce(pkvec.vec[j].coeffs[i]);

  gen_matrix(matrix, bob_pk + KYBER_POLYVECBYTES, 0);
}

static void int64_minmax(long long *a, long long *b) {
  int64_t ab = *b ^ *a, c = *b - *a;
  c = ((((c ^ *b) & ab) ^ c) >> 63) & ab;
  *a ^= c;
  *b ^= c;
}

static void sort(long long *x, long long n) {
  long long top = 1, p, q, r, i;
  if (n < 2) return;
  while (top < n - top) top += top;
  for (i = 0; i < n; ++i) x[i] ^= 0x8000000000000000;
  for (p = top; p > 0; p >>= 1) {
    for (i = 0; i < n - p; ++i)
      if (!(i & p)) int64_minmax(&x[i], &x[i + p]);
    i = 0;
    for (q = top; q > p; q >>= 1) {
      for (; i < n - q; ++i) {
        if (!(i & p)) {
          long long a = x[i + p];
          for (r = q; r > p; r >>= 1) int64_minmax(&a, &x[i + r]);
          x[i + p] = a;
        }
      }
    }
  }
  for (i = 0; i < n; ++i) x[i] ^= 0x8000000000000000;
}

#define IQM_SCALE 16

// assumes x is sorted
static long long scaled_iqm(long long *x, long long n) {
  long long left = 0;
  long long right = n;
  long long total = 0;
  while ((right - left - 2) * 2 >= n) {
    ++left;
    --right;
  }
  for (long long i = left; i < right; ++i) total += x[i];
  return (total * IQM_SCALE) / (right - left);
}

#define TEMPLATE_LOOPS 32
#define TEMPLATE_TIMINGS 15
#define TEMPLATE_D 8
long long template_dlist[TEMPLATE_D] = {0, 192, 833, 1216, 2497, 2881, 3264, 3328};
long long template_scaledcycles[TEMPLATE_D];

#define MULTIPLIERS 7
long long multipliers[MULTIPLIERS] = {0, 3, -3, 72, -72, 107, -107};
long long Csel[MULTIPLIERS] = {0, 0, 0, 208, 208, 208, 208};

#define CYCLE_REPS 1

#define SNUM 7
long long slist[SNUM] = {-3, -2, -1, 0, 1, 2, 3};
long long spredict[SNUM][MULTIPLIERS];

static void template(void) {
  long long order[TEMPLATE_D];
  long long t[TEMPLATE_TIMINGS + 1];
  long long data[TEMPLATE_D][TEMPLATE_LOOPS];
  long long result[TEMPLATE_D];
  uint8_t msg[KYBER_INDCPA_MSGBYTES];
  poly p;

  for (long long loop = 0; loop < TEMPLATE_LOOPS; ++loop) {
    randombytes((void *)order, sizeof order);
    for (long long b = 0; b < TEMPLATE_D; ++b) {
      order[b] &= 0x0fffffffffffffff;
      order[b] = (order[b] / TEMPLATE_D) * TEMPLATE_D + b;
    }
    sort(order, TEMPLATE_D);
    for (long long b = 0; b < TEMPLATE_D; ++b) {
      long long dpos = order[b] % TEMPLATE_D;
      long long d = template_dlist[dpos];
      for (long long i = 0; i < KYBER_N; ++i) p.coeffs[i] = d;
      for (long long i = 0;; ++i) {
        t[i] = ticks();
        if (i == TEMPLATE_TIMINGS) break;
        poly_tomsg(msg, &p);
      }
      for (long long i = 0; i < TEMPLATE_TIMINGS; ++i) t[i] = t[i + 1] - t[i];
      sort(t, TEMPLATE_TIMINGS);
      result[b] = scaled_iqm(t, TEMPLATE_TIMINGS);
    }
    for (long long b = 0; b < TEMPLATE_D; ++b) {
      long long dpos = order[b] % TEMPLATE_D;
      data[dpos][loop] = result[b];
    }
  }

  printf("iqm_scale %d\n", IQM_SCALE);

  for (long long dpos = 0; dpos < TEMPLATE_D; ++dpos) {
    long long d = template_dlist[dpos];
    sort(data[dpos], TEMPLATE_LOOPS);
    template_scaledcycles[dpos] = scaled_iqm(data[dpos], TEMPLATE_LOOPS) / (256 * IQM_SCALE);
    printf("template_scaledcycles %lld %lld %lld\n", d, d * 2 + 1664, template_scaledcycles[dpos]);
  }

  printf("cycle_reps %d\n", CYCLE_REPS);

  for (long long spos = 0; spos < SNUM; ++spos) {
    long long s = slist[spos];
    for (long long whichm = 0; whichm < MULTIPLIERS; ++whichm) {
      long long m = multipliers[whichm];
      long long ms = Csel[whichm] - m * s;
      long long predict;
      ms %= 3329;
      ms += 3329;
      ms %= 3329;
      ms *= 2;
      ms += 1664;
      predict = template_scaledcycles[0];
      for (long long dpos = 1; dpos < TEMPLATE_D; ++dpos) {
        long long d = template_dlist[dpos];
        if (d * 2 + 1664 <= ms) predict = template_scaledcycles[dpos];
      }
      spredict[spos][whichm] = CYCLE_REPS * predict;
    }
  }

  for (long long spos = 0; spos < SNUM; ++spos) {
    long long s = slist[spos];
    printf("spredict %lld", s);
    for (long long whichm = 0; whichm < MULTIPLIERS; ++whichm) printf(" %lld,%lld:%lld", multipliers[whichm], Csel[whichm], spredict[spos][whichm]);
    printf("\n");
  }

  fflush(stdout);
}

long long confidence[KYBER_K * KYBER_N];
polyvec eve_sk;
polyvec eve_sk_backup;

static int eve_happy(long long sample) {
  sort(confidence, KYBER_K * KYBER_N);

  for (long long b = 0; b < 10; ++b) {
    long long pos = confidence[b] % KYBER_N;
    long long segment = (confidence[b] / KYBER_N) % KYBER_K;
    long long ranking = confidence[b] / (KYBER_N * KYBER_K);
    printf("try %lld %lld %lld %lld %d %d\n", sample, b, segment * KYBER_N + pos, ranking, eve_sk.vec[segment].coeffs[pos], eve_sk_backup.vec[segment].coeffs[pos]);
  }
  fflush(stdout);

  // could do mitm or more serious lattice attack here
  for (long long search = 0; search < 1024; ++search) {
    polyvec eve_sk_mix = eve_sk;
    polyvec x, y;
    int happy = 1;

    for (long long b = 0; b < 10; ++b) {
      if (search & (1 << b)) {
        long long pos = confidence[b] % KYBER_N;
        long long segment = (confidence[b] / KYBER_N) % KYBER_K;
        eve_sk_mix.vec[segment].coeffs[pos] = eve_sk_backup.vec[segment].coeffs[pos];
      }
    }
    printf("search %lld", search);
    for (long long b = 0; b < 10; ++b) {
      long long pos = confidence[b] % KYBER_N;
      long long segment = (confidence[b] / KYBER_N) % KYBER_K;
      printf(" %lld:%d", segment * KYBER_N + pos, eve_sk_mix.vec[segment].coeffs[pos]);
    }
    printf("\n");
    fflush(stdout);

    x = eve_sk_mix;
    polyvec_ntt(&x);
    for (long long i = 0; i < KYBER_K; ++i) {
      polyvec_basemul_acc_montgomery(&y.vec[i], &matrix[i], &x);
      poly_tomont(&y.vec[i]);
    }
    polyvec_invntt_tomont(&y);
    for (long long j = 0; j < KYBER_K; ++j)
      for (long long i = 0; i < KYBER_N; ++i) y.vec[j].coeffs[i] = montgomery_reduce(y.vec[j].coeffs[i]);
    for (long long i = 0; i < KYBER_K; ++i) poly_sub(&y.vec[i], &y.vec[i], &pkvec.vec[i]);
    polyvec_reduce(&y);
    for (long long i = 0; i < KYBER_K; ++i)
      for (long long j = 0; j < KYBER_N; ++j) {
        int c = y.vec[i].coeffs[j];
        if (c < -10) happy = 0;
        if (c > 10) happy = 0;
      }

    if (happy) {
      eve_sk = eve_sk_mix;
      return 1;
    }
  }
  return 0;
}

static int poly_compress_coeff(int c) {
  int16_t u = c;
  u += (u >> 15) & KYBER_Q;
#if (KYBER_POLYCOMPRESSEDBYTES == 128)
  return ((((uint16_t)u << 4) + KYBER_Q / 2) / KYBER_Q) & 15;
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
  return ((((uint32_t)u << 5) + KYBER_Q / 2) / KYBER_Q) & 31;
#endif
}

static void poly_pack(uint8_t r[KYBER_POLYCOMPRESSEDBYTES], const poly *a) {
  unsigned int i;
  const int16_t *t = a->coeffs;

  for (i = 0; i < KYBER_N / 8; i++) {
#if (KYBER_POLYCOMPRESSEDBYTES == 128)
    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4;
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
    r[0] = (t[0] >> 0) | (t[1] << 5);
    r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[2] = (t[3] >> 1) | (t[4] << 4);
    r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[4] = (t[6] >> 2) | (t[7] << 3);
    r += 5;
#endif
    t += 8;
  }
}

static int polyvec_compress_coeff(int c) {
  int16_t u = c;
  u += (u >> 15) & KYBER_Q;
#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
  return ((((uint32_t)u << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7ff;
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
  return ((((uint32_t)u << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3ff;
#endif
}

static void polyvec_pack(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES], const polyvec *a) {
  unsigned int i, j;
  for (i = 0; i < KYBER_K; i++) {
    const int16_t *t = a->vec[i].coeffs;
#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
    for (j = 0; j < KYBER_N / 8; j++) {
      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 3);
      r[2] = (t[1] >> 5) | (t[2] << 6);
      r[3] = (t[2] >> 2);
      r[4] = (t[2] >> 10) | (t[3] << 1);
      r[5] = (t[3] >> 7) | (t[4] << 4);
      r[6] = (t[4] >> 4) | (t[5] << 7);
      r[7] = (t[5] >> 1);
      r[8] = (t[5] >> 9) | (t[6] << 2);
      r[9] = (t[6] >> 6) | (t[7] << 5);
      r[10] = (t[7] >> 3);
      r += 11;
      t += 8;
    }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
    for (j = 0; j < KYBER_N / 4; j++) {
      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 2);
      r[2] = (t[1] >> 6) | (t[2] << 4);
      r[3] = (t[2] >> 4) | (t[3] << 6);
      r[4] = (t[3] >> 2);
      r += 5;
      t += 4;
    }
#endif
  }
}

#define TIMINGS 16
#define BATCH (KYBER_N * KYBER_K * MULTIPLIERS)

long long order[BATCH];

uint8_t eve_ct[CRYPTO_CIPHERTEXTBYTES];
uint16_t eve_whichsegment[BATCH];
uint8_t eve_whichpos[BATCH];
uint8_t eve_whichm[BATCH];
long long timings[TIMINGS + 1];
long long results[BATCH];

#define SAMPLES 512
long long data[KYBER_K][KYBER_N][MULTIPLIERS][SAMPLES];

static void eve_main(void) {
  polyvec B;
  poly C;
  long long last_timestamp, this_timestamp;
  long long stats_dec = 0;

  ticks_enable();
  template();  // XXX: should run on targeted core; should precompute

  readall(pipe_bob_to_eve[0], (void *)bob_pk, sizeof bob_pk);
  eve_unpackpk();
  last_timestamp = timestamp();

  for (long long sample = 0; sample < SAMPLES;) {
    randombytes((void *)order, sizeof order);
    for (int b = 0; b < BATCH; ++b) {
      order[b] &= 0x0fffffffffffffff;
      order[b] = (order[b] / BATCH) * BATCH + b;
    }
    sort(order, BATCH);
    for (int b = 0; b < BATCH; ++b) {
      int index = order[b] % BATCH;
      eve_whichm[b] = index % MULTIPLIERS;
      index /= MULTIPLIERS;
      eve_whichpos[b] = index % KYBER_N;
      eve_whichsegment[b] = index / KYBER_N;
    }

    for (int b = 0; b < BATCH; ++b) {
      int segment = eve_whichsegment[b];
      int pos = eve_whichpos[b];
      int m = multipliers[eve_whichm[b]];
      int Cnonsel = poly_compress_coeff((5 * 3329) / 8);
      int compressm = polyvec_compress_coeff(m);
      for (int j = 0; j < KYBER_K; ++j)
        for (int i = 0; i < KYBER_N; ++i) B.vec[j].coeffs[i] = compressm * (i + pos == KYBER_N - 1) * (j == segment);
      for (int i = 0; i < KYBER_N - 1; ++i) C.coeffs[i] = Cnonsel;
      C.coeffs[KYBER_N - 1] = poly_compress_coeff(Csel[eve_whichm[b]]);
      polyvec_pack(eve_ct, &B);
      poly_pack(eve_ct + KYBER_POLYVECCOMPRESSEDBYTES, &C);
      for (int t = 0; t < TIMINGS; ++t) {
        send_ciphertext(eve_ct);
        this_timestamp = timestamp();
        timings[t] = this_timestamp - last_timestamp;
        last_timestamp = this_timestamp;
      }
      for (int t = 0; t < TIMINGS; ++t) timings[t] &= 0xffffffff;
      sort(timings, TIMINGS);
      results[b] = timings[TIMINGS / 2];
      stats_dec += TIMINGS;
    }

    for (int j = 0; j < BATCH; ++j) {
      int segment = eve_whichsegment[j];
      int pos = eve_whichpos[j];
      int whichm = eve_whichm[j];
      int insert = 0;
      while (insert < sample && data[segment][pos][whichm][insert] < results[j]) ++insert;
      for (int i = sample; i > insert; --i) data[segment][pos][whichm][i] = data[segment][pos][whichm][i - 1];
      data[segment][pos][whichm][insert] = results[j];
    }

    ++sample;

    for (int segment = 0; segment < KYBER_K; ++segment) {
      for (int pos = 0; pos < KYBER_N; ++pos) {
        long long iqm[MULTIPLIERS];
        long long score[SNUM];
        long long bestscore;
        long long nextbestscore;
        double nextrel;
        long long bestscorepos;
        long long nextbestscorepos;

        for (int whichm = 0; whichm < MULTIPLIERS; ++whichm) iqm[whichm] = scaled_iqm(data[segment][pos][whichm], sample);

        for (int spos = 0; spos < SNUM; ++spos) {
          int offset = 0;
          for (int whichm = 0; whichm < MULTIPLIERS; ++whichm) offset += iqm[whichm] - spredict[spos][whichm];
          score[spos] = 0;
          for (int whichm = 0; whichm < MULTIPLIERS; ++whichm) {
            long long delta = MULTIPLIERS * (iqm[whichm] - spredict[spos][whichm]) - offset;
            score[spos] += delta * delta;
          }
        }
        bestscore = score[0];
        bestscorepos = 0;
        for (int spos = 1; spos < SNUM; ++spos)
          if (score[spos] < bestscore) {
            bestscore = score[spos];
            bestscorepos = spos;
          }
        eve_sk.vec[segment].coeffs[pos] = slist[bestscorepos];

        nextbestscore = -1;
        nextbestscorepos = -1;
        for (int spos = 0; spos < SNUM; ++spos)
          if (spos != bestscorepos)
            if (nextbestscore == -1 || score[spos] < nextbestscore) {
              nextbestscore = score[spos];
              nextbestscorepos = spos;
            }
        eve_sk_backup.vec[segment].coeffs[pos] = slist[nextbestscorepos];

        nextrel = nextbestscore * 1.0 / bestscore;
        if (nextrel > 1024)
          confidence[segment * KYBER_N + pos] = 1073741824LL * KYBER_K * KYBER_N + segment * KYBER_N + pos;
        else
          confidence[segment * KYBER_N + pos] = ((long long)(1048576 * nextrel)) * KYBER_K * KYBER_N + segment * KYBER_N + pos;

        printf("pos %d", segment * KYBER_N + pos);
        printf(" guess %lld", slist[bestscorepos]);
        printf(" samples/m %lld", sample);
        printf(" iqms");
        for (int whichm = 0; whichm < MULTIPLIERS; ++whichm) printf(" %lld,%lld:%lld", multipliers[whichm], Csel[whichm], iqm[whichm]);
        printf(" bestscore %lld", bestscore);
        printf(" relscore");
        for (int spos = 0; spos < SNUM; ++spos) {
          printf(" %lld:%.3lf", slist[spos], score[spos] * 1.0 / bestscore);
        }
        printf(" nextrel %.3lf", nextrel);
        printf("\n");
      }
    }

    printf("totaldec %lld", stats_dec);
    printf(" samples/m/pos %lld", sample);
    printf(" limit %d", SAMPLES);
    printf("\n");
    fflush(stdout);
    if (eve_happy(sample)) {
      printf("eve declares success\n");
      fflush(stdout);
      return;
    }
  }
  printf("eve giving up ... for now\n");
}

static void eve(void) {
  eve_main();
  writeall(pipe_eve_to_judge[1], (void *)&eve_sk, sizeof eve_sk);
}

// ----- judge

static void judge(void) {
  int match = 1;
  printf("checking whether eve's secret key matches bob's secret key...\n");
  for (long long i = 0; i < KYBER_K; ++i)
    for (long long j = 0; j < KYBER_N; ++j) {
      int c = eve_sk.vec[i].coeffs[j];
      int d = bob_sk.vec[i].coeffs[j];
      printf("pos %lld eve %d bob %d matches", i * KYBER_N + j, c, d);
      if (c == d)
        printf(" True");
      else {
        printf(" False");
        match = 0;
      }
      printf("\n");
    }
  if (match)
    printf("yes, eve succeeded\n");
  else
    printf("no, eve failed\n");
  fflush(stdout);
}

int main() {
  pid_t pid_bob;
  pid_t pid_eve;
  cpu_set_t mask;

  if (pipe(pipe_eve_to_bob) == -1) {
    fprintf(stderr, "pipe failed: %s\n", strerror(errno));
    return 111;
  }
  if (pipe(pipe_bob_to_eve) == -1) {
    fprintf(stderr, "pipe failed: %s\n", strerror(errno));
    return 111;
  }
  if (pipe(pipe_bob_to_judge) == -1) {
    fprintf(stderr, "pipe failed: %s\n", strerror(errno));
    return 111;
  }
  if (pipe(pipe_eve_to_judge) == -1) {
    fprintf(stderr, "pipe failed: %s\n", strerror(errno));
    return 111;
  }

  switch (pid_bob = fork()) {
    case -1:
      fprintf(stderr, "fork failed: %s\n", strerror(errno));
      return 111;
    case 0:
      CPU_ZERO(&mask);
      CPU_SET(BOB_CPU, &mask);
      sched_setaffinity(0, sizeof mask, &mask);
      close(pipe_eve_to_bob[1]);
      close(pipe_bob_to_eve[0]);
      close(pipe_bob_to_judge[0]);
      close(pipe_eve_to_judge[0]);
      close(pipe_eve_to_judge[1]);
      bob();
      return 0;
    default:
      close(pipe_eve_to_bob[0]);
      close(pipe_bob_to_eve[1]);
      close(pipe_bob_to_judge[1]);
  }

  readall(pipe_bob_to_judge[0], (void *)&bob_sk, sizeof bob_sk);
  close(pipe_bob_to_judge[0]);

  switch (pid_eve = fork()) {
    case -1:
      fprintf(stderr, "fork failed: %s\n", strerror(errno));
      return 111;
    case 0:
      CPU_ZERO(&mask);
      CPU_SET(EVE_CPU, &mask);
      sched_setaffinity(0, sizeof mask, &mask);
      close(pipe_eve_to_judge[0]);
      eve();
      return 0;
    default:
      close(pipe_eve_to_bob[1]);
      close(pipe_bob_to_eve[0]);
      close(pipe_eve_to_judge[1]);
  }

  readall(pipe_eve_to_judge[0], (void *)&eve_sk, sizeof eve_sk);
  judge();

  waitpid(pid_bob, 0, 0);
  waitpid(pid_eve, 0, 0);
  return 0;
}
