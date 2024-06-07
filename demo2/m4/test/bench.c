#include "api.h"
#include "hal.h"
#include "sendfn.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define printcycles(S, U) send_unsignedll((S), (U))
#ifndef NUMREPS
#define NUMREPS 3
#endif

static void receive_ciphertext(unsigned char ct[CRYPTO_CIPHERTEXTBYTES])
{
  hal_send_str("#");
  hal_recv_bytes(ct, CRYPTO_CIPHERTEXTBYTES);
}

static void receive_sk(unsigned char sk[CRYPTO_SECRETKEYBYTES])
{
  hal_send_str("#");
  hal_recv_bytes(sk, CRYPTO_SECRETKEYBYTES);
}

static void waitForStart(void)
{

  unsigned char t[2];
  hal_send_str("waiting for start");
  do
  {
    hal_recv_bytes(t, 1);
  } while (t[0] != '#');
}

int main(void)
{
  unsigned char key_b[CRYPTO_BYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  unsigned long long t0, t1;

  hal_setup(CLOCK_FAST);

  waitForStart();

  receive_sk(sk);

  while (1)
  {

    receive_ciphertext(ct);

    for (int j = 0; j < NUMREPS; j++)
    {
      hal_send_str("#");
      hal_reset_time();
      t0 = hal_get_time();
      crypto_kem_dec(key_b, ct, sk);
      t1 = hal_get_time();
      printcycles("decaps_cycles", t1 - t0);
      hal_send_str("=");
    }
  }

  return 0;
}
