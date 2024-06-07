#include <stdlib.h>
#include "hal.h"
#include "api.h"

#ifndef NUMREPS
#define NUMREPS 3
#endif

static void receive_ciphertext(unsigned char ct[CRYPTO_CIPHERTEXTBYTES])
{
  hal_send_char('=');
  hal_recv_bytes(ct, CRYPTO_CIPHERTEXTBYTES);
}

static void receive_sk(unsigned char sk[CRYPTO_SECRETKEYBYTES])
{
  hal_send_char('=');
  hal_recv_bytes(sk, CRYPTO_SECRETKEYBYTES);
}

static void wait_for_start(void)
{
  char t;
  do
  {
    t = hal_recv_char();
  } while (t != '#');
}

int main(void)
{
  hal_setup(CLOCK_BENCHMARK);
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  unsigned char key_b[CRYPTO_BYTES];
  wait_for_start();

  receive_sk(sk);
  while (1)
  {

    receive_ciphertext(ct);
    hal_send_char('=');

    wait_for_start();
    for (int i = 0; i < NUMREPS + 1; i++)
    {
      crypto_kem_dec(key_b, ct, sk);
      hal_send_char('$');
    }

    hal_send_char('=');
  }

  return 0;
}
