#include <stdlib.h>
#include <stdio.h>
#include "hal.h"

extern int usartIsDone;
extern size_t usartIdx;
extern uint32_t times[20000];

#define CRYPTO_SECRETKEYBYTES 2400
#define CRYPTO_CIPHERTEXTBYTES 1088

static void receive_ciphertext(unsigned char ct[CRYPTO_CIPHERTEXTBYTES])
{
  hal_send_str_host("#");
  hal_recv_bytes_host(ct, CRYPTO_CIPHERTEXTBYTES);
}

static void receive_sk(unsigned char sk[CRYPTO_SECRETKEYBYTES])
{
  hal_send_str_host("#");
  hal_recv_bytes_host(sk, CRYPTO_SECRETKEYBYTES);
}

static void wait_for_victim(void)
{
  while (!usartIsDone)
  {
    asm("nop");
  }
}

static void wait_for_start(void)
{
  unsigned char t;
  do
  {
    hal_recv_bytes_host(&t, 1);
  } while (t != '#');
}

int main(void)
{
  hal_setup(CLOCK_FAST);
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  char str[100];

  wait_for_start();

  usartIsDone = 0;
  hal_send_char_victim('#');
  hal_send_str_host("waiting for victim #");
  wait_for_victim();
  hal_send_str_host("victim online #");

  receive_sk(sk);

  usartIsDone = 0;
  hal_send_bytes_victim(sk, CRYPTO_SECRETKEYBYTES);
  wait_for_victim();

  while (1)
  {

    receive_ciphertext(ct);

    usartIsDone = 0;
    hal_send_bytes_victim(ct, CRYPTO_CIPHERTEXTBYTES);
    wait_for_victim();

    usartIdx = 0;
    usartIsDone = 0;
    hal_send_char_victim('#');
    wait_for_victim();
    for (size_t i = 0; i < usartIdx - 1; i++)
    {
      sprintf(str, "%lu", times[i + 1] - times[i]);
      hal_send_str_host(str);
    }

    hal_send_str_host("#");
  }

  return 0;
}
