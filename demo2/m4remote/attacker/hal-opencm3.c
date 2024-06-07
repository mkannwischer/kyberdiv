#include "hal.h"
#include <sys/cdefs.h>

#define SERIAL_BAUD_HOST 7*115200
#define SERIAL_BAUD_VICTIM 6*128000

#include <libopencm3/cm3/dwt.h>
#include <libopencm3/cm3/nvic.h>
#include <libopencm3/cm3/systick.h>


#include <libopencm3/cm3/scs.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/rng.h>
#define SERIAL_GPIO_VICTIM GPIOC
#define SERIAL_USART_VICTIM USART3
#define SERIAL_PINS_VICTIM (GPIO10 | GPIO11)

#define SERIAL_GPIO_HOST GPIOA
#define SERIAL_USART_HOST USART2
#define SERIAL_PINS_HOST (GPIO2 | GPIO3)

#define STM32
#define DISCOVERY_BOARD

/* 24 MHz */
const struct rcc_clock_scale benchmarkclock = {
  .pllm = 8, //VCOin = HSE / PLLM = 1 MHz
  .plln = 192, //VCOout = VCOin * PLLN = 192 MHz
  .pllp = 8, //PLLCLK = VCOout / PLLP = 24 MHz (low to have 0WS)
  .pllq = 4, //PLL48CLK = VCOout / PLLQ = 48 MHz (required for USB, RNG)
  .pllr = 0,
  .hpre = RCC_CFGR_HPRE_DIV_NONE,
  .ppre1 = RCC_CFGR_PPRE_DIV_2,
  .ppre2 = RCC_CFGR_PPRE_DIV_NONE,
  .pll_source = RCC_CFGR_PLLSRC_HSE_CLK,
  .voltage_scale = PWR_SCALE1,
  .flash_config = FLASH_ACR_DCEN | FLASH_ACR_ICEN | FLASH_ACR_LATENCY_0WS,
  .ahb_frequency = 24000000,
  .apb1_frequency = 12000000,
  .apb2_frequency = 24000000,
};



#define _RCC_CAT(A, B) A ## _ ## B
#define RCC_ID(NAME) _RCC_CAT(RCC, NAME)

__attribute__((unused))
static uint32_t _clock_freq;

#ifdef STM32F2
extern uint32_t rcc_apb1_frequency;
extern uint32_t rcc_apb2_frequency;
#endif

static void clock_setup(enum clock_mode clock)
{
  switch(clock) {
  case CLOCK_BENCHMARK:
    rcc_clock_setup_pll(&benchmarkclock);
    break;
  case CLOCK_FAST:
  default:
    rcc_clock_setup_pll(&rcc_hse_8mhz_3v3[RCC_CLOCK_3V3_168MHZ]);
    break;
  }

  rcc_periph_clock_enable(RCC_RNG);
  rng_enable();

  flash_prefetch_enable();
}

static void usart_setup(void)
{
  rcc_periph_clock_enable(RCC_GPIOC);
  rcc_periph_clock_enable(RCC_USART3);

  rcc_periph_clock_enable(RCC_GPIOA);
  rcc_periph_clock_enable(RCC_USART2);


  gpio_set_output_options(SERIAL_GPIO_HOST, GPIO_OTYPE_OD, GPIO_OSPEED_100MHZ, SERIAL_PINS_HOST);
  gpio_set_af(SERIAL_GPIO_HOST, GPIO_AF7, SERIAL_PINS_HOST);
  gpio_mode_setup(SERIAL_GPIO_HOST, GPIO_MODE_AF, GPIO_PUPD_PULLUP, SERIAL_PINS_HOST);
  usart_set_baudrate(SERIAL_USART_HOST, SERIAL_BAUD_HOST);
  usart_set_databits(SERIAL_USART_HOST, 8);
  usart_set_stopbits(SERIAL_USART_HOST, USART_STOPBITS_1);
  usart_set_mode(SERIAL_USART_HOST, USART_MODE_TX_RX);
  usart_set_parity(SERIAL_USART_HOST, USART_PARITY_NONE);
  usart_set_flow_control(SERIAL_USART_HOST, USART_FLOWCONTROL_NONE);
  usart_disable_rx_interrupt(SERIAL_USART_HOST);
  usart_disable_tx_interrupt(SERIAL_USART_HOST);
  usart_enable(SERIAL_USART_HOST);


  gpio_set_output_options(SERIAL_GPIO_VICTIM, GPIO_OTYPE_OD, GPIO_OSPEED_100MHZ, SERIAL_PINS_VICTIM);
  gpio_set_af(SERIAL_GPIO_VICTIM, GPIO_AF7, SERIAL_PINS_VICTIM);
  gpio_mode_setup(SERIAL_GPIO_VICTIM, GPIO_MODE_AF, GPIO_PUPD_PULLUP, SERIAL_PINS_VICTIM);
  usart_set_baudrate(SERIAL_USART_VICTIM, SERIAL_BAUD_VICTIM);
  usart_set_databits(SERIAL_USART_VICTIM, 8);
  usart_set_stopbits(SERIAL_USART_VICTIM, USART_STOPBITS_1);
  usart_set_mode(SERIAL_USART_VICTIM, USART_MODE_TX_RX);
  usart_set_parity(SERIAL_USART_VICTIM, USART_PARITY_NONE);
  usart_set_flow_control(SERIAL_USART_VICTIM, USART_FLOWCONTROL_NONE);
  
  nvic_enable_irq(NVIC_USART3_IRQ);
  usart_enable_rx_interrupt(SERIAL_USART_VICTIM);

  usart_disable_tx_interrupt(SERIAL_USART_VICTIM);
  usart_enable(SERIAL_USART_VICTIM);
}

int usartIsDone = 0;
size_t usartIdx = 0;
uint32_t times[1000];

void usart3_isr(void)
{
  	if (((USART_CR1(USART3) & USART_CR1_RXNEIE) != 0) &&
	    ((USART_SR(USART3) & USART_SR_RXNE) != 0)) {
        
        times[usartIdx++] = DWT_CYCCNT;
	      char data = usart_recv(USART3);


        if(data == '=') {
          usartIsDone = 1;
          usartIdx--;
          DWT_CYCCNT = 0; 
        }

      }
}


static volatile unsigned long long overflowcnt = 0;
void hal_setup(const enum clock_mode clock)
{
  clock_setup(clock);
  usart_setup();


  SCS_DEMCR |= SCS_DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;
}


void hal_send_str_host(const char* in)
{
  const char* cur = in;
  while (*cur) {
    usart_send_blocking(SERIAL_USART_HOST, *cur);
    cur += 1;
  }
  usart_send_blocking(SERIAL_USART_HOST, '\n');
}

void hal_send_str_victim(const char* in)
{
  const char* cur = in;
  while (*cur) {
    usart_send_blocking(SERIAL_USART_VICTIM, *cur);
    cur += 1;
  }
  usart_send_blocking(SERIAL_USART_VICTIM, '\n');
}

void hal_send_char_victim(char in) {
  usart_send_blocking(SERIAL_USART_VICTIM, in);
}

void hal_send_bytes_victim(const unsigned char *in, unsigned int n){
  for(unsigned int i=0;i<n;i++){
    usart_send_blocking(SERIAL_USART_VICTIM, *in);
    in += 1;
  }
}

void hal_recv_bytes_host(unsigned char *out, unsigned int n){
    unsigned int i;
    for(i = 0; i < n; i++) {
        out[i] = usart_recv_blocking(SERIAL_USART_HOST);
    }
}

void hal_recv_str_victim(char *out, unsigned int n){
    unsigned int i;
    for(i = 0; i < n; i++) {
        out[i] = usart_recv_blocking(SERIAL_USART_VICTIM);
    }
}


/* End of BSS is where the heap starts (defined in the linker script) */
extern char end;
static char* heap_end = &end;
void* __wrap__sbrk (int incr);
void* __wrap__sbrk (int incr)
{
  char* prev_heap_end;

  prev_heap_end = heap_end;
  heap_end += incr;

  return (void *) prev_heap_end;
}

size_t hal_get_stack_size(void)
{
  register char* cur_stack;
	__asm__ volatile ("mov %0, sp" : "=r" (cur_stack));
  return cur_stack - heap_end;
}
