/*
 * Copyright (c) 2011, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */
/**
 * \file
 *         border-router
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 *         Nicolas Tsiftes <nvt@sics.se>
 */

#include "contiki.h"
#include "contiki-net.h"

#include "net/routing/routing.h"
#include "if-router.h"
#include "cmd.h"
#include "border-router.h"
#include "border-router-cmds.h"


#include "net/ipv6/uip-ds6-route.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"


/*---------------------------------------------------------------------------*/
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "BR"
#define LOG_LEVEL LOG_LEVEL_INFO

#include <stdlib.h>

extern long slip_sent;
extern long slip_received;

static uint8_t mac_set;

extern int contiki_argc;
extern char **contiki_argv;
extern const char *slip_config_ipaddr;

CMD_HANDLERS(border_router_cmd_handler);

static void addRoutes1()
{
	  uip_ipaddr_t ipaddr = {.u16 = {0x80fe, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0xe7a0}};
	  uip_ipaddr_t ipaddrG = {.u16 = {0x00fd, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0xe7a0}};
	  uip_ipaddr_t ipaddrG2 = {.u16 = {0x00fd, 0, 0, 0, 0x0, 0x0, 0x0, 0x0200}};
	  uip_lladdr_t lladdr = {{0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0xa0, 0xe7}};

	  uip_ds6_nbr_add(&ipaddr, &lladdr, 1, NBR_REACHABLE, NBR_TABLE_REASON_ROUTE, NULL);

	  uip_ds6_route_add(&ipaddrG, 128, &ipaddr);
	  uip_ds6_route_add(&ipaddrG2, 128, &ipaddr);
}

static void addRoutes2()
{
	  uip_ipaddr_t ipaddr = {.u16 = {0x80fe, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0x8aaa}};
	  uip_ipaddr_t ipaddrG = {.u16 = {0x00fd, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0x8aaa}};
	  uip_ipaddr_t ipaddrG2 = {.u16 = {0x00fd, 0, 0, 0, 0x0, 0x0, 0x0, 0x0100}};
	  uip_lladdr_t lladdr = {{0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0xaa, 0x8a}};

	  uip_ds6_nbr_add(&ipaddr, &lladdr, 1, NBR_REACHABLE, NBR_TABLE_REASON_ROUTE, NULL);

	  uip_ds6_route_add(&ipaddrG, 128, &ipaddr);
	  uip_ds6_route_add(&ipaddrG2, 128, &ipaddr);
}
/*
static void addRoutes3()
{
	  uip_ipaddr_t ipaddr = {.u16 = {0x80fe, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0x7daa}};
	  uip_ipaddr_t ipaddrG = {.u16 = {0x00fd, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0x7daa}};
	  uip_ipaddr_t ipaddrG2 = {.u16 = {0x00fd, 0, 0, 0, 0x0, 0x0, 0x0, 0x0200}};
	  uip_lladdr_t lladdr = {{0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0xaa, 0x7d}};

	  uip_ds6_nbr_add(&ipaddr, &lladdr, 1, NBR_REACHABLE, NBR_TABLE_REASON_ROUTE, NULL);

	  uip_ds6_route_add(&ipaddrG, 128, &ipaddr);
	  uip_ds6_route_add(&ipaddrG2, 128, &ipaddr);
}*/

void addRoutes(void)
{
  int i;
  uint8_t state;

  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
    	if (uip_ds6_if.addr_list[i].ipaddr.u16[7] == 0x8aaa) {
    		addRoutes1();
    	    break;
    	}
    	if (uip_ds6_if.addr_list[i].ipaddr.u16[7] == 0xe7a0) {
    		addRoutes2();
    	    break;
    	}
    }
  }
}

PROCESS(border_router_process, "Border router process");

/*---------------------------------------------------------------------------*/
static void
request_mac(void)
{
  write_to_slip((uint8_t *)"?M", 2);
}
/*---------------------------------------------------------------------------*/
void
border_router_set_mac(const uint8_t *data)
{
  memcpy(uip_lladdr.addr, data, sizeof(uip_lladdr.addr));
  linkaddr_set_node_addr((linkaddr_t *)uip_lladdr.addr);

  /* is this ok - should instead remove all addresses and
     add them back again - a bit messy... ?*/
  PROCESS_CONTEXT_BEGIN(&tcpip_process);
  uip_ds6_init();
  NETSTACK_ROUTING.init();
  PROCESS_CONTEXT_END(&tcpip_process);

  mac_set = 1;
}
/*---------------------------------------------------------------------------*/
void
border_router_print_stat()
{
  printf("bytes received over SLIP: %ld\n", slip_received);
  printf("bytes sent over SLIP: %ld\n", slip_sent);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(border_router_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();
  prefix_set = 0;

  PROCESS_PAUSE();

  process_start(&border_router_cmd_process, NULL);

  LOG_INFO("RPL-Border router started\n");

  slip_config_handle_arguments(contiki_argc, contiki_argv);

  /* tun init is also responsible for setting up the SLIP connection */
  tun_init();

  while(!mac_set) {
    etimer_set(&et, CLOCK_SECOND);
    request_mac();
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  }

  if(slip_config_ipaddr != NULL) {
    uip_ipaddr_t prefix;

    if(uiplib_ipaddrconv((const char *)slip_config_ipaddr, &prefix)) {
      LOG_INFO("Setting prefix ");
      LOG_INFO_6ADDR(&prefix);
      LOG_INFO_("\n");
      set_prefix_64(&prefix);
    } else {
      LOG_ERR("Parse error: %s\n", slip_config_ipaddr);
      exit(0);
    }
  }

  addRoutes();

  print_local_addresses();

  while(1) {
    etimer_set(&et, CLOCK_SECOND * 2);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    /* do anything here??? */
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
