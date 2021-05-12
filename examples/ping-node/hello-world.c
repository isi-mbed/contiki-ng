/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
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
 *         A very simple Contiki application showing how Contiki programs look
 * \author
 *         Adam Dunkels <adam@sics.se>
 */



#include "contiki.h"

#include <stdio.h> /* For printf() */
#include "net/ipv6/uip-ds6-route.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/routing/routing.h"
/*---------------------------------------------------------------------------*/
PROCESS(hello_world_process, "Hello world process");
AUTOSTART_PROCESSES(&hello_world_process);


/*static void
set_global_address(void)
{
	uip_ipaddr_t ipaddr;

	const uip_ipaddr_t *default_prefix = uip_ds6_default_prefix();

	uip_ip6addr_copy(&ipaddr, default_prefix);
	uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
	uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
}
static void addRoutes0()
{
	printf("Setting prefix ");
	set_global_address();
    uip_ipaddr_t ipaddr = {.u16 = {0x80fe, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0x09ab}};
   	uip_ipaddr_t ipaddrG = {.u16 = {0x00fd, 0, 0, 0, 0x1202, 0x004b, 0x1506, 0x09ab}};
    uip_ipaddr_t ipaddrG2 = {.u16 = {0x00fd, 0, 0, 0, 0x0, 0x0, 0x0, 0x0100}};
	
    uip_ipaddr_t ipaddrremote = {.u16 = {0x052a, 0x14d0, 0x5a04, 0x016f, 0x3097, 0xb1e8, 0x198a, 0xa1de}}; 
	uip_ipaddr_t ipaddrG3 = {.u16 = {0x0120, 0x4806, 0xb023, 0, 0, 0, 0, 0x0100}}; 
   	uip_ipaddr_t ipaddrhost = {.u16 = {0x0120, 0x4806, 0xb023, 0, 0, 0, 0x0200, 0x0100}}; 
     uip_ipaddr_t ipaddrhost2 = {.u16 = {0x0120, 0x4806, 0xb023, 0, 0, 0, 0x0200, 0x0200}};
     uip_ipaddr_t ipaddrhost3 = {.u16 = {0x0120, 0x4806, 0xb023, 0, 0, 0, 0x0200, 0x0300}};  
    uip_lladdr_t lladdr = {{0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0xab, 0x09}};
    uip_ds6_nbr_add(&ipaddr, &lladdr, 1, NBR_REACHABLE, NBR_TABLE_REASON_ROUTE, NULL);

	uip_ds6_route_add(&ipaddrG, 128, &ipaddr);
	uip_ds6_route_add(&ipaddrG2, 128, &ipaddr);
	uip_ds6_route_add(&ipaddrremote, 128, &ipaddr);
	uip_ds6_route_add(&ipaddrG3, 128, &ipaddr);
  	uip_ds6_route_add(&ipaddrhost, 128, &ipaddr);
    	uip_ds6_route_add(&ipaddrhost2, 128, &ipaddr);
      	uip_ds6_route_add(&ipaddrhost3, 128, &ipaddr);
   	
}*/
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hello_world_process, ev, data)
{
  static struct etimer timer;

  PROCESS_BEGIN();
  //addRoutes0(); 
  /* Setup a periodic timer that expires after 10 seconds. */
  etimer_set(&timer, CLOCK_SECOND * 10);

  while(1) {
    printf("Hello, world\n");

    /* Wait for the periodic timer to expire and then restart the timer. */
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
