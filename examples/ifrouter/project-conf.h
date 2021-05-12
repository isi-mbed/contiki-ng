/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
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
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#ifndef WEBSERVER_CONF_CFS_CONNS
#define WEBSERVER_CONF_CFS_CONNS 2
#endif

#ifndef BORDER_ROUTER_CONF_WEBSERVER
#define BORDER_ROUTER_CONF_WEBSERVER 1
#endif

#if BORDER_ROUTER_CONF_WEBSERVER
#define UIP_CONF_TCP 1
#endif

//#define NETSTACK_CONF_WITH_IPV6	1
#define UIP_CONF_ND6_SEND_RA 0
#define UIP_CONF_ND6_SEND_NS 0
#define UIP_CONF_ND6_SEND_NA 0
#define UIP_CONF_ROUTER	1
#define UIP_CONF_ND6_AUTOFILL_NBR_CACHE 0

#define BUILD_WITH_RPL_BORDER_ROUTER               1
#define UIP_FALLBACK_INTERFACE         rpl_interface

#define LPM_CONF_MAX_PM       1

#define UIP_CONF_BUFFER_SIZE           	1280

#define QUEUEBUF_CONF_NUM					16

//#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS	16
//#define SICSLOWPAN_CONF_REASS_CONTEXTS	 	4

//#define ZOUL_CONF_USE_CC1200_RADIO	1

#define LOG_CONF_LEVEL_IPV6 			LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_6LOWPAN          LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_MAC              LOG_LEVEL_DBG
//#define LOG_CONF_LEVEL_FRAMER           LOG_LEVEL_DBG

//#define UART0_CONF_BAUD_RATE			57600

#endif /* PROJECT_CONF_H_ */
