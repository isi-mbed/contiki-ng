/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
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
 */

/**
 * \file
 *      Erbium (Er) example project configuration.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_
#define LPM_CONF_MAX_PM 1
#define IEEE802154_CONF_PANID 0x0a0b

#define EDHOC_CONF_TIMEOUT 100000

/* Mandatory EDHOC definitions on Client*/
/* Define one kind of the following kind of identifiaction for the authentication key*/
//#define AUTH_SUBJECT_NAME "Node_101"
#define AUTH_KID 0x24

/* Definde a value for the Conection Identifier*/
#define EDHOC_CID 0x16

/*Define the coap server to conect with*/
//#define EDHOC_CONF_SERVER_EP "coap://[fe80::212:4b00:615:9fec]"

//#define EDHOC_CONF_SERVER_EP "coap://[64:ff9b::c3fb:3acb]"
//#define EDHOC_CONF_SERVER_EP "coap://[64:ff9b::5c22:11f3]"
#define EDHOC_CONF_SERVER_EP "coap://[fe80::212:4b00:615:9fee]"
//#define EDHOC_CONF_SERVER_EP "coap://[fd01::202:2:2:2]" /* Server IP for Cooja simulator*/



/*Define the party rol on the EDHOC protocol as Initiator and the correlation method*/
#define EDHOC_CONF_PART PART_I
#define EDHOC_CONF_CORR EXTERNAL_CORR_U 

/*To run with the test vector DH ephimeral keys used on the edhoc-v02 interoperability sesion*/
//#define EDHOC_TEST TEST_VECTOR
#define EDHOC_CONF_VERSION EDHOC_04

/*Define the authentication method*/
//#define EDHOC_CONF_AUTHENT_TYPE PRK_ID
#define EDHOC_CONF_AUTHENT_TYPE X5CHAIN
#define EDHOC_CONF_SH256 CC2538_SH2


/*Define the libray for ECDH operations*/
#define EDHOC_CONF_ECC CC2538_ECC
#define LOG_LEVEL_APP LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_COAP LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */

