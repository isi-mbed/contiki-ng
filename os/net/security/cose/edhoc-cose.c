/*
 * Copyright (c) 2020, Industrial Systems Institute (ISI), Patras, Greece
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

/**
 * \file
 *         COSE, an implementation of COSE_Encrypt0 structure from: CBOR Object Signing and Encryption (COSE)(IETF RFC 8152)
 * \author
 *         Lidia Pocero <pocero@isi.gr>
 */

#include "edhoc-cose.h"
#include "contiki-lib.h"
#include <os/lib/ccm-star.h>
#include <string.h>
#include "cose-log.h"
uint8_t str_encode[2 * COSE_MAX_BUFFER];
uint8_t tag[TAG_LEN];

MEMB(encrypt0_storage, cose_encrypt0, 1);

static inline cose_encrypt0 *
encrypt0_storage_new()
{
  return (cose_encrypt0 *)memb_alloc(&encrypt0_storage);
}
static inline void
encrypt0_free(cose_encrypt0 *enc)
{
  memb_free(&encrypt0_storage, enc);
}
static void
encrypt0_storage_init(void)
{
  memb_init(&encrypt0_storage);
}
cose_encrypt0 *
cose_encrypt0_new()
{
  encrypt0_storage_init();
  cose_encrypt0 *enc;
  enc = encrypt0_storage_new();
  return enc;
}
void
cose_encrypt0_finalize(cose_encrypt0 *enc)
{
  encrypt0_free(enc);
}
static char enc_rec[] = RECIPIENT;

void
cose_print_key(cose_key *cose)
{
  LOG_DBG("kid:");
  cose_print_buff_8_dbg(cose->kid.buf, cose->kid.len);
  LOG_DBG("identity:");
  cose_print_char_8_dbg((uint8_t *)cose->identity.buf, cose->identity.len);
  LOG_DBG("kty: %d\n", cose->kty);
  LOG_DBG("crv: %d\n", cose->crv);
  LOG_DBG("x:");
  cose_print_buff_8_dbg(cose->x.buf, cose->x.len);
  LOG_DBG("y:");
  cose_print_buff_8_dbg(cose->y.buf, cose->y.len);
  LOG_DBG("CERT_HASH (%d):",cose->header);
  cose_print_buff_8_dbg(cose->cert_hash.buf, cose->cert_hash.len);
}
uint8_t
cose_encrypt0_set_keys(cose_encrypt0 *enc, uint8_t alg, uint8_t *key, uint8_t key_sz, uint8_t *nonce, uint16_t nonce_sz)
{
  if(key_sz != KEY_LEN) {
    return 0;
  }
  if(nonce_sz != IV_LEN) {
    return 0;
  }
  enc->key_sz = key_sz;
  enc->nonce_sz = nonce_sz;
  memcpy(enc->key, key, key_sz);
  memcpy(enc->nonce, nonce, nonce_sz);
  return 1;
}
uint8_t
cose_encrypt0_set_contents(cose_encrypt0 *enc, uint8_t *plain, size_t plain_sz, uint8_t *add, size_t add_sz)
{
  if(plain_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(enc->plaintext, plain, plain_sz);
  //memcpy(enc->external_aad, add, add_sz);
  enc->plaintext_sz = plain_sz;
  enc->external_aad.buf = add;
  enc->external_aad.len = add_sz;
  //enc->external_aad_sz = add_sz;
  return 1;
}
/*uint8_t
cose_encrypt0_set_content(cose_encrypt0 *enc, uint8_t *plain, size_t plain_sz, uint8_t *add, size_t add_sz)
{
  if(plain_sz > COSE_MAX_BUFFER) {
    return 0;
  }
  memcpy(enc->plaintext, plain, plain_sz);
  memcpy(enc->external_aad, add, add_sz);
  enc->plaintext_sz = plain_sz;
  enc->external_aad_sz = add_sz;
  return 1;
}*/
uint8_t
cose_encrypt0_set_ciphertext(cose_encrypt0 *enc, uint8_t *ciphertext, size_t ciphertext_sz)
{
  if(ciphertext_sz > MAX_CIPHER) {
    return 0;
  }
  memcpy(enc->plaintext, ciphertext, ciphertext_sz);
  enc->plaintext_sz = ciphertext_sz;
  //memcpy(enc->ciphertext, ciphertext, ciphertext_sz);
  //enc->ciphertext_sz = ciphertext_sz;
  return 1;
}
/*void
cose_encrypt0_set_header(cose_encrypt0 *enc, uint8_t *prot, size_t prot_sz, uint8_t *unp, size_t unp_sz)
{
  memcpy(enc->protected_header, prot, prot_sz);
  memcpy(enc->unprotected_header, unp, unp_sz);
  enc->protected_header_sz = prot_sz;
  enc->unprotected_header_sz = unp_sz;
}*/
void
cose_encrypt0_set_header(cose_encrypt0 *enc, uint8_t *prot, size_t prot_sz, uint8_t *unp, size_t unp_sz)
{
  //memcpy(enc->protected_header, prot, prot_sz);
  //memcpy(enc->unprotected_header, unp, unp_sz);
  enc->protected_header.buf = prot;
  enc->protected_header.len = prot_sz;
  enc->unprotected_header.buf = unp;
  enc->unprotected_header.len = unp_sz;
}
static size_t
encode_enc_structure(enc_structure str, uint8_t *cbor)
{
  size_t size = cbor_put_array(&cbor, 3);
  size += cbor_put_text(&cbor, str.str_id.buf, strlen(str.str_id.buf));
  size += cbor_put_bytes(&cbor, str.protected.buf, str.protected.len);
  size += cbor_put_bytes(&cbor, str.external_aad.buf, str.external_aad.len);
  return size;
}
uint8_t
cose_decrypt(cose_encrypt0 *enc)
{
  
  /*enc_structure str = {
    .str_id = (sstr_cose){ enc_rec, sizeof(enc_rec) },
    .protected = (bstr_cose){ enc->protected_header, enc->protected_header_sz }, 
    .external_aad = (bstr_cose){ enc->external_aad, enc->external_aad_sz },
  };*/ /* the enc estructure have tha autetification data */
  enc_structure str = {
    .str_id = (sstr_cose){ enc_rec, sizeof(enc_rec) },
    .protected = (bstr_cose){ enc->protected_header.buf, enc->protected_header.len }, 
    .external_aad = (bstr_cose){ enc->external_aad.buf, enc->external_aad.len },
  };
  
  size_t str_sz = encode_enc_structure(str, str_encode);
  LOG_INFO("encript in decript(%d)\n",enc->plaintext_sz );
  //cose_print_buff_8_info(enc->plaintext,enc->plaintext_sz);
  LOG_INFO("external aad (%d bytes)\n", enc->external_aad.len);
  LOG_INFO("protected header (%d bytes)\n", enc->protected_header.len);
 
  LOG_INFO("(CBOR-encoded AAD) (%d bytes)\n", str_sz);
  cose_print_buff_8_dbg(str_encode, str_sz);
  CCM_STAR.set_key(enc->key);
  //enc->plaintext_sz = enc->ciphertext_sz - (size_t)TAG_LEN;
  //cose_print_buff_8_info(enc->ciphertext, enc->ciphertext_sz);
  CCM_STAR.aead(enc->nonce, enc->plaintext, enc->plaintext_sz - (size_t)TAG_LEN, str_encode, str_sz, tag, TAG_LEN, 0);
  //CCM_STAR.aead(enc->nonce, enc->ciphertext, enc->plaintext_sz, str_encode, str_sz, tag, TAG_LEN, 0);
 // LOG_INFO("enc plaintext size (%u)\n", enc->plaintext_sz);
  //memcpy(enc->plaintext, enc->ciphertext, enc->plaintext_sz);
 // LOG_INFO("plaintext sz: (%u)\n", enc->plaintext_sz);
  //cose_print_buff_8_info(enc->plaintext, enc->plaintext_sz);
 //LOG_INFO("TAG:");
 // cose_print_buff_8_info(tag, TAG_LEN);
 // LOG_INFO("TAG 2:");
 // cose_print_buff_8_info(&(enc->ciphertext[enc->plaintext_sz]), TAG_LEN);
  LOG_INFO("plaintext(%d)\n",enc->plaintext_sz );
  cose_print_buff_8_info(enc->plaintext,enc->plaintext_sz);
  if(memcmp(tag, &(enc->plaintext[enc->plaintext_sz - (size_t)TAG_LEN]), TAG_LEN) != 0) {
  //if(memcmp(tag, &(enc->ciphertext[enc->plaintext_sz]), TAG_LEN) != 0) {
    LOG_ERR("Decrypt msg error\n");
    return 0;     /* Decryption failure */
  }
  return 1;
}
size_t
cose_encrypt(cose_encrypt0 *enc)
{

  enc_structure str = {
    .str_id = (sstr_cose){ enc_rec, sizeof(enc_rec) }, /*Encrypt0 */
    .protected = (bstr_cose){ enc->protected_header.buf, enc->protected_header.len }, /*empty */
    .external_aad = (bstr_cose){ enc->external_aad.buf, enc->external_aad.len }, /* OLD REF TH@ */
  }; /* the enc estructure have tha autetification data */

  //uint8_t str_encode[2 * COSE_MAX_BUFFER];
  size_t str_sz = encode_enc_structure(str, str_encode);
 // LOG_INFO("plaintext(%d)\n",enc->plaintext_sz );
   // LOG_INFO("external aad (%d bytes)\n", enc->external_aad.len);
  //  LOG_INFO("protected header (%d bytes)\n", enc->protected_header.len);
  //cose_print_buff_8_info(enc->plaintext,enc->plaintext_sz); 
  //LOG_INFO("(CBOR-encoded AAD) (%d bytes)\n", str_sz);
  //cose_print_buff_8_info(str_encode, str_sz);

  /*TO DO: check the algorithm selected in enc */
  if(enc->key_sz != KEY_LEN || enc->nonce_sz != IV_LEN || enc->plaintext_sz > COSE_MAX_BUFFER || str_sz > (2 * COSE_MAX_BUFFER)) {
    LOG_ERR("The cose parameter are not corresponing with the selected algorithm or buffer sizes\n");
    return 0;
  }
  CCM_STAR.set_key(enc->key);
  //memcpy(enc->ciphertext, enc->plaintext, enc->plaintext_sz);
  //CCM_STAR.aead(enc->nonce, enc->ciphertext, enc->plaintext_sz, str_encode, str_sz, &enc->ciphertext[enc->plaintext_sz], TAG_LEN, 1);
  CCM_STAR.aead(enc->nonce, enc->plaintext, enc->plaintext_sz, str_encode, str_sz, &enc->plaintext[enc->plaintext_sz], TAG_LEN, 1);
  enc->plaintext_sz = enc->plaintext_sz + TAG_LEN;
 // LOG_INFO("encript in encrypt(%d)\n",enc->plaintext_sz );
 // cose_print_buff_8_info(enc->plaintext,enc->plaintext_sz);
  //LOG_INFO("TAG (%d):",TAG_LEN);
  

  //enc->ciphertext_sz = enc->plaintext_sz + TAG_LEN;
  return enc->plaintext_sz;
  //return enc->ciphertext_sz;
}