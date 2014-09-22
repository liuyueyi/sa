/*
 * aes.h
 *
 *  Created on: 2014-8-21
 *      Author: wzb
 */

#ifndef RSA_H_
#define RSA_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

char *base64(const char *a, size_t length, char *result, size_t size);

char *debase64(char *a, size_t length, char *result, size_t size);

char *rsa_sha1(const char *filename, char *result, size_t len, const char *ptr);

char *rsa_encrypt(const char *plain_text, char *result, size_t size,
		const char *pk_filename);

char *rsa_decrypt(const char *cipher, char *result, size_t size,
		const char *sk_filename);

char *rsa_sign(const char *text, char *signature, size_t size,
		const char *sk_filename);

int rsa_verify(const char *text, const char *signature, const char *pk_filename);

#endif
