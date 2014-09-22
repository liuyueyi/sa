/*
 * sm2.h
 *
 *  Created on: 2014-9-22
 *      Author: pc
 */

#ifndef SM2_H_
#define SM2_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include "eccapi.h"

int sm2_encrypt(char *plain_text, char *cipher, size_t len,
		const char *sk_pathname);

int sm2_decrypt(char *cipher, char *recover, size_t len,
		const char *pk_pathname);

int sm2_sha1(const char *pathname, char *result, size_t len,
		const char *pk_pathname);
#endif /* SM2_H_ */
