/*
 * encrypt.h
 *
 *  Created on: 2014-8-21
 *      Author: pc
 */

#ifndef ENCRYPT_H_
#define ENCRYPT_H_

#include <limits.h>
#include "rsa.h"
// #include "sm2.h"

struct encrypt_operations
{
	char *(*encrypt)(const char *plain_text, char *result, size_t size,
			const char *pk_filename);
	char *(*decrypt)(const char *cipher, char *result, size_t size,
			const char *sk_filename);
	char *(*sign)(const char *text, char *signature, size_t size,
			const char *sk_filename);
	int (*verify)(const char *text, const char *signature,
			const char *pk_filename);

	char *(*sha1)(const char *filename, char *result, size_t len,
			const char *ptr);

	char sk_filename[PATH_MAX];
	char pk_filename[PATH_MAX];
};

struct encrypt_operations *set_encryption_method(const char *method,
		char *sk_filename, char *pk_filename);

#endif /* ENCRYPT_H_ */
