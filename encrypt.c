/*
 * encrypt.c
 *
 *  Created on: 2014-8-25
 *      Author: pc
 */

#include "encrypt.h"

struct encrypt_operations * set_encryption_method(const char *method,
		const char *sk_filename, const char *pk_filename)
{
	struct encrypt_operations *e = (struct encrypt_operations *) malloc(
			sizeof(struct encrypt_operations));
	if (NULL == e)
		return NULL ;

	if (strcmp(method, "rsa") == 0 || strcmp(method, "RSA") == 0)
	{
		e->encrypt = rsa_encrypt;
		e->decrypt = rsa_decrypt;
		e->sign = rsa_sign;
		e->verify = rsa_verify;
		e->sha1 = rsa_sha1;
	}
	/*
	else if (strcmp(method, "sm") == 0 || strcmp(method, "SM") == 0)
	{
		e->encrypt = sm2_encrypt;
		e->decrypt = sm2_decrypt;
		e->sha1 = sm2_sha1;
	}
	*/
	else
	{
		free(e);
		e = NULL;
	}
	if (strlen(sk_filename) < PATH_MAX)
		strcpy(e->sk_filename, sk_filename);
	if (strlen(pk_filename) < PATH_MAX)
		strcpy(e->pk_filename, pk_filename);

	return e;
}
