/*
 * aes.c
 *
 *  Created on: 2014-8-21
 *      Author: pc
 */

#include "rsa.h"
#include <limits.h>

char *base64(const char *input, size_t length, char *result, size_t size)
{
	BIO * bmem = NULL;
	BIO * b64 = NULL;
	BUF_MEM * bptr = NULL;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	if (bptr->length + 1 > size)
	{
		BIO_free_all(b64);
		return NULL ;
	}
	memcpy(result, bptr->data, bptr->length);
	result[bptr->length] = 0;

	BIO_free_all(b64);

	return result;
}

char *debase64(char *input, size_t length, char *result, size_t size)
{
	BIO * b64 = NULL;
	BIO * bmem = NULL;
	if (length > size)
		return NULL ;
	memset(result, 0, size);

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	BIO_read(bmem, result, length);
	BIO_free_all(bmem);

	return result;
}

char *sha1(const char *filename, char *result, size_t len)
{
	FILE *f = fopen(filename, "r");
	if (NULL == f)
	{
		fprintf(stderr, "%s open failed!\n", filename);
		return NULL ;
	}

	SHA_CTX c;
	unsigned char dest[SHA_DIGEST_LENGTH + 1];
	if (!SHA1_Init(&c) || dest == NULL )
	{
		fprintf(stderr, "calcuate sha1 dest error\n");
		return NULL ;
	}
	memset(dest, 0, SHA_DIGEST_LENGTH + 1);
	char line[LINE_MAX];
	while (fgets(line, LINE_MAX, f))
	{
		int index = strlen(line);
		while (line[index - 1] == '\r' || line[index - 1] == '\n')
			--index;
		if (index < strlen(line))
		{
			line[index] = '\n';
			line[index + 1] = 0;
		}
		SHA1_Update(&c, line, strlen(line));
	}

	SHA1_Final(dest, &c);
	OPENSSL_cleanse(&c, sizeof(c));
	fclose(f);

	base64(dest, strlen(dest), result, len);
	return result;
}

char *rsa_encrypt(const char *plain_text, char *result, size_t size,
		const char *pk_filename)
{
	unsigned char *cipher;
	int len;
	RSA *rsa;
	FILE *file;

	if (NULL == (file = fopen(pk_filename, "rb")))
	{
		fprintf(stderr, "%s public key file not exist!\n", pk_filename);
		return NULL ;
	}
	if (NULL == (rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL )))
	{
		ERR_print_errors_fp(stdout);
		return NULL ;
	}
	fclose(file);

	len = RSA_size(rsa);
	if (NULL == (cipher = (unsigned char *) malloc(len + 1)))
	{
		RSA_free(rsa);
		return NULL ;
	}
	memset(cipher, 0, len + 1);

	if (0
			> RSA_public_encrypt(strlen(plain_text),
					(unsigned char *) plain_text, (unsigned char*) cipher, rsa,
					RSA_PKCS1_PADDING))
	{
		RSA_free(rsa);
		free(cipher);
		return NULL ;
	}

	RSA_free(rsa);
	base64((char *) cipher, strlen((char *) cipher), result, size);
	free(cipher);
	return result;
}

char *rsa_decrypt(const char *cipher, char *plain_text, size_t size,
		const char *sk_filename)
{
	FILE *file = NULL;
	RSA *rsa;
	int len;

	if (NULL == (file = fopen(sk_filename, "rb")))
	{
		fprintf(stderr, "%s private key file not exist!\n", sk_filename);
		return NULL ;
	}
	if ((rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL )) == NULL )
	{
		ERR_print_errors_fp(stdout);
		return NULL ;
	}
	fclose(file);

	len = RSA_size(rsa);
	memset(plain_text, 0, size);

	char temp[250];
	if (NULL == debase64(cipher, strlen(cipher), temp, 250))
	{
		RSA_free(rsa);
		fprintf(stderr, "decrypt error\n");
		return NULL ;
	}

	if (0
			> RSA_private_decrypt(len, (unsigned char *) temp,
					(unsigned char*) plain_text, rsa, RSA_PKCS1_PADDING))
	{
		RSA_free(rsa);
		return NULL ;
	}

	RSA_free(rsa);
	return plain_text;
}

char *rsa_sign(const char *text, char *signature, size_t size,
		const char *sk_filename)
{
	RSA *rsa;
	FILE *file;
	unsigned char *sig;
	unsigned int sig_len;

	if (NULL == (file = fopen(sk_filename, "rb")))
	{
		printf("error:open key file error\n");
		return NULL ;
	}
	if ((rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL )) == NULL )
	{
		ERR_print_errors_fp(stdout);
		return NULL ;
	}
	fclose(file);

	if (NULL == (sig = (unsigned char*) malloc(RSA_size(rsa))))
	{
		RSA_free(rsa);
		return NULL ;
	}

	unsigned char temp[50];
	SHA((const unsigned char *) text, strlen(text), temp);
	if (1 != RSA_sign(NID_sha1, temp, 16, sig, &sig_len, rsa))
	{
		printf("error:fail to sign the message!\n");
		free(sig);
		RSA_free(rsa);
		return NULL ;
	}

	RSA_free(rsa);
	base64((char *) sig, strlen((char *) sig), signature, size);
	free(sig);
	return signature;
}

int rsa_verify(const char *text, const char *sig, const char *pk_filename)
{
	RSA *rsa;
	FILE *file;

	if (NULL == (file = fopen(pk_filename, "rb")))
	{
		printf("error:open key file error\n");
		return -1;
	}
	if ((rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL )) == NULL )
	{
		ERR_print_errors_fp(stdout);
		return -1;
	}
	fclose(file);

	char sig_temp[250];
	if (NULL == debase64(sig, strlen((char *) sig), sig_temp, 250))
	{
		return -1;
	}

	unsigned char temp[50];
	SHA((const unsigned char *) text, strlen(text), temp);
	int ret = RSA_verify(NID_sha1, temp, 16, (unsigned char *) sig_temp, 128,
			rsa);
	RSA_free(rsa);
	return (ret == 1) ? 0 : -1;
}
