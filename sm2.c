#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include "eccapi.h"

int sm2(char *buf1, char *buf2, size_t len, const char *pathname,
		int (*crypt)(void *handle, char *buf1, char *buf2, size_t len,
				const char *pathname))
{
	int ret, i;
	void *handle, *session;

	ret = SDF_OpenDevice(&handle);
	if (ret)
	{
		fprintf(stderr, "could open decvice (err=%d)\n", ret);
		goto err_device;
	}

	ret = SDF_OpenSession(handle, &session);
	if (ret)
	{
		fprintf(stderr, "could not open session (err=%d)\n", ret);
		goto err_session;
	}

	ret = crypt(session, buf1, buf2, len, pathname); // encrypt or decrypt

	err_decrypt: SDF_CloseSession(session);
	err_session: SDF_CloseDevice(handle);
	err_device: return ret;
}

int do_encrypt(void *handle, char *plain_text, char *result, size_t len,
		const char *pk_pathname)
{
	int ret = 0;
	unsigned int uiAlgID = SGD_SM2_3;
	ECCrefPublicKey *pucPublicKey; /* public key */
	ECCCipher *pucEncData = (ECCCipher *) malloc(sizeof(ECCCipher)); /* cipher */
	if (pucEncData == NULL )
	{
		fprintf(stderr, "could not alloc ECCCipher\n");
		return -1;
	}

	ret = SDF_ExternalEncrypt_ECC(handle, uiAlgID, pucPublicKey,
			(unsigned char *) plain_text, strlen(plain_text), pucEncData);
	if (ret)
		fprintf(stderr, "failed to decrypt the cipher (err=%d)\n", ret);

	/*
	 * convert the pucEncData to result
	 */

	free(pucEncData);
	return ret;
}

int do_decrypt(void *session, char *cipher, char *result, size_t len,
		const char *sk_pathname)
{
	int ret = 0;
	unsigned int uiAlgID = SGD_SM2_3;
	ECCrefPrivateKey *pucPrivateKey; /* private key */
	ECCCipher *pucEncData; /* cipher */
	unsigned char *recover;
	unsigned int length = 0;

	/*
	 * convert the cipher to pucEncData
	 */
	// ...
	ret = SDF_ExternalDecrypt_ECC(session, uiAlgID, pucPrivateKey, pucEncData,
			recover, &length);
	if (ret)
		fprintf(stderr, "failed to decrypt the cipher (err=%d)\n", ret);

	/*
	 * convert the recover to result
	 */
	//...
	return ret;
}

int do_hash(void *session, char *buf1, char *buf2, size_t len,
		const char *pathname)
{
	FILE *f = fopen(pathname, "r");
	if (NULL == f)
	{
		fprintf(stderr, "%s open failed!\n", pathname);
		return -1;
	}

	int ret = 0;
	unsigned int uiAlgID = SGD_SM3;
	ECCrefPublicKey *pucPublicKey; /* public key */
	unsigned char *pucID = "1001";
	size_t uiIDLength = strlen((char *) pucID);

	ret = SDF_HashInit(session, uiAlgID, pucPublicKey, pucID, uiIDLength);
	if (ret)
	{
		fprintf(stderr, "sm3 sha1 init failed (err=%d)\n", ret);
		return ret;
	}

	char line[LINE_MAX];
	while (fgets(line, LINE_MAX, f))
	{
		int index = strlen(line);
		while (line[index - 1] == '\r' || line[index - 1] == '\n')
			--index;
		if (index < strlen(line))
			line[index] = 0;

		ret = SDF_HashUpdate(session, line, strlen(line));
		if (ret)
		{
			fprintf(stderr, "sm3 sha1 update failed (err=%d)\n", ret);
			goto err;
		}
	}

	unsigned int length = 0;
	ret = SDF_HashFinal(session, buf2, &length);
	if (ret)
		fprintf(stderr, "sm3 sha1 final failed (err=%d)\n", ret);

	err: fclose(f);
	return ret;
}

int encrypt(char *plain_text, char *cipher, size_t len, const char *sk_pathname)
{
	return sm2(plain_text, cipher, len, sk_pathname, do_encrypt);
}

int decrypt(char *cipher, char *recover, size_t len, const char *pk_pathname)
{
	return sm2(cipher, recover, len, pk_pathname, do_decrypt);
}

int sm_sha1(const char *pathname, char *result, size_t len)
{
	return sm2(NULL, result, len, pathname, do_hash);
}
