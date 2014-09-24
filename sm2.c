#include "sm2.h"
#include "rsa.h"

int save_key(ECCrefPublicKey *pk, const char *pk_pathname, ECCrefPrivateKey *sk,
		const char *sk_pathname)
{
	FILE *pf, *sf;
	if (NULL == (pf = fopen(pk_pathname, "w"))
			|| NULL == (sf = fopen(sk_pathname, "w")))
	{
		fprintf(stderr, "save key error(pk=%s sk=%s)\n", pk_pathname,
				sk_pathname);
		return -1;
	}

	fprintf(pf, "%d\n", pk->bits);
	char bx[1000], by[1000];
	if (NULL == base64(pk->x, ECCref_MAX_LEN, bx, 1000)
			|| NULL == base64(pk->y, ECCref_MAX_LEN, by, 1000))
	{
		fprintf(stderr, "base key error\n");
		return -1;
	}
	fputs(bx, pf);
	fputc('\n', pf);
	fputs(by, pf);
	fputc('\n', pf);
	fclose(pf);

	fprintf(sf, "%d\n", sk->bits);
	char bd[1000];
	if (NULL == base64(sk->D, ECCref_MAX_LEN, bd, 1000))
	{
		fprintf(stderr, "base private key error\n");
		return -1;
	}
	fputs(bd, sf);
	fclose(sf);
	return 0;
}

int read_pk(ECCrefPublicKey *pk, const char *pk_pathname)
{
	FILE *pf;
	if (NULL == (pf = fopen(pk_pathname, "r")))
	{
		fprintf(stderr, "save key error (pk=%s)\n", pk_pathname);
		return -1;
	}

	char buf[LINE_MAX];
	if (NULL == fgets(buf, LINE_MAX, pf))
	{
		fprintf(stderr, "get pk: bits error\n");
		return -1;
	}
	pk->bits = atoi(buf);
	if (NULL == fgets(buf, LINE_MAX, pf))
	{
		fprintf(stderr, "get pk: x error\n");
		return -1;
	}
	int l = strlen(buf);
	buf[l - 1] = '\0';
	char temp[100];
	if (NULL
			== debase64(buf, strlen(buf), temp,
					100) || strlen(temp) > ECCref_MAX_LEN){
	fprintf(stderr, "debase public key's x error\n");
	return -1;
}
	strcpy(pk->x, temp);

	if (NULL == fgets(buf, LINE_MAX, pf))
	{
		fprintf(stderr, "get pk: y error\n");
		return -1;
	}
	if (NULL
			== debase64(buf, strlen(buf), temp,
					100) || strlen(temp) > ECCref_MAX_LEN){
	fprintf(stderr, "debase public key's y error\n");
	return -1;
}
	strcpy(pk->y, temp);
	fclose(pf);
	return 0;
}

int read_sk(ECCrefPrivateKey *sk, const char *sk_pathname)
{
	FILE *sf;
	if (NULL == (sf = fopen(sk_pathname, "r")))
	{
		fprintf(stderr, "save key error (sk=%s)\n", sk_pathname);
		return -1;
	}

	char buf[LINE_MAX];
	if (NULL == fgets(buf, LINE_MAX, sf))
	{
		fprintf(stderr, "get sk: bits error\n");
		return -1;
	}
	sk->bits = atoi(buf);
	if (NULL == fgets(buf, LINE_MAX, sf))
	{
		fprintf(stderr, "get sk: d error\n");
		return -1;
	}
	char temp[100];
	if (NULL
			== debase64(buf, strlen(buf), temp,
					100) || strlen(temp) > ECCref_MAX_LEN){
	fprintf(stderr, "debase private key's D error\n");
	return -1;
}
	strcpy(sk->D, temp);
	fclose(sf);
	return 0;
}

int debase_cipher(char *buf, char **ptr, char *result)
{
	char temp[100];
	if (NULL == (*ptr = strtok(buf, "$")))
	{
		fprintf(stderr, "the string cipher is error(%s)\n", buf);
		return -1;
	}
	if (NULL
			== debase64(*ptr, strlen(*ptr), temp,
					100) || strlen(temp) > ECCref_MAX_LEN){
	fprintf(stderr, "debase cipher x error\n");
	return -1;
}
	strcpy(result, temp);
	return 0;
}

int str_to_cipher(ECCCipher *cipher, char *buf, size_t len)
{
	char *ptr;
	if (-1 == debase_cipher(buf, &ptr, cipher->x))
		return -1;

	if (-1 == debase_cipher(NULL, &ptr, cipher->y))
		return -1;

	if (-1 == debase_cipher(NULL, &ptr, cipher->C))
		return -1;

	if (-1 == debase_cipher(NULL, &ptr, cipher->M))
		return -1;
	return 0;
}

int cat_str(char *line, size_t len, char *buf, size_t *count)
{
	*count += strlen(buf) + 1;
	printf("count=%d %s\n", *count, buf);
	if (*count > len)
	{
		fprintf(stderr, "base cipher memory not enouth (size=%d)\n", len);
		return -1;
	}
	strcat(line, buf);
	strcat(line, "$");
	return 0;
}

int cipher_to_str(ECCCipher *cipher, char *line, size_t len)
{
	int count = 0;
	char buf[1000];
	strcpy(line, "");
	if (NULL == base64(cipher->x, ECCref_MAX_LEN, buf, 1000))
	{
		fprintf(stderr, "base cipher x error\n");
		return -1;
	}
	if (-1 == cat_str(line, len, buf, &count))
		return -1;

	if (NULL == base64(cipher->y, ECCref_MAX_LEN, buf, 1000))
	{
		fprintf(stderr, "base cipher y error\n");
		return -1;
	}
	if (-1 == cat_str(line, len, buf, &count))
		return -1;

	if (NULL == base64(cipher->C, ECCref_MAX_LEN, buf, 1000))
	{
		fprintf(stderr, "base cipher C error\n");
		return -1;
	}
	if (-1 == cat_str(line, len, buf, &count))
		return -1;

	if (NULL == base64(cipher->M, ECCref_MAX_LEN, buf, 1000))
	{
		fprintf(stderr, "base cipher M error\n");
		return -1;
	}
	if (-1 == cat_str(line, len, buf, &count))
		return -1;
	line[strlen(line) - 1] = '\0'; // remove the last '$'
	return 0;
}

int sm2(char *buf1, char *buf2, size_t len, const char *pathname,
		int (*crypt)(void *handle, char *buf1, char *buf2, size_t len,
				const char *pathname))
{
	int ret, i;
	void *handle, *session;

	ret = SDF_OpenDevice(&handle);
	if (ret)
	{
		fprintf(stderr, "could open device (err=%d)\n", ret);
		goto err_device;
	}

	ret = SDF_OpenSession(handle, &session);
	if (ret)
	{
		fprintf(stderr, "could not open session (err=%d)\n", ret);
		goto err_session;
	}

	ret = crypt(session, buf1, buf2, len, pathname); // encrypt or decrypt

	SDF_CloseSession(session);
	err_session: SDF_CloseDevice(handle);
	err_device: return ret;
}

int do_encrypt(void *handle, char *plain_text, char *result, size_t len,
		const char *pk_pathname)
{
	int ret = 0;
	unsigned int uiAlgID = SGD_SM2_3;
	ECCrefPublicKey pucPublicKey;
	if (-1 == read_pk(pucPublicKey, pk_pathname))
		return -1;

	ECCCipher pucEncData;
	ret = SDF_ExternalEncrypt_ECC(handle, uiAlgID, &pucPublicKey,
			(unsigned char *) plain_text, strlen(plain_text), &pucEncData);
	if (ret)
	{
		fprintf(stderr, "failed to decrypt the cipher (err=%d)\n", ret);
		return -1;
	}

	// convert the struct to string
	if (-1 == cipher_to_str(&pucEncData, result, len))
		ret = -1;

	return ret;
}

int do_decrypt(void *session, char *cipher, char *result, size_t len,
		const char *sk_pathname)
{
	int ret = 0;
	unsigned int uiAlgID = SGD_SM2_3;
	ECCrefPrivateKey pucPrivateKey;
	ECCCipher pucEncData;

	if (-1 == read_sk(pucPrivateKey, sk_pathname))
		return -1;

	// convert the string cipher to struct cipher
	if (-1 == str_to_cipher(&pucEncData, cipher, strlen(cipher)))
		return -1;

	// decrypt the punEncData, and save the answer in parameter:result
	ret = SDF_ExternalDecrypt_ECC(session, uiAlgID, &pucPrivateKey, &pucEncData,
			result, &len);
	if (ret)
		fprintf(stderr, "failed to decrypt the cipher (err=%d)\n", ret);

	return ret;
}

int do_hash(void *session, char *pathname, char *buf2, size_t len,
		const char *pk_pathname)
{
	int ret = 0;
	unsigned int uiAlgID = SGD_SM3;
	ECCrefPublicKey pucPublicKey;
	unsigned char *pucID = "501"; // communicate with KMC, can be any string
	size_t uiIDLength = strlen((char *) pucID);

	if (-1 == read_pk(pucPublicKey, pk_pathname))
		return -1;

	FILE *f = fopen(pathname, "r");
	if (NULL == f)
	{
		fprintf(stderr, "%s open failed!\n", pathname);
		return -1;
	}

	ret = SDF_HashInit(session, uiAlgID, &pucPublicKey, pucID, uiIDLength);
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

int sm2_encrypt(char *plain_text, char *cipher, size_t len,
		const char *sk_pathname)
{
	return sm2(plain_text, cipher, len, sk_pathname, do_encrypt);
}

int sm2_decrypt(char *cipher, char *recover, size_t len,
		const char *pk_pathname)
{
	return sm2(cipher, recover, len, pk_pathname, do_decrypt);
}

int sm2_sha1(const char *pathname, char *result, size_t len,
		const char *pk_pathname)
{
	return sm2(pathname, result, len, pk_pathname, do_hash);
}
