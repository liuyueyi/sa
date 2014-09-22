#ifndef _ECCAPI_H
#define _ECCAPI_H

#ifdef __cplusplus
extern "C" {
#endif

/********************     ERROR CODE     ********************/
#define SDR_OK					0x00000000	//����ִ�гɹ�
#define SDR_BASE				0x01000000	//���������ֵ
#define SDR_UNKNOWERR			SDR_BASE + 0x00000001	//δ֪����
#define SDR_NOTSUPPORT			SDR_BASE + 0x00000002	//��֧�ֵĽӿڵ���
#define SDR_COMMFAIL			SDR_BASE + 0x00000003	//���豸ͨ��ʧ��
#define SDR_HARDFAIL			SDR_BASE + 0x00000004	//����ģ������Ӧ
#define SDR_OPENDEVICE			SDR_BASE + 0x00000005	//���豸ʧ��
#define SDR_OPENSESSION			SDR_BASE + 0x00000006	//�����Ựʧ��
#define SDR_PARDENY				SDR_BASE + 0x00000007	//��˽Կʹ��Ȩ��
#define SDR_KEYNOTEXIST			SDR_BASE + 0x00000008	//�����ڵ���Կ����
#define SDR_ALGNOTSUPPORT		SDR_BASE + 0x00000009	//��֧�ֵ��㷨����
#define SDR_ALGMODNOTSUPPORT	SDR_BASE + 0x0000000A 	//��֧�ֵ��㷨ģʽ����
#define SDR_PKOPERR				SDR_BASE + 0x0000000B 	//��Կ����ʧ��
#define SDR_SKOPERR				SDR_BASE + 0x0000000C 	//˽Կ����ʧ��
#define SDR_SIGNERR				SDR_BASE + 0x0000000D 	//ǩ������ʧ��
#define SDR_VERIFYERR			SDR_BASE + 0x0000000E	//��֤ǩ��ʧ��
#define SDR_SYMOPERR			SDR_BASE + 0x0000000F 	//�Գ��㷨����ʧ��
#define SDR_STEPERR				SDR_BASE + 0x00000010	//�ಽ���㲽�����
#define SDR_FILESIZEERR			SDR_BASE + 0x00000011	//�ļ����ȳ�������
#define SDR_FILENOEXIST			SDR_BASE + 0x00000012	//ָ�����ļ�������
#define SDR_FILEOFSERR			SDR_BASE + 0x00000013	//�ļ���ʼλ�ô���
#define SDR_KEYTYPEERR			SDR_BASE + 0x00000014	//��Կ���ʹ���
#define SDR_KEYERR				SDR_BASE + 0x00000015	//��Կ����

#define SDR_INPUT_LEN_ERROR		SDR_BASE + 0x00000016	//�����������ָʾ����
#define SDR_NO_BUFFER			SDR_BASE + 0x00000017	//�����������ռ�δָ��
#define SDR_BUFFER_TOO_SMALL	SDR_BASE + 0x00000018	//�����������ռ�̫С
#define SDR_KEYID_INVALID		SDR_BASE + 0x00000019	//ָ������Կ�ŷǷ�
#define SDR_NOT_INITIALIZED		SDR_BASE + 0x00000020	//δ���ó�ʼ��
#define SDR_ALREADY_INITIALIZED	SDR_BASE + 0x00000021	//��ʼ���ѵ���

//�Գ��㷨��ʶ 
#define SGD_SM1_ECB		0x00000101// SM1�㷨ECB����ģʽ
#define SGD_SM1_CBC		0x00000102// SM1�㷨CBC����ģʽ
#define SGD_SM1_OFB		0x00000108// SM1�㷨OFB����ģʽ
#define SGD_SM1_MAC		0x00000110// SM1�㷨MAC����ģʽ
#define SGD_SSF33_ECB	0x00000201// SSF33�㷨ECB����ģʽ

//�ǶԳ��㷨��ʶ
#define SGD_SM2_1		0x00020100// ��Բ����ǩ���㷨
#define SGD_SM2_2		0x00020200// ��Բ������Կ����Э��
#define SGD_SM2_3		0x00020400// ��Բ���߼����㷨

//�Ӵ��㷨��ʶ
#define SGD_SM3			0x00000001	//SM3�Ӵ��㷨
#define SGD_SHA1		0x00000002	//SHA1�Ӵ��㷨
#define SGD_SHA256	0x00000004	//SHA256�Ӵ��㷨

#define SGD_SCH_ID	0x00000040// ��ID��SCH�㷨����
#define SGD_SCH			SGD_SM3	//SM3�Ӵ��㷨
//�豸��Ϣ�ṹ
typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
}DEVICEINFO;

//ECC��Կ���ݽṹ����
#define ECCref_MAX_BITS			256
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)
typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN]; 
	unsigned char y[ECCref_MAX_LEN]; 
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
  unsigned char D[ECCref_MAX_LEN]; 
} ECCrefPrivateKey;

//ECC�������ݽṹ����
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN]; 
	unsigned char y[ECCref_MAX_LEN]; 
	unsigned char C[ECCref_MAX_LEN];
	unsigned char M[ECCref_MAX_LEN];
} ECCCipher;

//ECCǩ�����ݽṹ����
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];	
	unsigned char s[ECCref_MAX_LEN];	
} ECCSignature;

/*************************�豸������**********************/
int SDF_OpenDevice(void **phDeviceHandle);
int SDF_CloseDevice(void *hDeviceHandle);
int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
int SDF_CloseSession(void *hSessionHandle);
int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);
int SDF_GenerateRandom(void *hSessionHandle, unsigned int  uiLength,unsigned char *pucRandom);
int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int  uiKeyIndex,
								 unsigned char *pucPassword,unsigned int  uiPwdLength);
int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int  uiKeyIndex);

int free_sem(); //�ź������

/*************************��Կ������**********************/
int SDF_ExportSignPublicKey_ECC(
																void *hSessionHandle, 
																unsigned int  uiKeyIndex,
																ECCrefPublicKey *pucPublicKey
																);
							
int SDF_ExportEncPublicKey_ECC(
																void *hSessionHandle, 
																unsigned int  uiKeyIndex,
																ECCrefPublicKey *pucPublicKey
																);
																
int SDF_GenerateKeyPair_ECC(
														void *hSessionHandle, 
														unsigned int  uiAlgID,
														unsigned int  uiKeyBits,
														ECCrefPublicKey *pucPublicKey,
														ECCrefPrivateKey *pucPrivateKey
														);

int SDF_GenerateKeyWithIPK_ECC (
																void *hSessionHandle, 
																unsigned int uiIPKIndex,
																unsigned int uiKeyBits,
																ECCCipher *pucKey,
																void **phKeyHandle
																);

int SDF_GenerateKeyWithEPK_ECC (
																void *hSessionHandle,
																unsigned int uiKeyBits,
																unsigned int uiAlgID, 
																ECCrefPublicKey *pucPublicKey,
																ECCCipher *pucKey,
																void **phKeyHandle
																);



int SDF_GenerateKeyWithKEK(void *hSessionHandle,
							   unsigned int uiKeyBits,
							   unsigned int  uiAlgID,
							   unsigned int uiKEKIndex, 
							   unsigned char *pucKey,
								unsigned int *puiKeyLength, 
								void **phKeyHandle);

int SDF_ImportKeyWithISK_ECC (
															void *hSessionHandle,
															unsigned int uiISKIndex,
															ECCCipher *pucKey,
															void **phKeyHandle
															);


int SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int  uiAlgID,unsigned int uiKEKIndex, 
						 unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);

int SDF_GenerateKeyWithECC_ECDH (
														void *hSessionHandle, 
														ECCrefPrivateKey *pucPrivateKey,
														ECCrefPublicKey *pucPublicKey,
														void **phKeyHandle
														);
int SDF_GenerateAgreementDataWithECC (
									  void *hSessionHandle, 
									  unsigned int uiISKIndex,
									  unsigned int uiKeyBits,
									  unsigned char *pucSponsorID,
									  unsigned int uiSponsorIDLength,
									  ECCrefPublicKey  *pucSponsorPublicKey,
									  ECCrefPublicKey  *pucSponsorTmpPublicKey,
									  void **phAgreementHandle);
int SDF_GenerateKeyWithECC (
								void *hSessionHandle, 
								unsigned char *pucResponseID,
								unsigned int uiResponseIDLength,
								ECCrefPublicKey *pucResponsePublicKey,
								ECCrefPublicKey *pucResponseTmpPublicKey,
								void *phAgreementHandle,
								void **phKeyHandle);

int SDF_GenerateAgreementDataAndKeyWithECC (
												void *hSessionHandle, 
												unsigned int uiISKIndex,
												unsigned int uiKeyBits,
												unsigned char *pucResponseID,
												unsigned int uiResponseIDLength,
												unsigned char *pucSponsorID,
												unsigned int uiSponsorIDLength,
												ECCrefPublicKey *pucSponsorPublicKey,
												ECCrefPublicKey *pucSponsorTmpPublicKey,
												ECCrefPublicKey  *pucResponsePublicKey,
												ECCrefPublicKey  *pucResponseTmpPublicKey,
												void **phKeyHandle);

int SDF_ExchangeDigitEnvelopeBaseOnECC(
									   void *hSessionHandle, 
									   unsigned int  uiKeyIndex,
									   unsigned int  uiAlgID,
									   ECCrefPublicKey *pucPublicKey,
									   ECCCipher *pucDEInput,
									   ECCCipher *pucDEOutput);
									   
int SDF_ImportKey(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
int SDF_DestoryKey(void *hSessionHandle, void *hKeyHandle);

/*********************�ǶԳ�������***********************/
int SDF_ExternalSign_ECC(
													void *hSessionHandle,
													unsigned int uiAlgID,
													ECCrefPrivateKey *pucPrivateKey,
													unsigned char *pucData,
													unsigned int  uiDataLength,
													ECCSignature *pucSignature
													);

int SDF_ExternalVerify_ECC(
														void *hSessionHandle,
														unsigned int uiAlgID,
														ECCrefPublicKey *pucPublicKey,
														unsigned char *pucDataInput,
														unsigned int  uiInputLength,
														ECCSignature *pucSignature
														);
														
int SDF_InternalSign_ECC(
													void *hSessionHandle,
													unsigned int  uiISKIndex,
													unsigned char *pucData,
													unsigned int  uiDataLength,
													ECCSignature *pucSignature
													);

int SDF_InternalVerify_ECC(
														void *hSessionHandle,
														unsigned int  uiISKIndex,
														unsigned char *pucData,
														unsigned int  uiDataLength,
														ECCSignature *pucSignature
														);

int SDF_ExternalEncrypt_ECC(
								void *hSessionHandle,
								unsigned int uiAlgID,
								ECCrefPublicKey *pucPublicKey,
								unsigned char *pucData,
								unsigned int  uiDataLength,
								ECCCipher *pucEncData
								);

int SDF_ExternalDecrypt_ECC(
								void *hSessionHandle,
								unsigned int uiAlgID,
								ECCrefPrivateKey *pucPrivateKey,
								ECCCipher *pucEncData,
								unsigned char *pucData,
								unsigned int  *puiDataLength
								);


//�ԳƼ���
int SDF_Encrypt_Ex(void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength,
				unsigned int uiAlgID,unsigned char *pucIV,
				unsigned char *pucData,unsigned int uiDataLength,
				unsigned char *pucEncData,unsigned int  *puiEncDataLength);
int SDF_Decrypt_Ex (void *hSessionHandle, unsigned char *pucKey, unsigned int uiKeyLength,
				 unsigned int uiAlgID,unsigned char *pucIV,
				 unsigned char *pucEncData,unsigned int uiEncDataLength,
				 unsigned char *pucData,unsigned int  *puiDataLength);

int SDF_Encrypt(void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,
				unsigned char *pucData,unsigned int uiDataLength,
				unsigned char *pucEncData,unsigned int  *puiEncDataLength);

int SDF_Decrypt (void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,
				 unsigned char *pucEncData,unsigned int uiEncDataLength,
				 unsigned char *pucData,unsigned int  *puiDataLength);
int SDF_CalculateMAC(void *hSessionHandle,void *hKeyHandle,unsigned int uiAlgID,unsigned char *pucIV,
					 unsigned char *pucData,unsigned int uiDataLength,
					 unsigned char *pucMAC,unsigned int  *puiMACLength);

//�Ӵ�������
int SDF_HashInit(void *hSessionHandle,
					 unsigned int uiAlgID,
					 ECCrefPublicKey *pucPublicKey,
					 unsigned char *pucID,
					 unsigned int uiIDLength);
int SDF_HashUpdate(void *hSessionHandle,unsigned char *pucData,unsigned int  uiDataLength);
int SDF_HashFinal(void *hSessionHandle,unsigned char *pucHash,unsigned int  *puiHashLength);
int SDF_Hash(
			 		  void *hSessionHandle,
			 		  unsigned int uiAlgID,
			 		  ECCrefPublicKey *pucPublicKey,
						unsigned char *pucID,
						unsigned int  uiIDLength,
						unsigned char *pucData,
						unsigned int  uiDataLength,
						unsigned char *pucHash,
						unsigned int  *puiHashLength
						);
			 
//�û��ļ�������
int SDF_CreateFile(void *hSessionHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);
int SDF_ReadFile(void *hSessionHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
				 unsigned int  *puiFileLength, unsigned char *pucBuffer);
int SDF_WriteFile(void *hSessionHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
				  unsigned int  uiFileLength,unsigned char *pucBuffer);
int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen);


//�����û�ǩ����Կ���ܹ����û�������Կ���ģ�����ӹ����������
int GenerateEncryptedIK(
						void *hSessionHandle,
						unsigned int  uiKeyIndex,
						ECCrefPublicKey *pucPublicKey,
						ECCrefPrivateKey *pucPrivateKey,
						unsigned char *pucEncData,
						unsigned int  *uiEncDataLength
						);
//�����豸������Կ���ܹ�����Կ������Կ���ģ�����ӹ����������
int GenerateEncryptedKEK(
						 void *hSessionHandle,
						 unsigned int  uiKeyIndex,
						 unsigned char *pucKEK,//256λ
						 unsigned char *pucEncData,
						 unsigned int  *uiEncDataLength
						);
int CreatUKeyHash(void *hSessionHandle,			//�����û���ԿHASHֵ
				  unsigned int   KeyId,
				  unsigned char * pHASHData,
				  unsigned int  * pHASHDataLen
				  );
int LoginIC(void *hSessionHandle,					//IC��������֤
			unsigned char   * pIcPassword,
			unsigned int  ICPasswordLen
			);
int ChangeICPassword(void *hSessionHandle,		//IC�������޸�
					  unsigned char   * pIcOldPassword,
					  unsigned int    ICOldPasswordLen,
					  unsigned char   * pIcNewPassword,
					  unsigned int    ICNewPasswordLen
						);							  						
#ifdef __cplusplus
}
#endif
#endif


