#ifndef _ECCAPI_H
#define _ECCAPI_H

#ifdef __cplusplus
extern "C" {
#endif

/********************     ERROR CODE     ********************/
#define SDR_OK					0x00000000	//函数执行成功
#define SDR_BASE				0x01000000	//错误码基础值
#define SDR_UNKNOWERR			SDR_BASE + 0x00000001	//未知错误
#define SDR_NOTSUPPORT			SDR_BASE + 0x00000002	//不支持的接口调用
#define SDR_COMMFAIL			SDR_BASE + 0x00000003	//与设备通信失败
#define SDR_HARDFAIL			SDR_BASE + 0x00000004	//运算模块无响应
#define SDR_OPENDEVICE			SDR_BASE + 0x00000005	//打开设备失败
#define SDR_OPENSESSION			SDR_BASE + 0x00000006	//创建会话失败
#define SDR_PARDENY				SDR_BASE + 0x00000007	//无私钥使用权限
#define SDR_KEYNOTEXIST			SDR_BASE + 0x00000008	//不存在的密钥调用
#define SDR_ALGNOTSUPPORT		SDR_BASE + 0x00000009	//不支持的算法调用
#define SDR_ALGMODNOTSUPPORT	SDR_BASE + 0x0000000A 	//不支持的算法模式调用
#define SDR_PKOPERR				SDR_BASE + 0x0000000B 	//公钥运算失败
#define SDR_SKOPERR				SDR_BASE + 0x0000000C 	//私钥运算失败
#define SDR_SIGNERR				SDR_BASE + 0x0000000D 	//签名运算失败
#define SDR_VERIFYERR			SDR_BASE + 0x0000000E	//验证签名失败
#define SDR_SYMOPERR			SDR_BASE + 0x0000000F 	//对称算法运算失败
#define SDR_STEPERR				SDR_BASE + 0x00000010	//多步运算步骤错误
#define SDR_FILESIZEERR			SDR_BASE + 0x00000011	//文件长度超出限制
#define SDR_FILENOEXIST			SDR_BASE + 0x00000012	//指定的文件不存在
#define SDR_FILEOFSERR			SDR_BASE + 0x00000013	//文件起始位置错误
#define SDR_KEYTYPEERR			SDR_BASE + 0x00000014	//密钥类型错误
#define SDR_KEYERR				SDR_BASE + 0x00000015	//密钥错误

#define SDR_INPUT_LEN_ERROR		SDR_BASE + 0x00000016	//输入参数长度指示错误
#define SDR_NO_BUFFER			SDR_BASE + 0x00000017	//输出参数缓冲空间未指定
#define SDR_BUFFER_TOO_SMALL	SDR_BASE + 0x00000018	//输出参数缓冲空间太小
#define SDR_KEYID_INVALID		SDR_BASE + 0x00000019	//指定的密钥号非法
#define SDR_NOT_INITIALIZED		SDR_BASE + 0x00000020	//未调用初始化
#define SDR_ALREADY_INITIALIZED	SDR_BASE + 0x00000021	//初始化已调用

//对称算法标识 
#define SGD_SM1_ECB		0x00000101// SM1算法ECB加密模式
#define SGD_SM1_CBC		0x00000102// SM1算法CBC加密模式
#define SGD_SM1_OFB		0x00000108// SM1算法OFB加密模式
#define SGD_SM1_MAC		0x00000110// SM1算法MAC加密模式
#define SGD_SSF33_ECB	0x00000201// SSF33算法ECB加密模式

//非对称算法标识
#define SGD_SM2_1		0x00020100// 椭圆曲线签名算法
#define SGD_SM2_2		0x00020200// 椭圆曲线密钥交换协议
#define SGD_SM2_3		0x00020400// 椭圆曲线加密算法

//杂凑算法标识
#define SGD_SM3			0x00000001	//SM3杂凑算法
#define SGD_SHA1		0x00000002	//SHA1杂凑算法
#define SGD_SHA256	0x00000004	//SHA256杂凑算法

#define SGD_SCH_ID	0x00000040// 带ID的SCH算法机制
#define SGD_SCH			SGD_SM3	//SM3杂凑算法
//设备信息结构
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

//ECC密钥数据结构定义
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

//ECC加密数据结构定义
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN]; 
	unsigned char y[ECCref_MAX_LEN]; 
	unsigned char C[ECCref_MAX_LEN];
	unsigned char M[ECCref_MAX_LEN];
} ECCCipher;

//ECC签名数据结构定义
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];	
	unsigned char s[ECCref_MAX_LEN];	
} ECCSignature;

/*************************设备管理类**********************/
int SDF_OpenDevice(void **phDeviceHandle);
int SDF_CloseDevice(void *hDeviceHandle);
int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle);
int SDF_CloseSession(void *hSessionHandle);
int SDF_GetDeviceInfo(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);
int SDF_GenerateRandom(void *hSessionHandle, unsigned int  uiLength,unsigned char *pucRandom);
int SDF_GetPrivateKeyAccessRight(void *hSessionHandle, unsigned int  uiKeyIndex,
								 unsigned char *pucPassword,unsigned int  uiPwdLength);
int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle, unsigned int  uiKeyIndex);

int free_sem(); //信号量清除

/*************************密钥管理类**********************/
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

/*********************非对称运算类***********************/
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


//对称加密
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

//杂凑运算类
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
			 
//用户文件操作类
int SDF_CreateFile(void *hSessionHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);
int SDF_ReadFile(void *hSessionHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
				 unsigned int  *puiFileLength, unsigned char *pucBuffer);
int SDF_WriteFile(void *hSessionHandle,unsigned char *pucFileName, unsigned int uiNameLen, unsigned int uiOffset,
				  unsigned int  uiFileLength,unsigned char *pucBuffer);
int SDF_DeleteFile(void *hSessionHandle, unsigned char *pucFileName, unsigned int uiNameLen);


//生成用户签名密钥加密过的用户加密密钥密文，方便从管理程序下载
int GenerateEncryptedIK(
						void *hSessionHandle,
						unsigned int  uiKeyIndex,
						ECCrefPublicKey *pucPublicKey,
						ECCrefPrivateKey *pucPrivateKey,
						unsigned char *pucEncData,
						unsigned int  *uiEncDataLength
						);
//生成设备加密密钥加密过的密钥加密密钥密文，方便从管理程序下载
int GenerateEncryptedKEK(
						 void *hSessionHandle,
						 unsigned int  uiKeyIndex,
						 unsigned char *pucKEK,//256位
						 unsigned char *pucEncData,
						 unsigned int  *uiEncDataLength
						);
int CreatUKeyHash(void *hSessionHandle,			//生成用户密钥HASH值
				  unsigned int   KeyId,
				  unsigned char * pHASHData,
				  unsigned int  * pHASHDataLen
				  );
int LoginIC(void *hSessionHandle,					//IC卡口令验证
			unsigned char   * pIcPassword,
			unsigned int  ICPasswordLen
			);
int ChangeICPassword(void *hSessionHandle,		//IC卡口令修改
					  unsigned char   * pIcOldPassword,
					  unsigned int    ICOldPasswordLen,
					  unsigned char   * pIcNewPassword,
					  unsigned int    ICNewPasswordLen
						);							  						
#ifdef __cplusplus
}
#endif
#endif


