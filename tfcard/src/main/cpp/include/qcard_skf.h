/*************************************************
 Copyright (C), 2009 Qasky Co., Ltd
 File name: qcard_skf.h
 Author: Jianbin Wang    Version:  1.1.0      Date: 2019年5月20日
 Description: 量子移动存储设备应用接口
 *************************************************/
#ifndef QCARD_SKF_H
#define QCARD_SKF_H
#include "qcard_type.h"

#ifdef _WIN32
#ifndef QCARD_API
#define QCARD_API __declspec(dllexport)
#endif
#else
#define QCARD_API 
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
* Function Name  : QCard_GetDevInfo
* Description    : 获取设备信息
* Input          : phStoreHandle : QCard_EnumStore枚举成功后的安全存储区句柄
* Output         : pInfo         : 设备信息
*******************************************************************************/
QCARD_API int QCard_GetDevInfo(QHANDLE hStoreHandle, QCard_DEVINFO *pInfo);

/*******************************************************************************
* Function Name  : QCard_GetAppInfo
* Description    : 查看设备应用信息
* Input          : hStoreHandle : 安全存储区句柄
* Output         : pAppList     : 设备应用列表
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetAppInfo(QHANDLE hStoreHandle, QCard_APPLIST *pAppList);

/*******************************************************************************
* Function Name  : QCard_FreeAppInfo
* Description    : 释放设备应用信息
* Input          : AppList : 设备应用列表
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API void QCard_FreeAppInfo(QCard_APPLIST *AppList);

/*******************************************************************************
* Function Name  : QCard_CreateApp
* Description    : 创建应用
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcAdminPin      : 管理员PIN
*                : ulAdminPinRetry : 管理员PIN最大重试次数
*                : pcUserPin       : 用户PIN
*                : ulUserPinRetry  : 用户PIN最大重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_CreateApp(QHANDLE hStoreHandle, char *pcAppName, char *pcAdminPin,
				unsigned long ulAdminPinRetry, char *pcUserPin, unsigned long ulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_DelectApp
* Description    : 删除应用
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_DelectApp(QHANDLE hStoreHandle, char *pcAppName);

/*******************************************************************************
* Function Name  : QCard_DelectApp
* Description    : 删除应用
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_DelectApp_SKF(QHANDLE hStoreHandle, char *pcAppName);

/*******************************************************************************
* Function Name  : QCard_UnblockContainer
* Description    : 解锁应用
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcAdminPin      : 管理员PIN
*                : pcNewUserPin    : 用户新PIN
*                : pulAdinPinRetry : 管理员PIN最大重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_UnblockApp(QHANDLE hStoreHandle, char *pcAppName,  char *pcAdminPin,
									char *pcNewUserPin, unsigned long * pulAdminPinRetry);

/*******************************************************************************
* Function Name  : QCard_ChangePIN
* Description    : 修改PIN
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : ulPinType       : PIN类型 ADMIN_TYPE/USER_TYPE
*                : pcOldPin        : 旧PIN
*                : pcNewPin        : 新PIN
*                : pulPinRetry     : PIN重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ChangeAppPin(QHANDLE hStoreHandle, char *pcAppName, unsigned long ulPinType,
									char *pcOldPin, char *pcNewPin, unsigned long *pulPinRetry);

/*******************************************************************************
* Function Name  : QCard_CreateContainer
* Description    : 创建容器
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcUserPin       : 应用用户PIN
*                : pcContainerName : 容器名称
* Output         : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_CreateContainer(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin, 
									unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_DeleteContainer
* Description    : 删除容器
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcContainerName : 容器名称
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_DeleteContainer(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin, 
									unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_GenRSAKeyPair
* Description    : 生成RSA签名密钥对
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : ulBitsLen       : 密钥模长, 一般填写2048
*                : pcUserPin       : 用户PIN
* Output         : ulUserPinRetry  : 用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GenRSAKeyPair(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned long ulBitsLen,
								  char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_VerifyAppPIN
* Description    : 校验PIN
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcUserPin       : 用户PIN
* Output         : ulUserPinRetry  : 用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_VerifyAppPIN(QHANDLE hStoreHandle, char *pcAppName, char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_ChangeAppUserPin
* Description    : 修改用户PIN
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcOldPin        : 旧PIN
*                : pcNewPin        : 新PIN
*                : pulPinRetry     : PIN重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ChangeAppUserPin(QHANDLE hStoreHandle, char *pcAppName,
																char *pcOldPin, char *pcNewPin, unsigned long *pulPinRetry);

/*******************************************************************************
* Function Name  : QCard_DefaultPasswdFlag
* Description    : 获取默认PIN码标志位 0-未修改过默认PIN码 1-修改过默认PIN码
* Input          : QHANDLE hStoreHandle         : 安全存储区句柄
* Input          : char * pcAppName         : 应用名
* Output          : int * piDefaultPWDFlag         : 默认PIN码标志位
* Return         : 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_DefaultPasswdFlag(QHANDLE hStoreHandle, char *pcAppName, int *piDefaultPWDFlag);

/*******************************************************************************
* Function Name  : QCard_ExportPublicKey
* Description    : 导出公钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : ulPublicKeyType : 公钥类型, 1为签名公钥, 0为加密公钥
*                : pulPublicCertLen :输入时表示pcPublicCert缓存长度
*                : pcPublicCert     : 值为0时，pulPublicCertLen返回公钥长度
* OutPut         : pulPublicCertLen :输出时表示pcPublicCert公钥长度
*                : pcPublicCert     : 公钥文件
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ExportPublicKey(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned long ulPublicKeyType, 
									unsigned char *pcPublicCert, unsigned long *pulPublicCertLen);


/*******************************************************************************
* Function Name  : QCard_RSAPubKeyOperation
* Description    : 使用容器内RSA公钥进行运算
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : ulPublicKeyType : 公钥类型, 1为签名公钥, 0为加密公钥
*                : pcInput         : 待运算数据
*                : ulInput         : 带运算数据长度，长度应当小于密钥的模长-11
*                : pulOutPut       : 输入时表示pcOutput缓存长度
*                : pcOutput        : 值为0时，pulOutPut返回公钥长度
* OutPut         : pulOutPut       : 输出时表示pcOutput运算结果长度
*                : pcOutput        : 公钥文件
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_RSAPubKeyOperation(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned long ulPublicKeyType, 
									unsigned char *pcInput, unsigned long ulInput, unsigned char *pcOutput, unsigned long *pulOutPut);

/*******************************************************************************
* Function Name  : QCard_GenRSAPrivateKey
* Description    : 生成RSA私钥
* Input          : hStoreHandle      : 安全存储区句柄
*                : ulBitsLen         : 密钥模长,默认2048
*                : pcPrivateKey      : 值为0时，pulPrivateKey返回私钥长度
*                : pulPrivateKeyLen  : 输入时表示pcPublicCert缓存长度
* OutPut         : pcPrivateKey      : 输出时表示pulPrivateKeyLen长度
*                : pulPrivateKeyLen  : 私钥文件
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GenRSAPrivateKey(QHANDLE hStoreHandle, unsigned long ulBitsLen, unsigned char *pcPrivateKey, unsigned long *pulPrivateKeyLen);

/*******************************************************************************
* Function Name  : QCard_ImportRSAKeyPair
* Description    : 明文导入加密私钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcPrivateKey    : RSA私钥
*                : ulPrivateKeyLen : RSA私钥长度
*                : pcUserPin       : 应用用户PIN
* Output         : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ImportRSAKeyPair(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pcPrivateKey, unsigned long ulPrivateKeyLen, 
								  char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_ImportSymmKey
* Description    : 明文导入对称密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pucSymmKey      : 明文对称密钥
*                : ulSymmKeyLen    : 明文对称密钥长度
*                : pcUserPin       : 应用用户PIN
* Output         : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ImportSymmKey(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pucSymmKey, unsigned long ulSymmKeyLen, 
                                     char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_CustomImportSymmKey
* Description    : 基于SKF定制接口，向容器中导入对称密钥,用于保护后期会话密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pbWrapedData    : 对称密钥密文。当容器为ECC类型时，此参数ECCCIPHERBLOB密文数据，
*                                    当容器为RSA类型时，此参数为RSA公钥加密后的数据
*                : ulWrapedLen     : 对称密钥密文长度
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcUserPin       : 应用用户PIN
* Output         : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
*                : hKeyHandle      : 密钥句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_CustomImportSymmKey(QHANDLE hStoreHandle, unsigned char *pbWrapedData, unsigned long ulWrapedLen,
                                    char *pcAppName, char *pcContainerName, char *pcUserPin,
                                    unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_CustomImportSymmKey
* Description    : 基于SKF定制接口，向容器中导入对称密钥,用于保护后期会话密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pbWrapedData    : 对称密钥密文。当容器为ECC类型时，此参数ECCCIPHERBLOB密文数据，
*                                    当容器为RSA类型时，此参数为RSA公钥加密后的数据
*                : ulWrapedLen     : 对称密钥密文长度
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcUserPin       : 应用用户PIN
* Output         : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
*                : hKeyHandle      : 密钥句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_CustomImportSessionKey(QHANDLE hStoreHandle, unsigned char *pbWrapedData, unsigned long ulWrapedLen,
                                    unsigned long  ulSysAlgId, unsigned long ulAlgId,
                                    char *pcAppName, char *pcContainerName, char *pcUserPin,
                                    unsigned long *pulUserPinRetry, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_ContainPublicKeyEnctryptData
* Description    : 使用容器加密公钥进行加密数据
* Input          : hStoreHandle    : 安全存储区句柄
*                : pucData         : 对称密钥密文。当容器为ECC类型时，此参数ECCCIPHERBLOB密文数据，
*                                    当容器为RSA类型时，此参数为RSA公钥加密后的数据
*                : ulDataLen       : 对称密钥密文长度
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcUserPin       : 应用用户PIN
* Output         : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
*                : hKeyHandle      : 密钥句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ContainPublicKeyEnctryptData(QHANDLE hStoreHandle, unsigned char *pucData, unsigned long ulDataLen,
                                    char *pcAppName, char *pcContainerName, char *pcUserPin,
                                    unsigned long *pulUserPinRetry, unsigned char *pbWrapedData, unsigned long *pulWrapedLen);


/*******************************************************************************
* Function Name  : QCard_CustomImportSessionKey
* Description    : 基于SKF定制接口，向容器中导入对称密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 加密密钥
*                : ulAlgId         : 加密算法标识
*                : ulWrapedLen     : 会话密钥密文长度
*                : pcUserPin       : 应用用户PIN
* Output         : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
*                : hKeyHandle      : 密钥句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
/*
QCARD_API int QCard_CustomImportSessionKey(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, ULONG ulSysAlgId,
                                 ULONG ulAlgId, BYTE *pbWrapedData, ULONG ulWrapedLen, 
                                 char *pcUserPin, unsigned long *pulUserPinRetry, KEYHANDLE hKeyHandle);*/
                                 

/*******************************************************************************
* Function Name  : QCard_EncImportRSAKeyPair
* Description    : 密文导入加密私钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcPrivateKey    : 使用对称密钥保护的RSA私钥
*                : ulPrivateKeyLen : RSA私钥长度
*                : ulSymAlgId      : 对称密钥算法标识
*                : pucWrappedKey   : 使用签名公钥保护的对称密钥
*                : ulWrappedKeyLen : 对称密钥长度
*                : pcUserPin       : 应用用户PIN
* Output         : pulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_EncImportRSAKeyPair(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pcEncPrivateKey,unsigned long ulEncPrivateKeyLen,
				unsigned long ulSymAlgId, unsigned char *pucWrappedKey, unsigned long ulWrappedKeyLen, char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_ImportCertificate
* Description    : 导入数字证书
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
*                : ulCertType       : 数字证书类型 1表示签名证书 0表示加密证书
*                : pcCert           : 数字证书
*                : ulCertLen        : 数字证书长度
*                : pcUserPin        : 应用用户PIN
* Output         : pulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ImportCertificate(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned long ulCertType, 
									  unsigned char *pcCert,unsigned long ulCertLen, char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_ExportCertificate
* Description    : 导出数字证书
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : ulCertType      : 数字证书类型 0:加密证书 1:签名证书 2加密证书
*                : pcCert          : 数字证书缓存，当为0时获取数字证书长度
*                : pulCertLen       :数字证书缓存长度
* OutPut         : pcCert          : 数字证书
*                : pulCertLen       :数字证书长度
*                : pulTimeOut       :数字证书过期位, 0 未过期; 1已过期;
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ExportCertificate(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned long ulCertType,
									  unsigned char *pcCert,unsigned long *pulCertLen, unsigned long *pulTimeOut);

/*******************************************************************************
* Function Name  : QCard_ExportCertificateRequest
* Description    : 导出证书请求
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : ulCertType      : 数字证书类型 1表示签名证书 0表示加密证书
*                : DN              : 证书信息
*                : pcRequest       : 证书请求缓存，当为0时获取数字证书长度
*                : pulRequsttLen   : 证书请求缓存长度
*                : pcUserPin       : 用户PIN
* OutPut         : pcRequest       : 证书请求
*                : pulRequsttLen   : 证书请求长度
*                : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ExportCertificateRequest(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned long ulCertType, QCard_DN DN,
											 unsigned char *pcRequest, unsigned long *pulRequsttLen, char *pcUserPin, unsigned long *ulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_RSASignSHA256DataAdmin
* Description    : RSA-SHA256签名数据
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcData          : 待签名数据
*                : ulDataLen       : 待签名数据长度
*                : pcAdminPin       : 管理员PIN
*                : pucSignature    : 签名结果数据存储缓存指针,值为0时获取签名结果数据长度
*                : pulSignatureLen : 签名结果数据存储缓存长度
* OutPut         : pulSignatureLen : 签名结果数据长度
*                : ulAdminPinRetry  : 应用管理员PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_RSASignSHA256DataAdmin(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pcData, unsigned long ulDataLen,
																			char *pcAdminPin, unsigned long *ulAdminPinRetry, char *pcSignature, unsigned long *pulSignatureLen);

/*******************************************************************************
* Function Name  : QCard_RSASignSHA256Data
* Description    : RSA-SHA256签名数据
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcData          : 待签名数据
*                : ulDataLen       : 待签名数据长度
*                : pcUserPin       : 用户PIN
*                : pcSignature    :  签名结果数据存储缓存指针,值为0时获取签名结果数据长度
*                : pulSignatureLen : 签名结果数据存储缓存长度
* OutPut         : pulSignatureLen : 签名结果数据长度
*                : pcSignature     : 签名结果
*                : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_RSASignSHA256Data(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pcData, unsigned long ulDataLen,
									  char *pcUserPin, unsigned long *ulUserPinRetry, char *pcSignature, unsigned long *pulSignatureLen);

/*******************************************************************************
* Function Name  : QCard_SM2SignSM3DataAdmin
* Description    : sm2-sm3签名数据
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcData          : 待签名数据
*                : ulDataLen       : 待签名数据长度
*                : pcAdminPin       : 管理员PIN
*                : pucSignature    : 签名结果数据存储缓存指针,值为0时获取签名结果数据长度
*                : pulSignatureLen : 签名结果数据存储缓存长度
* OutPut         : pulSignatureLen : 签名结果数据长度
*                : ulAdminPinRetry  : 应用管理员PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_SM2SignSM3DataAdmin(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pcData, unsigned long ulDataLen,
																		char *pcAdminPin, unsigned long *ulAdminPinRetry, char *pcSignature, unsigned long *pulSignatureLen);

/*******************************************************************************
* Function Name  : QCard_SM2SignSM3Data
* Description    : sm2-sm3签名数据
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcData          : 待签名数据
*                : ulDataLen       : 待签名数据长度
*                : pcUserPin       : 用户PIN
*                : pucSignature    : 签名结果数据存储缓存指针,值为0时获取签名结果数据长度
*                : pulSignatureLen : 签名结果数据存储缓存长度
* OutPut         : pulSignatureLen : 签名结果数据长度
*                : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_SM2SignSM3Data(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pcData, unsigned long ulDataLen,
                                      char *pcUserPin, unsigned long *ulUserPinRetry, char *pcSignature, unsigned long *pulSignatureLen);

/*******************************************************************************
* Function Name  : QCard_VerifyPIN
* Description    : 校验PIN
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcAppName        : 应用名称
*                : pcUserPin        : 应用用户PIN
* Output         : pulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_VerifyPIN(QHANDLE hStoreHandle, char *pcAppName, char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_GenRandom
* Description    : 获取随机数
* Input          : hStoreHandle     : 安全存储区句柄
*                : pucRandom        : 缓存指针
*                : ulRandom         : 缓存长度，随机数长度
* Output         : pucRandom        : 随机数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GenRandom(QHANDLE hStoreHandle, unsigned char* pucRandom, unsigned long ulRandom);

/*******************************************************************************
* Function Name  : QCard_WriteDoccument
* Description    : 写文件,需要QCard_LoginStore和QCard_InitResource成功后方可运行
* Input          : hStoreHandle      : 安全存储区句柄
*                : pcDoccumentName   : 文件名称
*                : pucData           : 文件内容
*                : ulDataLen         : 文件长度
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_WriteDocument(QHANDLE hStoreHandle, char *pcDocumentName, unsigned char* pucData, unsigned long ulDataLen);

/*******************************************************************************
* Function Name  : QCard_ReadDoccument
* Description    : 读文件,需要QCard_LoginStore和QCard_InitResource成功后方可运行
* Input          : hStoreHandle      : 安全存储区句柄
*                : pcDoccumentName   : 文件名称
*                : pucData           : 值为0是，ulDataLen返回文件长度
*                : pulDataLen        : pucData缓存长度
* Output         : pucData           : 文件内容
*                : pulDataLen        : 文件长度
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ReadDoccument(QHANDLE hStoreHandle, char *pcDocumentName, unsigned char* pucData, unsigned long *pulDataLen);

/*******************************************************************************
* Function Name  : QCard_DelectDoccument
* Description    : 删除文件,需要QCard_LoginStore和QCard_InitResource成功后方可运行
* Input          : hStoreHandle      : 安全存储区句柄
*                : pcDoccumentName   : 文件名称
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_DelectDoccument(QHANDLE hStoreHandle, char *pcDocumentName);

/*******************************************************************************
* Function Name  : QCard_ExportCertificateVaildTime
* Description    : 导出数字证书有效时间
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : ulCertType      : 数字证书类型 1表示签名证书 0表示加密证书
* OutPut         : pulTimeStart    : 数字证书有效期始
*                : pulTimeEnd       :数字证书有效期止
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ExportCertificateVaildTime(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName,
											   unsigned long ulCertType, unsigned long *pulTimeStart, unsigned long *pulTimeEnd);

/*******************************************************************************
* Function Name  : QCard_GetContianerType
* Description    : 查看容器类型
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
* Output         : pulContainerType: 容器类型 0：未定 1：RSA容器 2：ECC容器
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetContianerType(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned long *pulContainerType);

/*******************************************************************************
* Function Name  : QCard_GenECCSignKeyPair
* Description    : 生成ecc签名密钥对
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcUserPin       : 用户PIN
* Output         : ulUserPinRetry  : 用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GenECCSignKeyPair(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_GenECCEncKey
* Description    : 生成ECC加密密钥对
* Input          : hStoreHandle      : 安全存储区句柄
*                : pcPrivateKey      : 值为0时，pulPrivateKey返回私钥长度
*                : pulPrivateKeyLen  : 输入时表示pcPublicCert缓存长度
* OutPut         : pcPrivateKey      : 输出时表示pulPrivateKeyLen长度
*                : pulPrivateKeyLen  : 私钥文件
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GenECCEncKey(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_SkfDevLock
* Description    : SKF互斥锁加锁
* Input          : QHANDLE hStoreHandle         : 安全存储区句柄
* Input          : unsigned long ulTimeOut         : 超时时间(毫秒)，0xFFFFFFFF-无限等待
* Return         : QCARD_API int 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_SkfDevLock(QHANDLE hStoreHandle, unsigned long ulTimeOut);

/*******************************************************************************
* Function Name  : QCard_SkfDevUnLock
* Description    : SKF互斥锁解锁
* Input          : QHANDLE hStoreHandle         : 安全存储区句柄
* Return         : QCARD_API int 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_SkfDevUnLock(QHANDLE hStoreHandle);

#ifdef  __cplusplus
}
#endif  /* #ifdef  __cplusplus */

#endif