/*************************************************
 Copyright (C), 2009 Qasky Co., Ltd
 File name: qcard.h
 Author: Jianbin Wang    Version:  1.0.0      Date: 2019年12月23日
 Description: : 量子移动存储设备应用接口
 *************************************************/

#ifndef QCARD_H
#define QCARD_H
#include <qcard_skf.h>
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
* Function Name  : QCard_EnumStoreHandle
* Description    : 枚举安全存储区句柄
* Input          : phStoreHandle : 值为0
* Output         : phStoreHandle : 安全存储区句柄列表,使用QCard_QHANDLE_Free释放
* Return         : 成功返回安全存储区个数, 其它返回错误值
*******************************************************************************/
QCARD_API int QCard_EnumStoreHandle(QHANDLES *phStoreHandles,char *packetname,char *fixpacketname);

/*******************************************************************************
* Function Name  : QCard_EnumSpecifiedTypeStoreHandle
* Description    : 枚举指定类型的安全存储区句柄
* Input          : phStoreHandle : 值为0
*                : ulOperateDeviceType : 操作设备类型,
*                : 如果值为 QCARD_REMOTE_QUD|QCARD_REMOTE_QTF|QCARD_REMOTE_QUP|QCARD_REMOTE_QHID,则QCard_EnumStoreHandle函数将枚举到四种设备类型的句柄
*                : ulOpearteType       : 操作类型，
* Output         : phStoreHandle : 安全存储区句柄列表,使用QCard_QHANDLE_Free释放
* Return         : 成功返回安全存储区个数, 其它返回错误值
*******************************************************************************/
QCARD_API int QCard_EnumSpecifiedTypeStoreHandle(QHANDLES *phStoreHandles, unsigned long ulOpearteType);

/*******************************************************************************
* Function Name  : QCard_FreeStoreHandle
* Description    : 释放安全存储区句柄
* Input          : phStoreHandle : QCard_EnumStore枚举成功后的安全存储区句柄
*******************************************************************************/
QCARD_API void QCard_FreeStoreHandle(QHANDLES phStoreHandles);

/*******************************************************************************
* Function Name  : QCard_GetDeviceType
* Description    : 获取设备类型
* Input          : hStoreHandle   : 安全存储区句柄
* Output         : ulDeviceType  : 设备类型
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetDeviceType(QHANDLE hStoreHandle, unsigned long *ulDeviceType);

/*******************************************************************************
* Function Name  : QCard_GetStoreId
* Description    : 获取安全存储区序列号
* Input          : hStoreHandle   : 安全存储区句柄
*                : pcStoreId      : 缓存区指针,缓存区大小>=32字节
* Output         : pcStoreId      : 设备序列号
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetStoreId(QHANDLE hStoreHandle, char *pcStoreId);

/*******************************************************************************
* Function Name  : QCard_WaitForDevEvent
* Description    : 监听设备插拔事件
* Input          : pcDriverName     : 驱动名称缓存
*                : pulDevNameLen    : 驱动名称缓存长度
* Output         : pcDriverName     : 驱动名称
*                : pulDevNameLen    : 驱动名称长度
*                : pulEvent         : 插拔事件 1表示插入 2表示拔出
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_WaitForDevEvent(char *pcDriverName, unsigned long *pulDevNameLen, unsigned long *pulEvent);

/*******************************************************************************
* Function Name  : QCard_CancelWaitForDevEvent
* Description    : 取消监听设备插拔事件
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_CancelWaitForDevEvent();

/*******************************************************************************
* Function Name  : QCard_GetDriverName
* Description    : 获取驱动盘符
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcDriverName     : 驱动名称缓存
*                : pulDevNameLen    : 驱动名称缓存长度
* Output         : pcDriverName     : 驱动名称
*                : pulDevNameLen    : 驱动名称长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetDriverName(QHANDLE hStoreHandle, char *pcDriverName, unsigned long *pulDevNameLen);

/*******************************************************************************
* Function Name  : QCard_Login
* Description    : 登录安全存储区
* Input          : hStoreHandle : 安全存储区句柄
* Output         : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_Login(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_Logout
* Description    : 退出安全存储区
* Input          : hStoreHandle : 安全存储区句柄
* Output         : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_Logout(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_SetLog
* Description    : 设置日志输出
* Input          : cb      : 日志输出回调函数
*                : lverror : error日志等级设置
*                : lvwarn  : warn日志等级设置
*                : lvinfo  : info日志等级设置
*                : lvdebug : debug日志等级设置
*                : lvtrace : trace日志等级设置
* Return         : 返回值为写入密钥的长度; 其它值为错误码;
*******************************************************************************/
QCARD_API void QCard_SetLog(void (*cb)(int level, char * msg), int lverror, int lvwarn, int lvinfo,  int lvdebug, int lvtrace);

/*******************************************************************************
* Function Name  : QCard_SetNetworkInform
* Description    : 设置网络通知
* Input          : cb  : 日志输出回调函数
*                : iNetworkInfo : 值为0时表示准备发起网络请求 值为1时表示网络请求结束
* Return         : 返回值为写入密钥的长度; 其它值为错误码;
*******************************************************************************/
QCARD_API void QCard_SetNetworkInform(void(*cb)(int iNetworkInfo));

/*******************************************************************************
* Function Name  : QCard_SetLogExport
* Description    : 设置日志输出
* Input          : cb      : 日志输出回调函数
* Return         : 返回值为写入密钥的长度; 其它值为错误码;
*******************************************************************************/
QCARD_API void QCard_SetLogExport(void(*cb)(QCard_LogLevel level, char * msg));

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
									  unsigned char *pucCert,unsigned long *pulCertLen, unsigned long *pulTimeOut);

/*******************************************************************************
* Function Name  : QCard_RSASignData
* Description    : RSA签名
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcData          : 待签名数据
*                : ulDataLen       : 待签名数据长度
*                : pcUserPin       : 用户PIN
*                : pucSignature    : 签名结果数据存储缓存指针,值为0时获取签名结果数据长度
*                : pulSignatureLen : 签名结果数据存储缓存长度
* OutPut         : pulSignatureLen : 签名结果数据长度
*                : pucSignature    : 签名结果
*                : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_RSASignData(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin, unsigned long *pulUserPinRetry,
                                       unsigned char *pucData, unsigned long ulDataLen, unsigned char *pucSignature, unsigned long *pulSignatureLen);

/*******************************************************************************
* Function Name  : QCard_SM2SignSM3Data
* Description    : sm2sign-with-sm3签名数据, 该接口内部进行数据预处理
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
* Function Name  : QCard_InitResource
* Description    : 初始化资源
* Input          : hStoreHandle : 登录成功后的安全存储区句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_InitResource(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_DestoryResource
* Description    : 销毁资源
* Input          : hStoreHandle :  初始化资源成功后的安全存储区句柄
*******************************************************************************/
QCARD_API void QCard_DestoryResource(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_UpdateResource
* Description    : 更新资源,销毁资源前调用一次更新资源函数
* Input          : hStoreHandle : 登录成功后的安全存储区句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_UpdateResource(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_ReadAuthSynFlag
* Description    : 获取认证同步码
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcOtherStoreId  : 另一端设备序列号
*                : pcAppName       : 应用名称
*                ：pcContainerName : 容器名称
*                : pcPin           : 用户PIN
* Output         : pcFlag          : 认证同步码,当入参值为0时，pulFlagLen返回认证同步码长度，
*                : pulFlagLen      : 认证同步码长度，输入时为pcFlag缓存长度，输出时为认证同步码长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ReadAuthSynFlag(QHANDLE hStoreHandle, char *pcOtherStoreId, char *pcAppName, char *pcContainerName,
                                     char *pcPin, char *pcFlag, unsigned long *pulFlagLen);

/*******************************************************************************
* Function Name  : QCard_AuthSynFlag
* Description    : 认证同步
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcOtherStoreId  : 另一端设备序列号
*                : pcAppName       : 应用名称
*                ：pcContainerName : 容器名称
*                : pcPin           : 用户PIN
*                : pcFlag          : 认证同步码
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_AuthSynFlag(QHANDLE hStoreHandle, char *pcOtherStoreId, char *pcAppName, char *pcContainerName,
                                     char *pcPin, char *pcFlag);
                                    
/*******************************************************************************
* Function Name  : QCard_AuthSynFlagKeyInit
* Description    : 获取密钥句柄, 通过认证同步码获取。（CTC模式）
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcOtherStoreId   : 对端设备序列号
*                : pcFlag           : 认证同步码
*                : ulAlgId          :  算法标示
*                : KeyParam         : 分组密钥算法相关参数
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
*                : pcPin            : 用户PIN
*                : ulSafeTactics    : 安全策略
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*****************************************************/
QCARD_API int QCard_AuthSynFlagKeyInit (QHANDLE hStoreHandle, char *pcOtherStoreId, char *pcFlag, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, 
                                    char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulSafeTactics, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_GetAuthSynBlokcKey
* Description    : 通过认证同步码获取协商出的块密钥。（CTC模式）
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcOtherStoreId   : 对端设备序列号
*                : pcFlag           : 认证同步码
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
*                : pcPin            : 用户PIN
*                : ulSafeTactics    : 安全策略
* Output         : pucBlockKey      : 密钥块
*                : puikeyLen        : 密钥块大小
* Return         : 成功返回0; 其它值为错误码;
*****************************************************/
QCARD_API int QCard_GetAuthSynBlokcKeyId(QHANDLE hStoreHandle, char *pcOtherStoreId, char *pcFlag, 
    char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulSafeTactics, unsigned char **pucBlockKey, unsigned int *puikeyLen);

/*******************************************************************************
* Function Name  : QCard_GetClientBlockKey
* Description    : 通过在线与服务端协商获取密钥块, （CTS模式）
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcCheckCode      : 校验码
*                : pcFlag           : 协商信息
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
*                : pcPin            : 用户PIN
*                : ulSafeTactics    : 安全策略
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*****************************************************/
QCARD_API int QCard_GetClientBlockKey(QHANDLE hStoreHandle, char *pcCheckCode, char *pcFlag, 
    char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulSafeTactics, unsigned char **pucBlockKey, unsigned int *puikeyLen);


/*******************************************************************************
* Function Name  : QCard_ClientKeyInit
* Description    : 获取密钥句柄, 通过在线与服务端协商获取密钥, 当密钥不足或异常时会自动充值密钥（CTS模式）
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcCheckCode      : 校验码
*                : pcFlag           : 协商信息
*                : ulAlgId          : 算法标示
*                : KeyParam         : 分组密钥算法相关参数
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
*                : pcPin            : 用户PIN
*                : ulSafeTactics    : 安全策略
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*****************************************************/
QCARD_API int QCard_ClientKeyInit (QHANDLE hStoreHandle, char *pcCheckCode, char *pcFlag, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, 
                                    char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulSafeTactics, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_LocalKeyInit
* Description    : 获取密钥句柄,通过本地协商获取密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : ulAlgId         : 算法标示
*                : KeyParam        : 分组密钥算法相关参数
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcUserPin       : 应用用户PIN码
*                : ulSafeTactics   : 安全策略
* Output         : phKeyHandle     : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_LocalKeyInit (QHANDLE hStoreHandle, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam,
                                 char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulSafeTactics, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_ConsultKeyInit
* Description    : 获取协商密钥句柄,
* Input          : hStoreHandle     : 安全存储区句柄
*                : pucWrapedData    : RSA公钥加密后的数据
*                : ulWrapedDataLen  : RSA公钥加密后的数据长度
*                : ulAlgId          : 算法标示
*                : KeyParam         : 分组密钥算法相关参数
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
*                : pcPin            : 用户PIN
*                : ulSafeTactics    : 安全策略
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*****************************************************/
QCARD_API int QCard_ConsultKeyInit(QHANDLE hStoreHandle, unsigned char *pucWrapedData, unsigned long ulWrapedDataLen, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, 
                                    char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulSafeTactics, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_ExternalKeyInit
* Description    : 获取密钥句柄
* Input          : hStoreHandle  : 安全存储区句柄
*                : pucKey        : 会话密钥
*                : ulKeyLen      : 会话密钥长度
*                : ulAlgId       : 算法标示
*                : KeyParam      : 分组密钥算法相关参数
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ExternalKeyInit(QHANDLE hStoreHandle, unsigned char *pucKey, unsigned long ulKeyLen, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_KeyFinal
* Description    : 释放密钥句柄
* Input          : hStoreHandle : 安全存储区句柄
*                : hKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API void QCard_KeyFinal(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle);

/*******************************************************************************
* Function Name  : QCard_GetQKey
* Description    : 获取密钥
* Input          : hStoreHandle : 安全存储区句柄
*                : hKeyHandle   : 密钥句柄
* Output         : pucKey       : 密钥, 当值为0时，puiKeyLen返回密钥长度，
*                : puiKeyLen    ：密钥长度，当值为0时，puiKeyLen返回密钥长度，当值不为0时，puiKeyLen代表pucKey缓存长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ExportKey(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle, unsigned char *pucKey, unsigned long *pulKeyLen);

/*******************************************************************************
* Function Name  : QCard_Encrypt
* Description    : 数据加密
* Input          : hStoreHandle     : 安全存储区句柄
*                : hKeyHandle       : 密钥句柄
*                : pucData          : 待加密数据
*                : ulDataLen        : 待加密数据长度,必须是16字节的整数倍
*                : pulEncryptedLen  : 输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Output         : pucEncryptedData : 加密后的数据缓冲区指针,可以为NULL,用于获取加密后的数据长度
*                : ulEncryptedLen   : 输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_Encrypt(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle, unsigned char *pucData, unsigned long ulDataLen, unsigned char *pucEncryptedData, unsigned long *pulEncryptedLen);

/*******************************************************************************
* Function Name  : QCard_Decrypt
* Description    : 数据解密
* Input          : hStoreHandle     : 安全存储区句柄
*                : hKeyHandle       : 密钥句柄
*                : pucEncryptedData : 待解密数据,必须是16字节的整数倍
*                : ulEncryptedLen   : 输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Output         : pucData          : 指向解密后的数据缓冲区指针,当为NULL时可获得解密后的数据长度
*                : pulEncryptedLen  : 输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_Decrypt(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle, unsigned char *pucEncryptedData, unsigned long ulEncryptedLen, unsigned char *pucData, unsigned long *pulDataLen);

/*******************************************************************************
* Function Name  : QCard_OnlineChargingKey
* Description    : 在线充注密钥，运行成功则密钥量不小于ulMinKeyQuantity值
* Input          : hStoreHandle     : 安全存储区句柄
*                : pucAppName       : 应用名称
*                : pucContainerName : 容器名称
*                : pcPin            : 密钥
*                : ulMinKeyQuantity : 最低密钥量，低于该值则启动在线充注密钥
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_OnlineChargingKey(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulMinKeyQuantity);

/*******************************************************************************
* Function Name  : QCard_ProxyOnlineChargingKey
* Description    : 在线充注密钥，运行成功则密钥量不小于ulMinKeyQuantity值
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcProxyAddr      : 代理地址，格式为IP:PORT
*                : pucAppName       : 应用名称
*                : pucContainerName : 容器名称
*                : pcPin            : 密钥
*                : ulMinKeyQuantity : 最低密钥量，低于该值则启动在线充注密钥
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ProxyOnlineChargingKey(QHANDLE hStoreHandle, char *pcProxyAddr, char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulMinKeyQuantity);

/*******************************************************************************
* Function Name  : QCard_GetSysTemId
* Description    : 获取系统id
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
* Output         : pcSystemId       : 系统ID
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetSysTemId(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcSystemId);

/*******************************************************************************
* Function Name  : QCard_RequestCTSKey
* Description    : 协商密钥CToS模式
* Input          : pcAddr       : 服务端地址
*                : pcStoreId    : 设备序列号
*                : pcSystemId   : 系统序列号
* OutPut         ; pucKey       : 协商出的密钥
*                : pulKeyLen    : 密钥长度
*                : pcFlag       : 协商数据
*                : pcCheckCode  : 协商数据校验码
*******************************************************************************/
QCARD_API int QCard_RequestCTSKey(char *pcAddr, char *pcStoreId, char *pcSystemId, unsigned char **pucKey,
								  unsigned long *pulKeyLen, char **pcFlag, char *pcCheckCode);

/*******************************************************************************
* Function Name  : QCard_RequestCTSKeyByApp
* Description    : 协商密钥CToS模式
* Input          : pcAddr       : 服务端地址
*                : pcStoreId    : 设备序列号
*                : pcAppName    : 应用名
*                : pcConName    : 容器名
*                : ulKeyLen     : 软加密算法密钥长度
* OutPut         ; pucKey       : 协商出的密钥(16字节)
*                : pucSoftKey   : 软加密算法密钥
*                : pcFlag       : 协商数据
*                : pcCheckCode  : 协商数据校验码
*******************************************************************************/
QCARD_API int QCard_RequestCTSKeyByApp(char *pcAddr, char *pcStoreId, char *pcAppName, char *pcConName, unsigned long ulSoftKeyLen, 
                        unsigned char *pucKey, unsigned char *pucSoftKey, char **pcFlag, char *pcCheckCode);

/*******************************************************************************
* Function Name  : QCard_RequestCTSKeyByAppSetTimeOut
* Description    : 设置超时时间
* Input          :  TimeOut      : 接口超时时间
* OutPut         ; 
*******************************************************************************/
QCARD_API int QCard_RequestCTSKeyByAppSetTimeOut(unsigned long TimeOut);


/*******************************************************************************
* Function Name  : QCard_CreateOnlineBizKey
* Description    : 创建在线业务密钥
* Input          : pcAddr       : 服务端地址
*                : secretSize    : 在线业务密钥的大小范围16~64,必须是16的倍数
*                : validityDate    : 在线业务密钥的失效时间,日期格式（yyyy-MM-dd hh:mm:ss）
*                : systemId    : 系统ID
*                : serverId    : 服务端鉴权ID
*                : visitKeyBase64    : 访问密钥（加密后做base64编码）
*                : protectKey    : 保护密钥
* OutPut  : secretId       : 密钥ID
*******************************************************************************/
QCARD_API int QCard_CreateOnlineBizKey(char *pcAddr, int secretSize, char *validityDate,
    char *systemId, char *serverId, char *visitKeyBase64, const unsigned char *protectKey,
    char *secretId);

/*******************************************************************************
* Function Name  : QCard_ServerRequestOnlineBizKey
* Description    : 服务端协商在线业务密钥
* Input          : pcAddr       : 服务端地址
*                : systemId    : 系统ID（C2S协商）
*                : secretId    : 密钥ID
*                : serverId    : 服务端鉴权ID
*                : visitKeyBase64    : 访问密钥（加密后做base64编码）
*                : protectKey    : 保护密钥
* OutPut  : secretKey       : 业务密钥
*                : secretKeyLen  : 业务密钥长度(字节)
*******************************************************************************/
QCARD_API int QCard_ServerRequestOnlineBizKey(char *pcAddr, char *systemId,
    char *secretId, char *serverId, char *visitKeyBase64, const unsigned char *protectKey,
    unsigned char **secretKey, unsigned long *secretKeyLen);

/*******************************************************************************
* Function Name  : QCard_ClientRequestOnlineBizKey
* Description    : 客户端协商在线业务密钥
* Input          : pcAddr       : 服务端地址
*                : pcStoreId    : 设备序列号
*                : systemId    : 系统ID（C2S协商）
*                : secretId    : 密钥ID
*                : serverId    : 服务端鉴权ID
*                : visitKeyBase64    : 访问密钥（加密后做base64编码）
*                : protectKey    : 保护密钥
* OutPut  : pcFlag       : 协商数据
*                : pcCheckCode  : 协商数据校验码
*******************************************************************************/
QCARD_API int QCard_ClientRequestOnlineBizKey(char *pcAddr, char *pcStoreId, char *systemId,
    char *secretId, char *serverId, char *visitKeyBase64, const unsigned char *protectKey,
    char **pcFlag, char *pcCheckCode);

/*******************************************************************************
* Function Name  : QCard_cleanNegotiateOnlineBizKey
* Description    : 清除在线业务密钥
* Input          : pcAddr       : 服务端地址
*                : systemId    : 系统ID（C2S协商）
*                : secretId    : 密钥ID
*                : serverId    : 服务端鉴权ID
*                : visitKeyBase64    : 访问密钥（加密后做base64编码）
*                : protectKey    : 保护密钥
* OutPut  : 
*******************************************************************************/
QCARD_API int QCard_cleanNegotiateOnlineBizKey(char *pcAddr, char *systemId,
    char *secretId, char *serverId, char *visitKeyBase64, const unsigned char *protectKey);


/*******************************************************************************
* Function Name  : QCard_QueryKey
* Description    : 查询密钥量
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcStoreId        : 设备序列号
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
* OutPut         : pulKeyTotalLen   : 密钥总量
*                : pulKeyUsedLen    : 密钥已使用量
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_QueryKey(QHANDLE hStoreHandle, char *pcStoreId, char *pcAppName, char *pcContainerName, unsigned long *pulKeyTotalLen, unsigned long *pulKeyUsedLen);

/*******************************************************************************
* Function Name  : QCard_QueryLargeKey
* Description    : 查询密钥量,适用于查询4GB以上的密钥量
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcStoreId        : 设备序列号
*                : pcAppName        : 应用名称
*                : pcContainerName  : 容器名称
* OutPut         : pulKeyTotalLen   : 密钥总量
*                : pulKeyUsedLen    : 密钥已使用量
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_QueryLargeKey(QHANDLE hStoreHandle, char *pcStoreId, char *pcAppName, char *pcContainerName, unsigned long long *pullKeyTotalLen, unsigned long long *pullKeyUsedLen);

/*******************************************************************************
* Function Name  : QCard_GetNegotiateMode
* Description    : 获取协商模式
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcSystemId       : 系统名称  
* Output         : puiNegotiateMode : 输出值为0时,代表目标协商模式未确定
*                :                   :输出值为2时,代表目标协商模式为CTS模式（点对服务器）;
*                :                   :输出值为1时,代表目标协商模式为CTC模式 (点对点);
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetNegotiateMode(QHANDLE hStoreHandle, char *pcSystemId, unsigned int* puiNegotiateMode);

/*******************************************************************************
* Function Name  : QCard_GetNegotiateModeApp
* Description    : 获取协商模式
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcAppName        : 应用名称
*                : pcConName        : 容器名称
* Output         : puiNegotiateMode : 输出值为0时,代表目标协商模式未确定
*                :                   :输出值为2时,代表目标协商模式为CTS模式（点对服务器）;
*                :                   :输出值为1时,代表目标协商模式为CTC模式 (点对点);
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetNegotiateModeApp(QHANDLE hStoreHandle, char *pcAppName, char *pcConName, unsigned int* puiNegotiateMode);

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
* Function Name  : QCard_WriteAudit
* Description    : 写入审计日志
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcOperateType : 操作类型
*                : pcOperateObj : 操作对象
*                : ulResultCode : 操作结果
*                : pcDiscription : 操作描述或错误原因
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_WriteAudit(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcOperateType, char *pcOperateObj, unsigned long ulResultCode, char *pcDiscription);

/*******************************************************************************
* Function Name  : QCard_VerifyFingerPrint
* Description    : 验证终端
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名
*                : pcContainerName : 容器名
*                : char * pcUserPin                   : 用户pin码
* Output         : piVerifyResult  : 验证结果 0-验证不通过 1-验证通过
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_VerifyFingerPrint(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName,
															char *pcUserPin, int *piVerifyResult);

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
* Function Name  : QCard_StartSyncAuditThread
* Description    : 开启上传审计日志到服务端线程
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName    : 应用名
*                : pcContainerName : 容器名
*                : pcUserPin       : 用户pin码
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_StartSyncAuditThread(QHANDLE *phStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin);

/*******************************************************************************
* Function Name  : QCard_StopSyncAuditThread
* Description    : 停止上传审计日志到服务端线程
* Input          : hStoreHandle    : 安全存储区句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_StopSyncAuditThread(QHANDLE *phStoreHandle);

/*******************************************************************************
* Function Name  : QCard_FileRwWrLock
* Description    : 文件写锁
* Input          : QHANDLE hStoreHandle         : 安全存储区句柄
* Return         : QCARD_API int 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_FileRwWrLock(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_FileRwUnLock
* Description    : 文件锁解锁
* Input          : QHANDLE hStoreHandle         : 安全存储区句柄
* Return         : QCARD_API int 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_FileRwUnLock(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_SetSSL
* Description    : 设置启用服务
* Input          : uiSetSSL     : 0 使用HTTP 非0 使用HTTPS
*******************************************************************************/
QCARD_API void QCard_SetSSL(unsigned int uiSetSSL);

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

/*******************************************************************************
* Function Name  : QCard_SetProxyServerAddress
* Description    : 设置启用代理服务
* Input          : uiSetProxy   : 0 不使用代理 非0 使用代理
*                : pcProxyServerAddress : 代理协议
*                : pcProxyServerUserPassword：代理用户密码，格式为"user:password", 如果不需要则传""。
*******************************************************************************/
QCARD_API void QCard_SetProxyServerAddress(unsigned int uiSetProxy, const char *pcProxyServerAddress, const char *pcProxyServerUserPassword);




/*******************************************************************************
* Function Name  : QCard_SM3DigestData
* Description    : SM3摘要数据
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcData          : 待摘要数据
*                : ulDataLen       : 待签名数据长度
*                : pcUserPin       : 用户PIN
*                : pucSignature    : 摘要结果数据存储缓存指针,值为0时获取摘要结果数据长度
*                : pulSignatureLen : 摘要结果数据存储缓存长度
* OutPut         : pulSignatureLen : 摘要结果数据长度
*                : ulUserPinRetry  : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_SM3DigestData(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, unsigned char *pcData, unsigned long ulDataLen,
                                      char *pcUserPin, unsigned long *ulUserPinRetry, char **digestdata, unsigned long *digestdataLen);



/*******************************************************************************
* Function Name  : QCard_SetLocalNetListenPar
* Description    : 设置本地网络监听的ip 端口
* Input          : localip    : 本地的ip
*                : localport    :本地的端口
*                : storgedevice : 0：无存储设备        1：有存储设备 
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
//int QCard_SetLocalNetListenPar(char* localip,unsigned int localport,int storgedevice);

/*******************************************************************************
* Function Name  : QCard_SetNetNegotiatePar
* Description    : 设置本地与对端通信时参数
* Input          : remoteip    : 对端的ip
*                : remoteport  :对端的端口
*                : negotiatemode:协商的模式
                 ：appnem       : 应用名
                 : conname.....: 容器名 
* Return         : 返回密钥池ID
*******************************************************************************/
//int QCard_SetNetNegotiatePar(char* remoteip,unsigned int remoteport,int negotiatemode,char* appname,char*conname,char*pin);

/*******************************************************************************
* Function Name  : QCard_StartNetNegotiateKeyService
* Description    : 开启网络协商密钥服务
* Input          : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
//int QCard_StartNetNegotiateKeyService();

/*******************************************************************************
* Function Name  : QCard_StartNetNegotiateKeyService
* Description    : 关闭网络协商密钥服务
* Input          : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
//int QCard_ClosetNetNegotiateKeyService();

/*******************************************************************************
* Function Name  : QCard_GetKeyFromKeyPool
* Description    : 从对应的密钥池ID中获取密钥
* Input          : poolid:密钥池ID
* Output         ：key:   获得的密钥
                 ：sequence：密钥对应的序列号
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
//int QCard_GetKeyFromKeyPool(int poolid,unsigned char* key,char* sequence);


/*******************************************************************************
* Function Name  : QCard_GetKeyFromKeyPool
* Description    : 从对应的密钥池ID中获取密钥
* Input          : poolid:密钥池ID
                 ：sequence：密钥对应的序列号
* Output         ：key:   获得的密钥
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
//int QCard_GetSquenceKeyFromKeyPool(int poolid,unsigned char* key,char* sequence);

/*******************************************************************************
* Function Name  : QCard_SetAppPath
* Description    : 设置包名
* Input          : packetname
*******************************************************************************/
//QCARD_API int QCard_SetAppPath(char *packetname);





#ifdef  __cplusplus
}
#endif  /* #ifdef  __cplusplus */

#endif  //QCARD_H
