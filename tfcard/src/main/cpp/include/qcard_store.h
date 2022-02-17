/*************************************************
 Copyright (C), 2009 Qasky Co., Ltd
 File name: qcard_store.h
 Author: Jianbin Wang    Version:  1.1.0      Date: 2019年5月20日
 Description: : 量子移动存储设备应用接口
 *************************************************/
#ifndef QCARD_STORE_H
#define QCARD_STORE_H
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
* Function Name  : QCard_EnumStoreHandle
* Description    : 枚举安全存储区句柄
* Input          : phStoreHandle : 值为0
* Output         : phStoreHandle : 安全存储区句柄列表,使用QCard_QHANDLE_Free释放
* Return         : 成功返回安全存储区个数, 其它返回错误值
*******************************************************************************/
QCARD_API int QCard_EnumStoreHandle(QHANDLES *phStoreHandles);

/*******************************************************************************
* Function Name  : QCard_FreeStoreHandle
* Description    : 释放安全存储区句柄
* Input          : phStoreHandle : QCard_EnumStore枚举成功后的安全存储区句柄
*******************************************************************************/
QCARD_API void QCard_FreeStoreHandle(QHANDLES phStoreHandles);

/*******************************************************************************
* Function Name  : QCard_GetSingleStoreHandle
* Description    : 获取单设备句柄
				 : 需要调用QCard_FreeSingleStoreHandle函数单独释放
* Input          : phStoreHandles : QCard_EnumStore枚举成功后的安全存储区句柄列表
*                : uiSite         : 提取单个句柄的数组位置
* OutPut         : hStoreHandle   : 设备句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetSingleStoreHandle(QHANDLES phStoreHandles, unsigned int uiSite, QHANDLE *hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_FreeSingleStoreHandle
* Description    : 释放单设备句柄
				 : 需要调用QCard_FreeSingleStoreHandle函数单独释放
* Input          : hStoreHandle : 设备句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_FreeSingleStoreHandle(QHANDLE hStoreHandle);

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
* Function Name  : QCard_GetCapcity
* Description    : 获取设备私密区容量
* Input          : hStoreHandle : 设备句柄
* Output         : puCapcity    : 容量
* Return         : 返回值为写入密钥的长度; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetCapcity(QHANDLE hStoreHandle, unsigned long *puCapcity);

/*******************************************************************************
* Function Name  : QCard_LoginStore
* Description    : 登录安全存储区
* Input          : hStoreHandle : 安全存储区句柄
*                : pcPin : 安全存储区Pin码
* Output         : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_LoginStore(QHANDLE hStoreHandle, char *pcPin);

/*******************************************************************************
* Function Name  : QCard_LogoutStore
* Description    : 退出安全存储区
* Input          : hStoreHandle : 安全存储区句柄
* Output         : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_LogoutStore(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_ChangePin
* Description    : 修改安全存储区Pin码
* Input          : hStoreHandle  : 安全存储区句柄
*                : pcOldPin  : 原Pin码
*                : pcNewPin  : 新Pin码
* Output         : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_ChangePin(QHANDLE hStoreHandle, char *pcOldPin, char *pcNewPin);

/*******************************************************************************
* Function Name  : QCard_FormatDevice
* Description    : 格式设备
* Input          : hStoreHandle : 安全存储区句柄
*                : iDeleteApp   : 值为0时 不删除设备应用, 其他时 删除设备应用
* Return         : 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_FormatDevice(QHANDLE hStoreHandle, int iDeleteApp);

/*******************************************************************************
* Function Name  : QCard_Init
* Description    : 格式化卡
* Input          : hStoreHandle : 安全存储区句柄    
* Return         : 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_Init(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_UserPartInit
* Description    : 格式化卡
* Input          : hStoreHandle : 安全存储区句柄    
* Return         : 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_UserPartInit(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_InitResource
* Description    : 初始化资源
* Input          : hStoreHandle : 登录成功后的安全存储区句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_InitResource(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_GetStoreId
* Description    : 获取安全存储区序列号
* Input          : hStoreHandle : 安全存储区句柄
*                : pcStoreId      : 缓存区指针,缓存区大小>=32字节
* Output         : pcStoreId      : 设备序列号
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetStoreId(QHANDLE hStoreHandle, char *pcStoreId);

/*******************************************************************************
* Function Name  : QCard_WiteStoreIdToCon
* Description    : 写入设备序列号对应的容器名称
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcStoreId       : 设备序列号内容
*                : pcAppName       : 应用名称,如果未使用容器加密则传入0
*                : pcContainerName : 容器名称,如果未使用容器加密则传入0
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_WiteStoreIdToCon(QHANDLE hStoreHandle, char *pcStoreId, char *pcAppName, char *pcContainerName);

/*******************************************************************************
* Function Name  : QCard_QueryStoreIdKey
* Description    : 查询密钥
* Input          : hStoreHandle   : 安全存储区句柄
*                : pcStoreId      : 设备序列号
* OutPut         : uiQKeyTotalLen : 密钥总量
*                : uiQKeyUsedLen  : 密钥已使用量
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_QueryStoreIdKey(QHANDLE hStoreHandle, char *pcStoreId, unsigned long *pulQKeyTotalLen, unsigned long *pulQKeyUsedLen);

/*******************************************************************************
* Function Name  : QCard_QueryStoreIdLargeKey
* Description    : 查询密钥
* Input          : hStoreHandle   : 安全存储区句柄
*                : pcStoreId      : 设备序列号
* OutPut         : uiQKeyTotalLen : 密钥总量
*                : uiQKeyUsedLen  : 密钥已使用量
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_QueryStoreIdLargeKey(QHANDLE hStoreHandle, char *pcStoreId, unsigned long long*pullQKeyTotalLen, unsigned long long*pullQKeyUsedLen);

/*******************************************************************************
* Function Name  : QCard_ReadStoreIdFlag
* Description    : 获取校验同步码
* Input          : hStoreHandle : 安全存储区句柄
*                : pucMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucFlag      : flag缓存, flag为4个字节的数据
* Output         : pucFlag      : 校验同步码
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ReadStoreIdFlag(QHANDLE hStoreHandle, char *pcStoreId, unsigned char *pucFlag);

/*******************************************************************************
* Function Name  : QCard_CheckSynStoreIdFlag
* Description    : 校验同步
* Input          : hStoreHandle : 安全存储区句柄
*                : pucMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucFlag      : flag缓存, flag为4个字节的数据
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_CheckSynStoreIdFlag(QHANDLE hStoreHandle, char *pcStoreId, unsigned char *pucFlag);

/*******************************************************************************
* Function Name  : QCard_GetMapStoreId
* Description    : 获取安全存储区序列号缩写
* Input          : hStoreHandle : 安全存储区句柄
*                : pcStoreId      : 设备序列号
*                : pucMapStoreId : 缓存区指针,缓存区大小>=3字节
* Output         : pcMapStoreId : 设备序列号缩写,大小为2个字符
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetMapStoreId(QHANDLE hStoreHandle, char *pcStoreId, unsigned char *pucMapStoreId);

/*******************************************************************************
* Function Name  : QCard_SetMapStoreId
* Description    : 设置安全存储区序列号缩写
* Input          : hStoreHandle : 安全存储区句柄
*                : pcStoreId      : 设备序列号
*                : pucMapStoreId : 设备序列号对应的缩写,(二个字节)
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_SetMapStoreId(QHANDLE hStoreHandle, char *pcStoreId, unsigned char *pucMapStoreId);

/*******************************************************************************
* Function Name  : QCard_QueryMapStoreIdKey
* Description    : 查询密钥
* Input          : hStoreHandle   : 安全存储区句柄
*                : pucMapStoreId  : 设备序列号缩写,大小为2个字符
* OutPut         : uiQKeyTotalLen : 密钥总量
*                : uiQKeyUsedLen  : 密钥已使用量
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_QueryMapStoreIdKey(QHANDLE hStoreHandle, unsigned char *pucMapStoreId, unsigned long *puiQKeyTotalLen, unsigned long *puiQKeyUsedLen);

/*******************************************************************************
* Function Name  : QCard_ReadMapStoreIdFlag
* Description    : 获取校验同步码
* Input          : hStoreHandle : 安全存储区句柄
*                : pucMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucFlag      : flag缓存, flag为4个字节的数据
* Output         : pucFlag      : 校验同步码
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ReadMapStoreIdFlag(QHANDLE hStoreHandle, unsigned char *pucMapStoreId, unsigned char *pucFlag);

/*******************************************************************************
* Function Name  : QCard_CheckSynMapStoreIdFlag
* Description    : 校验同步
* Input          : hStoreHandle : 安全存储区句柄
*                : pucMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucFlag      : flag缓存, flag为4个字节的数据
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_CheckSynMapStoreIdFlag(QHANDLE hStoreHandle, unsigned char *pucMapStoreId, unsigned char *pucFlag);

/*******************************************************************************
* Function Name  : QCard_ReadMapStoreIdKey
* Description    : 读取密钥
* Input          : hStoreHandle : 安全存储区句柄
*                : pcMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucQKey      : 密钥缓存
*                : uiQKeyLen    : 读取量子密钥长度
* OutPut         : pucQKey      ：密钥
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ReadMapStoreIdKey(QHANDLE hStoreHandle, unsigned char *pucMapStoreId, unsigned char *pucQKey, unsigned int uiQKeyLen);

/*******************************************************************************
* Function Name  : QCard_WiteUnitToCon
* Description    : 写入密钥批次对应的容器名称
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcKeyUnitsId    : 密钥组ID,任意不大于64位值,由充注端定义
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_WiteUnitToCon(QHANDLE hStoreHandle, char *pcKeyUnitsId, char *pcAppName, char *pcContainerName);

/*******************************************************************************
* Function Name  : QCard_ClearStoreIdKey
* Description    : 清理密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcStoreId       : 密钥组ID,任意不大于64位值,由充注端定义
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ClearStoreIdKey(QHANDLE hStoreHandle, char *pcStoreId, char *pcAppName, char *pcContainerName);

/*******************************************************************************
* Function Name  : QCard_ClearAppKey
* Description    : 清理密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName       : 应用名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ClearAppKey(QHANDLE hStoreHandle, char *pcAppName);

/*******************************************************************************
* Function Name  : QCard_ClearUnitKey
* Description    : 清理密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcUnitsName      : 批次名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ClearUnitKey(QHANDLE hStoreHandle, char *pcUnitsName);

/*******************************************************************************
* Function Name  : QCard_ClearLocalUsedKey
* Description    : 清理CS系统已使用密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcUnitsName      : 批次名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ClearLocalUsedKey(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_ClearUsedKey
* Description    : 清理已使用密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcUnitsName      : 批次名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ClearUsedKey(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_WiteQKey
* Description    : 写入密钥
* Input          : hStoreHandle  : 安全存储区句柄
*                : pcStoreId     : 对端设备序列号
*                : pcKeyUnitsId  : 密钥组ID,任意不大于64位值,由充注端定义
*                : pcKeyBlocksId : 密钥Id,任意不大于64位值且唯一,由充注端定义
*                : pucQKey       : 写入的密钥
*                : uiQKeyLen     : 写入量子密钥长度
*                : pcTimeStart   : 密钥有效期起始时间
*                : pcTimeEnd     : 密钥有效期截止时间
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_WiteKey(QHANDLE hStoreHandle, char *pcStoreId, char *pcKeyUnitsId, char *pcKeyBlocksId,
							unsigned char *pucQKey, unsigned int uiQKeyLen, char *pcTimeStart, char *pcTimeEnd);

/*******************************************************************************
* Function Name  : QCard_WiteEncryptKey
* Description    : 写入密文密钥
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcStoreId       : 对端设备序列号
*                : pcKeyUnitsId    : 密钥组ID,任意不大于64位值,由充注端定义
*                : pcKeyBlocksId   : 密钥Id,任意不大于64位值且唯一,由充注端定义
*                : uiKeyLen        : 密钥长度
*                : pucEncryptKey   : 写入的密文密钥
*                : uiEncryptKeyLen : 写入密文密钥长度 
*                : pcTimeStart   : 密钥有效期起始时间
*                : pcTimeEnd     : 密钥有效期截止时间
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_WiteEncryptKey(QHANDLE hStoreHandle, char *pcStoreId, char *pcKeyUnitsId, char *pcKeyBlocksId, unsigned int uiQKeyLen, 
								   unsigned char *pucEncryptKey, unsigned int uiEncryptKeyLen, char *pcTimeStart, char *pcTimeEnd);

/*******************************************************************************
* Function Name  : QCard_WiteSymmetricEncryptKey
* Description    : 写入密文密钥(对称密钥加密)
* Input          : hStoreHandle  : 安全存储区句柄
*                : pcStoreId     : 对端设备序列号
*                : pcKeyUnitsId  : 密钥组ID,任意不大于64位值,由充注端定义
*                : pcKeyBlocksId : 密钥Id,任意不大于64位值且唯一,由充注端定义
*                : pucQKey       : 写入的密钥密文
*                : uiQKeyLen     : 写入量子密钥密文长度
*                : pcTimeStart   : 密钥有效期起始时间
*                : pcTimeEnd     : 密钥有效期截止时间
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_WiteSymmetricEncryptKey(QHANDLE hStoreHandle, char *pcStoreId, char *pcKeyUnitsId, char *pcKeyBlocksId,
    unsigned char *pucQKey, unsigned int uiQKeyLen, char *pcTimeStart, char *pcTimeEnd);

/*******************************************************************************
* Function Name  : QCard_QueryTotalKeySize
* Description    : 查询设备密钥容量
* Input          : hStoreHandle    : 安全存储区句柄
* OutPut         : puiTotalKeySize : 密钥总量,单位MB
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_QueryTotalKeySize(QHANDLE hStoreHandle, unsigned long *puiTotalKeySize);

/*******************************************************************************
* Function Name  : QCard_KeyToConVerifyPIN
* Description    : 校验PIN, 当使用三级密钥体系进行充注密钥后，QCard_KeyInit函数运行前需要进行校验PIN
* Input          : hStoreHandle       : 安全存储区句柄
*                : pcAppName          : 应用名
*                : pcContainerName    : 容器名
*                : pcUserPin          : 用户PIN
* OutPut         : pulUserPinRetry    : 应用用户PIN出错后返回的重试次数
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_KeyToConVerifyPIN(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle, char *pcAppName, char *pcContainerName, char *pcUserPin, unsigned long *pulUserPinRetry);

/*******************************************************************************
* Function Name  : QCard_KeyInit
* Description    : 获取密钥句柄
* Input          : hStoreHandle : 安全存储区句柄
*                : pcCheckCode  : 校验码,由密钥服务端定义
*                : pcFlag       : 密钥标记位,由密钥服务端定义
*                : ulAlgId      : 算法标示
*                : KeyParam     : 分组密钥算法相关参数
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_KeyInit(QHANDLE hStoreHandle, char *pcCheckCode, char *pcFlag, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_ConsultKeyInit
* Description    : 获取协商密钥句柄
* Input          : hStoreHandle     : 安全存储区句柄
*                : pucWrapedData    : 校验码,由密钥服务端定义
*                : ulWrapedDataLen  : 密钥标记位,由密钥服务端定义
*                : ulAlgId      : 算法标示
*                : KeyParam     : 分组密钥算法相关参数
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
//QCARD_API int QCard_ConsultKeyInit(QHANDLE hStoreHandle, unsigned char pucWrapedData, unsigned long ulWrapedDataLen, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_ClientKeyInit
* Description    : 获取密钥句柄
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcCheckCode     : 校验码,由密钥服务端定义
*                : pcFlag          : 密钥标记位,由密钥服务端定义
*                : ulAlgId         : 算法标示
*                : KeyParam        : 分组密钥算法相关参数
*                : pcAppName       : 应用名称
*                : pcContainerName : 容器名称
*                : pcUserPin       : 应用用户PIN码
*                : ulSafeTactics   : 安全策略
* Output         : phKeyHandle     : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ClientKeyInit(QHANDLE hStoreHandle, char *pcCheckCode, char *pcFlag, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam,
    char *pcAppName, char *pcContainerName, char *pcUserPin, unsigned long ulSafeTactics, KEYHANDLE *phKeyHandle);

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
* Function Name  : QCard_NegotiateKeyInit
* Description    : 获取密钥句柄,适用于点对点模式，二张卡完成QCard_CheckSynFlag协商后调用，保证密钥句柄一直
* Input          : hStoreHandle : 安全存储区句柄
*                : pcStoreId    : 对端设备序列号
*                : ulAlgId      : 算法标示
*                :KeyParam     : 分组密钥算法相关参数
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_NegotiateKeyInit(QHANDLE hStoreHandle, char *pcStoreId, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, KEYHANDLE *phKeyHandle);

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
QCARD_API int QCard_ExternalKeyInit(QHANDLE hStoreHandle, unsigned char *pucKey, unsigned long ulKeyLen, unsigned long ulAlgId,
	QCard_BLOCKCIPHERPARAM KeyParam, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_OnlineKeyInit
* Description    : 获取密钥句柄, 通过在线与服务端协商获取密钥, 当密钥不足或异常时会自动充值密钥
* Input          : hStoreHandle  : 安全存储区句柄
*                : pucKey        : 会话密钥
*                : ulKeyLen      : 会话密钥长度
*                : ulAlgId       : 算法标示
*                : KeyParam      : 分组密钥算法相关参数
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_OnlineKeyInit(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin, unsigned long *pulUserPinRetry,
                                  unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, KEYHANDLE *phKeyHandle);

/*******************************************************************************
* Function Name  : QCard_ClientKeyInit
* Description    : 获取密钥句柄, 通过在线与服务端协商获取密钥, 当密钥不足或异常时会自动充值密钥
* Input          : hStoreHandle  : 安全存储区句柄
*                : pucKey        : 会话密钥
*                : ulKeyLen      : 会话密钥长度
*                : ulAlgId       : 算法标示
*                : KeyParam      : 分组密钥算法相关参数
* Output         : phKeyHandle   : 密钥句柄
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ClientKeyInit (QHANDLE hStoreHandle, char *pcCheckCode, char *pcFlag, unsigned long ulAlgId, QCard_BLOCKCIPHERPARAM KeyParam, 
                                    char *pcAppName, char *pcContainerName, char *pcPin, unsigned long ulSafeTactics, KEYHANDLE *phKeyHandle);


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
* Output         : pucQKey      : 密钥, 当值为0时，puiQKeyLen返回密钥长度，
*                : puiQKeyLen   ：密钥长度，当值为0时，puiQKeyLen返回密钥长度，当值不为0时，puiQKeyLen代表pucQKey缓存长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetQKey(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle, unsigned char *pucQKey, unsigned int *puiQKeyLen);

/*******************************************************************************
* Function Name  : QCard_Encrypt
* Description    : 数据加密
* Input          : hStoreHandle    : 安全存储区句柄
*                : hKeyHandle      : 密钥句柄
*                : pucData         : 待加密数据
*                : ulDataLen       : 待加密数据长度,必须是16字节的整数倍
*                : pulEncryptedLen ：输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Output         : pucEncryptedData : 加密后的数据缓冲区指针,可以为NULL,用于获取加密后的数据长度
*                : ulEncryptedLen ：输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_Encrypt(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle, unsigned char *pucData, unsigned long ulDataLen, unsigned char *pucEncryptedData, unsigned long *pulEncryptedLen);

/*******************************************************************************
* Function Name  : QCard_Decrypt
* Description    : 数据解密
* Input          : hStoreHandle     : 安全存储区句柄
*                : hKeyHandle       : 密钥句柄
*                : pucEncryptedData : 待解密数据,必须是16字节的整数倍
*                : ulEncryptedLen   :输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Output         : pucData          : 指向解密后的数据缓冲区指针,当为NULL时可获得解密后的数据长度
*                : pulEncryptedLen  :输入时表示数据缓冲区长度,输出时表示结果数据实际长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_Decrypt(QHANDLE hStoreHandle, KEYHANDLE hKeyHandle, unsigned char *pucEncryptedData, unsigned long ulEncryptedLen, unsigned char *pucData, unsigned long *pulDataLen);

/*******************************************************************************
* Function Name  : QCard_UpdateResource
* Description    : 更新资源,销毁资源前调用一次更新资源函数
* Input          : hStoreHandle : 登录成功后的安全存储区句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_UpdateResource(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_DestoryResource
* Description    : 销毁资源
* Input          : hStoreHandle :  初始化资源成功后的安全存储区句柄
*******************************************************************************/
QCARD_API void QCard_DestoryResource(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_GetNegotiateMode
* Description    : 获取协商模式
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcSystemId       : 系统名称
* Output         : puiNegotiateMode : 输出值为0时,代表目标协商模式未确定
*                :                   :输出值为1时,代表目标协商模式为CTS模式（点对服务器）;
*                :                   :输出值为2时,代表目标协商模式为CTC模式(点对点);
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetNegotiateMode(QHANDLE hStoreHandle, char *pcSystemId, unsigned int* puiNegotiateMode);

/*******************************************************************************
* Function Name  : QCard_WaitForDevEvent
* Description    : 监听设备插拔事件
* Input          : pulDevNameLen    : 设备名称缓存长度
*                : pcDriverName     : 设备名称缓存
* Output         : pulDevNameLen    : 设备名称长度
*                : pcDriverName     : 设备名称
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
* Function Name  : QCard_SetLoginOverTime
* Description    : 设置登陆超时时间（默认5秒）
* Input          : hStoreHandle : 安全存储区句柄
*                : uiOverTime : 登陆超时时间,单位秒
* Output         : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_SetLoginOverTime(unsigned int uiOverTime);

/*******************************************************************************
* Function Name  : QCard_GetDriverName
* Description    : 获取驱动盘符
* Input          : hStoreHandle     : 安全存储区句柄
*                : pulDevNameLen    : 设备名称缓存长度
*                : pcDriverName     : 设备名称缓存
* Output         : pulDevNameLen    : 设备名称长度
*                : pcDriverName     : 设备名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetDriverName(QHANDLE hStoreHandle, char *pcDriverName, unsigned long *pulDevNameLen);

/*******************************************************************************
* Function Name  : QCard_GetContainerName
* Description    : 获取容器名称
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcSystemId       : 系统ID
* Output         : pucAppName       : 容器所属应用名称
*                : ContainerName    : 容器名称
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetContainerName(QHANDLE hStoreHandle, char *pcSystemId, char*pcAppName, char *pcContainerName);

/*******************************************************************************
* Function Name  : QCard_GetSysTemName
* Description    : 获取系统名称
* Input          : hStoreHandle     : 安全存储区句柄
* Output         : pucData          : 系统名称文件
*                : pucDataLen       : 文件长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetSysTemName(QHANDLE hStoreHandle, unsigned char **pucData, unsigned int *pucDataLen);

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
* Function Name  : QCard_GetStoreId_SKF
* Description    : 获取安全存储区序列号
* Input          : hStoreHandle : 安全存储区句柄
*                : pcDevId      : 缓存区指针,缓存区大小>=32字节
* Output         : pcDevId      : 设备序列号内容
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_GetStoreId_SKF(QHANDLE hStoreHandle, char *pcDevId);

/*******************************************************************************
* Function Name  : QCard_VerifyPIN
* Description    : 校验PIN
* Input          : hStoreHandle : 安全存储区句柄
*                : pcAppName    : 应用名
*                : pcUserPin    : 用户PIN
* Output         : pulUserPinRetry      : 错误返回值
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_VerifyPIN(QHANDLE hStoreHandle, char *pcAppName, char *pcUserPin, unsigned long *pulUserPinRetry);

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
* Function Name  : QCard_GetSystemAddr
* Description    : 获取系统地址
* Input          : hStoreHandle     : 安全存储区句柄
*                : pcAppName        : 应用名
*                : pcConName        : 容器名
* Output         : pucData          : 系统地址, 格式为IP:PORT
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetSystemAddr(QHANDLE hStoreHandle, char *pcAppName, char *pcConName, char *pcSystemAddr);

/*******************************************************************************
* Function Name  : QCard_SetTerminalInfo
* Description    : 设置终端信息
* Input          : hStoreHandle     : 安全存储区句柄
*                : pucData          : 终端信息
*                : uiDataLen        : 终端信息长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_SetTerminalInfo(QHANDLE hStoreHandle, unsigned char **pucData, unsigned int uiDataLen);

/*******************************************************************************
* Function Name  : QCard_GetTerminalInfo
* Description    : 获取终端信息
* Input          : hStoreHandle     : 安全存储区句柄
* Output         : pucData          : 终端信息
*                : pucDataLen       : 终端信息长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetTerminalInfo(QHANDLE hStoreHandle, unsigned char **pucData, unsigned int *pucDataLen);

/*******************************************************************************
* Function Name  : QCard_SetSystemConf
* Description    : 设置系统配置
* Input          : hStoreHandle     : 安全存储区句柄
*                : pucData          : 系统配置信息
*                : uiDataLen        : 系统配置长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_SetSystemConf(QHANDLE hStoreHandle, unsigned char **pucData, unsigned int uiDataLen);

/*******************************************************************************
* Function Name  : QCard_GetSystemConf
* Description    : 获取系统配置
* Input          : hStoreHandle     : 安全存储区句柄
* Output         : pucData          : 系统配置信息
*                : pucDataLen       : 系统配置长度
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetSystemConf(QHANDLE hStoreHandle, unsigned char **pucData, unsigned int *pucDataLen);

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
* Function Name  : QCard_SyncAuditForUser
* Description    : 上传审计日志到服务端（使用token上传）
* Input          : hStoreHandle    : 安全存储区句柄
*                : pcAppName    : 应用名
*                : pcContainerName : 容器名
*                : pcToken              : token
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_SyncAuditForUser(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcToken);

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
* Function Name  : QCard_SyncTerminalBindInfo
* Description    : 从服务端同步终端绑定信息
* Input          : QHANDLE hStoreHandle         : 安全存储区句柄
* Input          : char * pcAppName             : 应用名
* Input          : char * pcContainerName       : 容器名
* Input          : char * pcUserPin                   : 用户pin码
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_SyncTerminalBindInfo(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcUserPin);

/*******************************************************************************
* Function Name  : QCard_DelExpiredAudit
* Description    : 删除过期审计日志
* Input          : QHANDLE hStoreHandle         : 安全存储区句柄
* Return         : QCARD_API int 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_DelExpiredAudit(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_KeyStore
* Description    : 存储固定主秘钥
* Input          : hStoreHandle    : 安全存储区句柄
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_KeyStore(QHANDLE hStoreHandle);

/*******************************************************************************
* Function Name  : QCard_KeyEnSm4Stroe
* Description    : 明文充主时加密存储
* Input          ： hStoreHandle    : 安全存储区句柄
                 :  pucKey        : 会话密钥
*                : ulKeyLen       : 会话密钥长度
* Output         : enpucQKey   : 加密后秘钥
                 : enpuckeylen : 加密后的长度
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_KeySm4EnStroe(QHANDLE hStoreHandle,unsigned char *pucQKey, unsigned int uiQKeyLen,unsigned char *enpucKey,unsigned long *enpuckeylen);


/*******************************************************************************
* Function Name  : QCard_KeySm4DenStroe
* Description    : 明文充主时加密存储
* Input          ： hStoreHandle    : 安全存储区句柄
                 :  pucKey        : 会话密钥
*                : ulKeyLen       : 会话密钥长度
* Output         : denpucQKey   : 解密后秘钥
                 : denpuckeylen : 解密后的长度
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
QCARD_API int QCard_KeySm4DenStroe(QHANDLE hStoreHandle,unsigned char *pucQKey, unsigned int uiQKeyLen,unsigned char *denpucKey,unsigned long *denpuckeylen);


/*******************************************************************************
* Function Name  : QCard_ReadQKey
* Description    : 读取密钥
* Input          : hStoreHandle : 安全存储区句柄
*                : pcMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucQKey      : 密钥缓存
*                : uiQKeyLen    : 读取量子密钥长度
* OutPut         : pucQKey      ：密钥
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ReadKey(QHANDLE hStoreHandle, char *pcMapStoreId, unsigned char *pucQKey, unsigned int uiQKeyLen);


/*******************************************************************************
* Function Name  : QCard_ReadFlag
* Description    : 获取校验同步码
* Input          : hStoreHandle : 安全存储区句柄
*                : pcMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucFlag      : flag缓存, flag为4个字节的数据
* Output         : pucFlag      : 校验同步码
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_ReadFlag(QHANDLE hStoreHandle, char *pcMapStoreId, unsigned char *pucFlag);

/*******************************************************************************
* Function Name  : QCard_CheckSynFlag
* Description    : 校验同步
* Input          : hStoreHandle : 安全存储区句柄
*                : pcMapStoreId : 设备序列号缩写,大小为2个字符
*                : pucFlag      : flag缓存, flag为4个字节的数据
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_CheckSynFlag(QHANDLE hStoreHandle, char *pcMapStoreId, unsigned char *pucFlag);

/*******************************************************************************
* Function Name  : QCard_OnlineC2SUnitKey
* Description    : 充注一个批次的密钥
* Input          : hStoreHandle         : 安全存储区句柄
*                : pcAppName            : 应用名
*                : pcContainerName      : 容器名
*                : pcPin                : 应用PIN
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_OnlineC2SUnitKey(QHANDLE hStoreHandle, char *pcAppName, char *pcContainerName, char *pcPin);

/*******************************************************************************
* Function Name  : QCard_GetDeviceCapacity
* Description    : 获取设备剩余容量
* Input          : hStoreHandle         : 安全存储区句柄
*                : ullTotalKeyLen       : 设备总容量
*                : ullSurplusKeyLen     : 设备剩余容量
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetDeviceCapacity(QHANDLE hStoreHandle, unsigned long long *pullTotalKeyLen, unsigned long long *pullSurplusKeyLen);

/*******************************************************************************
* Function Name  : QCard_EnumFileNum
* Description    : 枚举文件个数
* Input          : QHandle      : 安全存储区句柄
*                : QCARD_FILES  : 值为0
* Output         : QCARD_FILES  : 文件集
* Return         : 成功返回0 ;其它返回错误值
*******************************************************************************/
QCARD_API int QCard_EnumFileNum(QHANDLE hStoreHandle, unsigned int *puiFileNum);

/*******************************************************************************
* Function Name  : QCard_GetSurplusQKeyBlockNum_DLL
* Description    : 获取设备剩余容量可容纳的密钥块数
* Input          : hStoreHandle         : 安全存储区句柄
*                : ullBlockQkeySize       : 密钥块大小（Byte）
*                : pullSurplusQKeyBlockNum     : 设备剩余容量可容纳的密钥块数
* Return         : 成功返回0; 其它值为错误码;
*******************************************************************************/
QCARD_API int QCard_GetSurplusQKeyBlockNum(QHANDLE hStoreHandle, unsigned long long ullBlockQkeySize, unsigned long long *pullSurplusQKeyBlockNum);

/*******************************************************************************
* Function Name  : QCard_SetLocalNetListenPar
* Description    : 设置本地网络监听的ip 端口
* Input          : localip    : 本地的ip
*                : localport    :本地的端口
*                : storgedevice : 0：无存储设备        1：有存储设备 
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
//int QCard_SetLocalNetListenPar(char* localip,unsigned short localport,int storgedevice);

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
//int QCard_SetNetNegotiatePar(char* remoteip,unsigned short* remoteport,int negotiatemode,char* appname,char*conname,char*pin);

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
* Function Name  : QCard_GetNetHandle
* Description    : 获得网络句柄
* Input          : 无
* Return         : 成功返回0,其它返回错误码
*******************************************************************************/
//QSocket * QCard_GetNetHandle();

#ifdef  __cplusplus
}
#endif  /* #ifdef  __cplusplus */

#endif  /* #ifndef QCARD_H */
