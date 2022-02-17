/*************************************************
 Copyright (C), 2009 Qasky Co., Ltd
 File name: qcard_type.h
 Author: Jianbin Wang    Version:  1.0.0      Date: 2019年12月23日
 Description: : 量子移动存储设备应用接口数据结构定义
 *************************************************/

#ifndef QCARD_TYPE_H
#define QCARD_TYPE_H

typedef unsigned char	u8;
typedef unsigned short	u16;
typedef unsigned int    u32; // 跨平台编译需要注意

#ifndef NO_PADDING
#define NO_PADDING				0
#endif

/* 是否启用定制接口 */
#define BOOL_CUSTOM_NEWSKF 1

/* 是否在编译EGW200库 */
#define IS_EGW200 0

/* 量子密钥加密标志位 */
#define QKEY_PUBLIC_KEY_ENCRYPT (0)
#define QKEY_NOT_ENCRYPT (1)  
#define QKEY_SYMMETRIC_KEY_ENCRYPT (2)

/* 设备类型 */
#define DEVICE_TYPE_QUD  (1)
#define DEVICE_TYPE_QTF  (2)
#define DEVICE_TYPE_QHID (4)
#define DEVICE_TYPE_QUP  (8)


/* 设备私密区&安全区错误码定义 */
#define QCard_OK              0x00000000   /* 操作成功 */ 
#define QCard_BASE            0xF4000000   /* 错误基 */ 
#define QCard_READERR         0xF4000001   /* 读数据错误 */  
#define QCard_WRITEERR        0xF4000002   /* 写数据失败 */ 
#define QCard_PARAMERR        0xF4000003   /* 参数错误 */
#define QCard_RESPONSEERR     0xF4000004   /* 获取到的数据错误 */  
#define QCard_NODEVICE        0xF4000005   /* 没有设备 */  
#define QCard_LOGSTATUS       0xF4000006   /* 登陆状态错误 */  
#define QCard_SPACENOTENOUGH  0xF4000007   /* 磁盘空间不足 */  
#define QCard_FILEDAMAGE      0xF4000008   /* 文件损坏 */ 
#define QCard_NOTFINDID       0xF4000009   /* 索引错误 */  
#define QCard_UNLAWFULNESS    0xF400000A   /* 读取密钥FLAG不合法 */ 
#define QCard_KEYNOTUNIQUE    0xF400000B   /* 密钥重复写入 */  
#define QCard_NOKEYPOOL       0xF400000C   /* 该对设备无密钥充注或者密钥不足 */ 
#define QCard_NOINIT          0xF400000D   /* 未初始化 */  
#define QCard_INITED          0xF400000E   /* 已初始化 */ 
#define QCard_NOTFIND         0xF400000F   /* 没有找到目标 */  
#define QCard_BUSY            0xF4000010   /* 设备繁忙 */  
#define QCard_NOINDEX         0xF4000011   /* 没有索引  */ 
#define QCard_EVENTFAIL       0xF4000012   /* 事务失败 */  
#define QCard_PINLOCKED		  0xF4000013   /* PIN锁死 */ 
#define QCard_PININCORRECT	  0xF4000014   /* PIN错误 */ 
#define QCard_FILLKEYFAIL     0xF4000015   /* 充注密钥失败 */  
#define QCard_CONSULTKEYFAIL  0xF4000016   /* 协商密钥失败 */ 
#define QCard_CLEARKETFAIL    0xF4000017   /* 清理密钥失败 */
#define QCard_OTHERERR        0xF4000018   /* 其它错误 */
#define QCard_FILEINDEXFAIL   0xF4000019   /* 文件索引HASH校验错误 */ 
#define QCard_DISKINDEXFAIL   0xF400001A   /* 磁盘索引HASH校验错误 */ 
#define QCard_FILEOPENFAIL	  0xF400001B   /* 打开文件失败 */
#define QCard_UNSTARTVERIFY   0xF400001C   /* 未开始设备校验流程 */
#define QCard_UNSENTVERIFY    0xF400001D   /* 未发送开始校验PIN事件 */
#define QCard_REPEATVERIFY    0xF400001E   /* 设备已经校验成功，不需要重复校验 */
#define QCard_ILLEGALITYDATA  0xF400001F   /* 非法数据 */

/* 网络通讯接口返回结果 */
#define QrngProxy_OK              0x00000000           // 操作成功
#define QrngProxy_BASE            0xF3000000           // 错误码基数值
#define QrngProxy_PARAMERR        QrngProxy_BASE + 1   // 参数错误
#define QrngProxy_NETERR          QrngProxy_BASE + 2   // 网络请求错误
#define QrngProxy_TIMEOUT         QrngProxy_BASE + 3   // 接口请求超时
#define QrngProxy_REQUESTERR      QrngProxy_BASE + 4   // 接口响应错误
#define QrngProxy_CONSULTFAIL     QrngProxy_BASE + 5   // 协商错误
#define QrngProxy_OTHERERR	      QrngProxy_BASE + 6   // 其它错误
#define QrngProxy_NOEXISTKEY      QrngProxy_BASE + 7   // 不存在有效密钥


/* 设备加密芯片错误码定义 */
#define SAR_OK							0x00000000
#define SAR_FAIL						0x0A000001
#define SAR_UNKOWNERR					0x0A000002
#define SAR_NOTSUPPORTYETERR			0x0A000003
#define SAR_FILEERR						0x0A000004
#define SAR_INVALIDHANDLEERR			0x0A000005
#define SAR_INVALIDPARAMERR				0x0A000006
#define SAR_READFILEERR					0x0A000007
#define SAR_WRITEFILEERR				0x0A000008
#define SAR_NAMELENERR					0x0A000009
#define SAR_KEYUSAGEERR					0x0A00000A
#define SAR_MODULUSLENERR				0x0A00000B
#define SAR_NOTINITIALIZEERR			0x0A00000C
#define SAR_OBJERR						0x0A00000D
#define SAR_MEMORYERR					0x0A00000E
#define SAR_TIMEOUTERR					0x0A00000F
#define SAR_INDATALENERR				0x0A000010
#define SAR_INDATAERR					0x0A000011
#define SAR_GENRANDERR					0x0A000012
#define SAR_HASHOBJERR					0x0A000013
#define SAR_HASHERR						0x0A000014
#define SAR_GENRSAKEYERR				0x0A000015
#define SAR_RSAMODULUSLENERR			0x0A000016
#define SAR_CSPIMPRTPUBKEYERR			0x0A000017
#define SAR_RSAENCERR					0x0A000018
#define SAR_RSADECERR					0x0A000019
#define SAR_HASHNOTEQUALERR				0x0A00001A
#define SAR_KEYNOTFOUNTERR				0x0A00001B
#define SAR_CERTNOTFOUNTERR				0x0A00001C
#define SAR_NOTEXPORTERR				0x0A00001D
#define SAR_DECRYPTPADERR				0x0A00001E
#define SAR_MACLENERR					0x0A00001F
#define SAR_BUFFER_TOO_SMALL			0x0A000020
#define SAR_KEYINFOTYPEERR				0x0A000021
#define SAR_NOT_EVENTERR				0x0A000022
#define SAR_DEVICE_REMOVED				0x0A000023
#define SAR_PIN_INCORRECT				0x0A000024
#define SAR_PIN_LOCKED					0x0A000025
#define SAR_PIN_INVALID					0x0A000026
#define SAR_PIN_LEN_RANGE				0x0A000027
#define SAR_USER_ALREADY_LOGGED_IN		0x0A000028
#define SAR_USER_PIN_NOT_INITIALIZED	0x0A000029
#define SAR_USER_TYPE_INVALID			0x0A00002A
#define SAR_APPLICATION_NAME_INVALID	0x0A00002B
#define SAR_APPLICATION_EXISTS			0x0A00002C
#define SAR_USER_NOT_LOGGED_IN			0x0A00002D
#define SAR_APPLICATION_NOT_EXISTS		0x0A00002E
#define SAR_FILE_ALREADY_EXIST			0x0A00002F
#define SAR_NO_ROOM						0x0A000030
#define SAR_FILE_NOT_EXIST				0x0A000031
#define SAR_REACH_MAX_CONTAINER_COUNT	0x0A000032	

//错误代码拓展
#define  SAR_PIN_INFO_ERR 0x0A000033        //获取pin的信息出错
#define  SAR_CONTAINER_NOT_EXISTS      0x0A000034          //容器不存在
#define  SAR_ECCDECERR                 0x0A000035          //ECC解密错误
#define  SAR_GENECCKEYERR              0x0A000036          //产生ECC密钥错误

#define QSKR_SUCCESS             0                          //成功
#define QSKR_E_BASE              0xE8000000                 
#define QSKR_E_DEVICE_UNKNOWN    (SKR_E_BASE + 1)           //未知设备
#define QSKR_E_NO_DEVICE         (SKR_E_BASE + 2)           //无设备
#define QSKR_PIN_INCORRECT       (SKR_E_BASE + 3)           //错误pin
#define QSKR_INVALID_HANDLE      (SKR_E_BASE + 4)           //无效句柄
#define QSKR_QUESTION_TOO_LONG   (SKR_E_BASE + 5)           //答案或者问题超长
#define	QSKR_ANSWER_INCORRECT    (SKR_E_BASE + 6)           //答案错误
#define	QSKR_NOT_FORMAT          (SKR_E_BASE + 7)           //未格式化
#define	QSKR_INVALID_PARAM       (SKR_E_BASE + 8)           //无效参数
#define QSKR_NO_PRIV_DRIVER      (SKR_E_BASE + 9)           //非私有区设备
#define QSKR_INVALID_LBA         (SKR_E_BASE + 0x0a)        //无效扇区号
#define QSKR_NOT_LOGIN           (SKR_E_BASE + 0x0b)        //未登录
#define QSKR_UNKNEW              (SKR_E_BASE + 0xaa)        //未知错误


/* 算法定义 */
#define SGD_SM1_ECB			0x00000101       /* SM1 ECB */
#define SGD_SM1_CBC			0x00000102       /* SM1 CBC */ 
#define SGD_SM1_CFB			0x00000104       /* SM1 CFB */ 
#define SGD_SM1_OFB			0x00000108       /* SM1 OFB */ 
#define SGD_SM1_MAC			0x00000110       /* SM1 MAC */ 
#define SGD_SSF33_ECB       0x00000201       /* SSF33 ECB */ 
#define SGD_SSF33_CBC       0x00000202       /* SSF33 CBC */ 
#define SGD_SSF33_CFB       0x00000204       /* SSF33 CFB */ 
#define SGD_SSF33_OFB       0x00000208       /* SSF33 OFB */ 
#define SGD_SSF33_MAC       0x00000210       /* SSF33 MAC */ 
#define SGD_SMS4_ECB		0x00000401       /* SMS4 ECB */ 
#define SGD_SMS4_CBC		0x00000402       /* SMS4 CBC */ 
#define SGD_SMS4_CBC_FILE	0x00001402       /* SMS4 CBC  file key */
#define SGD_SMS4_CBC_DDK	0x00002402       /* SMS4 CBC  DDK */
#define SGD_SMS4_CBC_WK		0x00004402       /* SMS4 CBC  WK */
#define SGD_SMS4_CFB		0x00000404       /* SMS4 CFB */ 
#define SGD_SMS4_OFB		0x00000408       /* SMS4 OFB */ 
#define SGD_SMS4_OFB_WK		0x00004408       /* SMS4 CBC  WK */
#define SGD_SMS4_MAC		0x00000410       /* SMS4 MAC */ 
#define SGD_SMS4_MAC_DDK	0x00002410       /* SMS4 MAC */ 
#define SGD_RSA				0x00010000       /* RSA */ 
#define SGD_SM2_1			0x00020100       /* ECC Sign */ 
#define SGD_SM2_2			0x00020200       /* ECC Exchange */ 
#define SGD_SM2_3			0x00020400       /* ECC cipher */ 
#define SGD_SM3				0x00000001       /* SM3 */
#define SGD_SHA1			0x00000002       /* SHA1 */ 
#define SGD_SHA256			0x00000004       /* SHA256 */

/* 安全策略 */
#define TAC_SAFE_CLEARR   0X00000000   /* 安全擦除 */
#define TAC_PUBLIC_CLEARR 0X00000001   /* 普通擦除 */

/* 分组密钥参数 */
#define MAX_IV_LEN 32
typedef struct{
    unsigned char IV[MAX_IV_LEN];
    unsigned long IVLen;
    unsigned long PaddingType;
    unsigned long FeedBitLen;
}QCard_BLOCKCIPHERPARAM;

/* 接口句柄 */
typedef void ** QHANDLES;
typedef void  * QHANDLE;
typedef void  * KEYHANDLE;
typedef void  * EVENTHANDLE;

/* 容器证书类型 */
#define SKF_CONTAINER_ENC   0 /* 加密证书 */
#define SKF_CONTAINER_SIGN  1 /* 签名证书 */
#define SKF_CONTAINER_ROOT  2 /* 根证书 */

/* 用户类型 */
#define ADMIN_TYPE	0	/* admin PIN */ 
#define USER_TYPE	1	/* user PIN */ 


typedef struct {
	unsigned char major;
	unsigned char minor;
}QCard_VERSION;

typedef struct{ 
	QCard_VERSION     Version; 
	char		      Manufacturer[64]; 
	char              Issuer[64]; 
	char              Label[32]; 
	char              SerialNumber[32]; 
	QCard_VERSION     HWVersion; 
	QCard_VERSION     FirmwareVersion; 
	unsigned long 	  AlgSymCap; 
	unsigned long	  AlgAsymCap; 
	unsigned long	  AlgHashCap; 
	unsigned long	  DevAuthAlgId; 
	unsigned long	  TotalSpace; 
	unsigned long	  FreeSpace; 
}QCard_DEVINFO; 

typedef struct{
	char ConName[65];             /* 容器名称 */
	unsigned long ContainerType;  /* 容器类型 1RSA 2ECC */
	unsigned long SignCertExist;  /* 签名证书是否存在  0存在 1不存在 */
	unsigned long SignKeyExist;   /* 签名密钥对是否存在 */
	unsigned long EncCertExist;   /* 加密证书是否存在 */
	unsigned long EncKeyExist;    /* 加密密钥对是否存在 */
}QCard_CON;

typedef struct{ 
	char AppName[65];
	unsigned int Length;
	QCard_CON *pContainers;
}QCard_APP;

typedef struct{ 
	unsigned int Length;
	QCard_APP *pApplications;
}QCard_APPLIST;

typedef struct{
	char CommonName[256];           /* 通用名称CN */
	char OrganizationUnit[256];     /* 组织单位OU */
	char OrganizationName[256];     /* 组织部门O */
	char LocalityName[256];         /* 本地名称L */
	char StateOrProvince[256];      /* 州/省 */
	char Country[256];              /* 国家 */
}QCard_DN;

#define QCARD_ECCCIPHERSIZE       (113)  // 服务端发送的密文长度
#define QCARD_DEVECCCIPHERSIZE    (180)  // 设备端密文长度

// 服务端发送密文格式
typedef struct{
    unsigned char bit;
    unsigned char x[32];
    unsigned char y[32];
    unsigned char Cipher[16];
    unsigned char hash[32];
}QCard_ECCCipher;

// 日志等级
typedef enum{
    QLOG_ERROR,
    QLOG_WARN,
    QLOG_INFO,
    QLOG_DEBUG,
    QLOG_TRACE
}QCard_LogLevel;

#endif  //QCARD_TYPE_H