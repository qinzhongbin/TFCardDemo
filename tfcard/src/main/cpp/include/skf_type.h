#ifndef __SKF_TYPE_DEF_H__
#define __SKF_TYPE_DEF_H__

#include "base_type.h"

typedef HANDLE			DEVHANDLE;
typedef HANDLE			HAPPLICATION;
typedef HANDLE			HCONTAINER;

#ifndef _WIN32
#define PACKED_ST(st) __attribute__((packed, aligned(1))) st
#else
#pragma pack(push, skf, 1)
#define PACKED_ST(st) st
#endif

typedef struct version_st 
{
	u8 major;
	u8 minor;
}PACKED_ST(VERSION);

typedef struct devinfo_st 
{ 
	VERSION     Version; 
	char        Manufacturer[64]; 
	char        Issuer[64]; 
	char        Label[32]; 
	char        SerialNumber[32]; 
	VERSION     HWVersion; 
	VERSION     FirmwareVersion; 
	u32			AlgSymCap; 
	u32			AlgAsymCap; 
	u32			AlgHashCap; 
	u32			DevAuthAlgId; 
	u32			TotalSpace; 
	u32			FreeSpace; 
	u32			MaxEccBufferSize;
	u32			MaxBufferSize;
	u8			Reserved[64]; 
}PACKED_ST(DEVINFO); 
typedef DEVINFO * PDEVINFO;

#define MAX_RSA_MODULUS_LEN		256
#define	MAX_RSA_EXPONENT_LEN	4
typedef struct rsapubkeyblob_st 
{
	u32		AlgID;
	u32		BitLen;
	u8		Modulus[MAX_RSA_MODULUS_LEN];
	u8		PublicExponent[MAX_RSA_EXPONENT_LEN];
}PACKED_ST(RSAPUBLICKEYBLOB);
typedef RSAPUBLICKEYBLOB * PRSAPUBLICKEYBLOB;

typedef struct rsaprivkeyblob_st 
{
	u32		AlgoID;
	u32		BitLen;
	u8		Modulus[MAX_RSA_MODULUS_LEN];
	u8		PublicExponent[MAX_RSA_EXPONENT_LEN];
	u8		PrivateExponent[MAX_RSA_MODULUS_LEN];
	u8		Prime1[MAX_RSA_MODULUS_LEN/2];
	u8		Prime2[MAX_RSA_MODULUS_LEN/2];
	u8		Prime1Exponent[MAX_RSA_MODULUS_LEN/2];
	u8		Prime2Exponent[MAX_RSA_MODULUS_LEN/2];
	u8		Coefficient[MAX_RSA_MODULUS_LEN/2];
}PACKED_ST(RSAPRIVATEKEYBLOB);
typedef RSAPRIVATEKEYBLOB * PRSAPRIVATEKEYBLOB;

#define ECC_MAX_XCOORDINATE_BITS_LEN		512
#define ECC_MAX_YCOORDINATE_BITS_LEN		ECC_MAX_XCOORDINATE_BITS_LEN
#define ECC_MAX_MODULUS_BITS_LEN			ECC_MAX_XCOORDINATE_BITS_LEN
typedef struct eccpubkeyblob_st 
{
	u32   BitLen; 
	u8    XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	u8    YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8]; 
}PACKED_ST(ECCPUBLICKEYBLOB);
typedef ECCPUBLICKEYBLOB * PECCPUBLICKEYBLOB;


typedef struct eccprivkeyblob_st 
{
	u32   BitLen; 
	u8    PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8]; 
}PACKED_ST(ECCPRIVATEKEYBLOB);
typedef ECCPRIVATEKEYBLOB  * PECCPRIVATEKEYBLOB; 

typedef struct ecccipherblob_st
{ 
	u8  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	u8  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	u8  HASH[32]; 
	u32	CipherLen;
	u8  Cipher[1]; 
} PACKED_ST(ECCCIPHERBLOB);
typedef ECCCIPHERBLOB  * PECCCIPHERBLOB; 

typedef struct ecccipherblob_P_st
{ 
	u8  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	u8  YCoordinate; 
	u8  HASH[4]; 
	u32	CipherLen;
	u8  Cipher[1]; 
} PACKED_ST(ECCCIPHERBLOB_P);
typedef ECCCIPHERBLOB_P  * PECCCIPHERBLOB_P; 

typedef struct eccsignatureblob_st
{ 
	u8 r[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	u8 s[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
}PACKED_ST(ECCSIGNATUREBLOB); 
typedef ECCSIGNATUREBLOB  * PECCSIGNATUREBLOB;

typedef struct SKF_ENVELOPEDKEYBLOB{
	u32 Version;					
	u32 ulSymmAlgID;				
	u32 ulBits;	
	u8  cbEncryptedPriKey[64];
	ECCPUBLICKEYBLOB PubKey;   
	ECCCIPHERBLOB ECCCipherBlob; 
}PACKED_ST(ENVELOPEDKEYBLOB);
typedef ENVELOPEDKEYBLOB  *  PENVELOPEDKEYBLOB;

typedef struct SKF_ENVELOPEDKEYBLOBEX{
	u32 Version;					
	u32 ulSymmAlgID;				
	u32 ulBits;	
	u8  cbEncryptedPriKey[8208];
	ECCPUBLICKEYBLOB PubKey;   
	ECCCIPHERBLOB ECCCipherBlob; 
}PACKED_ST(ENVELOPEDKEYBLOBEX);
typedef ENVELOPEDKEYBLOBEX  *  PENVELOPEDKEYBLOBEX;

#define	MAX_IV_LEN			32
typedef struct blockcipherparam_st 
{
    u8    IV[MAX_IV_LEN]; 
#ifdef WIN32
    u32   IVLen; 
    u32   PaddingType; 
    u32   FeedBitLen; 
#else
    unsigned int   IVLen; 
    unsigned int   PaddingType; 
    unsigned int   FeedBitLen; 
#endif
} PACKED_ST(BLOCKCIPHERPARAM); 
typedef BLOCKCIPHERPARAM  *  PBLOCKCIPHERPARAM;

typedef struct fileattr_st 
{
	char  FileName[32]; 
	u32   FileSize; 
	u32   ReadRights; 
	u32   WriteRights;  
}PACKED_ST(FILEATTRIBUTE); 
typedef FILEATTRIBUTE  *  PFILEATTRIBUTE;

//Flags for CIPHER_PARAM
#define CIPHER_NO_PADDING     0x0000
#define CIPHER_PKCS5_PADDING  0x0001
#define CIPHER_ENCRYPT        0x0000
#define CIPHER_DECRYPT        0x0010
#define CIPHER_FEED_BITS_MASK 0xFF00
typedef struct __cipher_param
{
	u32 uAlgo;
	u32 uFlags;
	int cbIV;
	u8  pbIV[32];
	int cbKey;
	u8  pbKey[128];
}PACKED_ST(CIPHER_PARAM);

#if defined(_WIN32)
#pragma pack(pop, skf) 
#endif

#define MAX_CONTAINER_NAME_LEN			64
#define MAX_APPLICATION_NAME_LEN		16

/* algorithm */
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


//////////////////////////////VENDOR DEFINED///////////////////////////////////
#define SGD_DES_ECB			0x80000101       /* DES ECB */ 
#define SGD_DES_CBC			0x80000102       /* DES CBC */ 
#define SGD_DES_CFB			0x80000104       /* DES CFB */
#define SGD_DES_OFB			0x80000108       /* DES OFB */ 
#define SGD_DES_MAC			0x80000110       /* DES MAC */ 

#define SGD_AES_ECB			0x80000201       /* AES ECB */ 
#define SGD_AES_CBC			0x80000202       /* AES CBC */ 
#define SGD_AES_CFB			0x80000204       /* AES CFB */
#define SGD_AES_OFB			0x80000208       /* AES OFB */ 
#define SGD_AES_MAC			0x80000210       /* AES MAC */ 

#define SGD_SM6_ECB			0x80000301       /* SM6 ECB */ 
#define SGD_SM6_CBC			0x80000302       /* SM6 CBC */ 
#define SGD_SM6_CFB			0x80000304       /* SM6 CFB */ 
#define SGD_SM6_OFB			0x80000308       /* SM6 OFB */ 
#define SGD_SM6_MAC			0x80000310       /* SM6 MAC  */
//////////////////////////////VENDOR DEFINED////////////////////////////////////

#ifndef TRUE
#define TRUE				1				
#endif
#ifndef FALSE
#define FALSE				0				
#endif

#ifndef NULL
#define NULL				0
#endif

#define ADMIN_TYPE			0				/* admin PIN */ 
#define USER_TYPE			1				/* user PIN */ 


/* account */
#define SECURE_NEVER_ACCOUNT	0x00		
#define SECURE_ADM_ACCOUNT		0x01		
#define SECURE_USER_ACCOUNT		0x10		
#define SECURE_ANYONE_ACCOUNT	0xFF

#define MIN_PIN_LEN				0x06
#define MAX_PIN_LEN				0x10


#define DEV_ABSENT_STATE		0x00000000	    
#define DEV_PRESENT_STATE		0x00000001      
#define DEV_UNKNOW_STATE		0x00000002  

#ifndef PKCS5_PADDING
#define PKCS5_PADDING			1
#endif

#ifndef NO_PADDING
#define NO_PADDING				0
#endif

#define CTNF_NOSET				0
#define CTNF_RSA				1
#define CTNF_ECC				2

#define HLF_DEV					0x1
#define HLF_APP					0x2
#define HLF_CTN					0x4
#define HLF_KEY					0x8
#define HLF_HASH				0x10
#define HLF_ECCWRAP_KEY			0x20

/* return value */
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
#endif /*__SKF_TYPE_DEF_H__*/
