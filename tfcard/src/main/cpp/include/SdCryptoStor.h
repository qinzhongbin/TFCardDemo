#ifndef __SD_CRYPTO_STOR_DLL_H__
#define __SD_CRYPTO_STOR_DLL_H__

#ifdef  __cplusplus
extern "C" {
#endif


#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
	typedef HANDLE			HDEV;
#else
typedef int				HDEV;
typedef void*				HANDLE;
typedef unsigned int	ULONG;
typedef unsigned char	UCHAR;
#endif

typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef int BOOL;
typedef char * PCHAR;
typedef unsigned char * PUCHAR;

#define TRUE	1
#define FALSE	0
#define MAX_PATH	260
#define _MAX_PATH		MAX_PATH

//-----------------return value--------------------//
#define SDR_OK					0
#define SDR_READ_ERROR			0x01	/* 读数据错误 */
#define SDR_WRITE_ERROR			0x02	/* 写数据错误 */
#define SDR_PARAM_ERROR			0x03	/* 参数错误 */
#define SDR_RESPONSE_ERROR		0x04	/* 获取到的数据错误 */
#define SDR_NO_DEVICE			0x05	/* 没有找到设备 */
#define SDR_NO_FILE_FOUND 0x06 /*文件列表为空*/
#define SDR_MEMERY_NOTENOUGH 0x07 /*缓存长度不够*/
const int MAX_SECTOR_SIZE = 512;
/* 功能：设置通讯数据包的包头
 * 参数：pucSendHeader
 *			发送数据包的包头，长度必须为7字节，不设置则为默认值
 * 参数：pucSendHeader
 *			接受数据包的包头，长度必须为7字节，不设置则为默认值
 * 返回：成功返回SDR_OK，否则其他
 */
void sd_CommInit(PUCHAR pucSendHeader, PUCHAR pucRecvHeader, PCHAR pszFileName);
/* 功能：设置包名
 * 参数：szPackageName
 *
 *		 	返回的字符长度
 * 返回：成功返回SDR_OK，否则其他
 */
int sd_SetPackageName(const char* szPackageName);
/* 功能：枚举所有可用设备
 * 参数：szDevNames
 *			枚举到的所有设备名称，名称之间用NULL分割，最后以2个NULL结束；例如"J\0N\0\0"
 *			使用sd_Free释放szDevNames
 *		 pulLen
 *		 	返回的字符长度
 * 返回：成功返回SDR_OK，否则其他
 */
int sd_EnumDevice(char** szDevNames, DWORD *pulLen);

/* 功能：打开指定设备
 * 参数：szDevName
 *			以NULL结尾的设备名称；例如"j\0"
 *		 phDevice
 *			返回的设备句柄，用sd_CloseDevice关闭
 * 返回：成功返回SDR_OK，否则其他
 */
int sd_OpenDevice(const char* szDevName, HDEV* phDevice);

/* 功能：关闭设备
 * 参数：hDevice
 *			设备句柄，由sd_OpenDevice获取
 * 返回：成功返回SDR_OK，否则其他
 */
void sd_CloseDevice(HDEV hDevice);

/* 功能：获取设备私有空间大小
 * 参数：hDevice
 *			设备句柄，由sd_OpenDevice获取
 *		 puCapcity
 *			返回总空间大小，扇区总数
 * 返回：成功返回SDR_OK，否则其他
 */

int sd_GetCapcity(HDEV hDevice, ULONG *puCapcity);

/* 功能：读取指定LBA的数据
 * 参数：hDevice
 *			设备句柄，由sd_OpenDevice获取
 *		uLba
 *			待访问的LBA地址
 *		dwBytesLength
 *			待读取的数据长度，单位是字节，该长度必须是512的整数倍
 *		pBuf
 *			接收读取数据的缓冲区，请确保长度
 * 返回：成功返回SDR_OK，否则其他
 */
int sd_ReadData(HDEV hDevice, ULONG uLba, DWORD dwBytesLength, UCHAR *pBuf);

/* 功能：把数据写入指定的LBA
 * 参数：hDevice
 *			设备句柄，由sd_OpenDevice获取
 *		uLba
 *			待访问的LBA地址
 *		dwBytesLength
 *			待写入的数据长度，单位是字节，该长度必须是512的整数倍
 *		pBuf
 *			待写入数据的缓冲区，请确保长度
 * 返回：成功返回SDR_OK，否则其他
 */
int sd_WriteData(HDEV hDevice, ULONG uLba, DWORD dwBytesLength, UCHAR *pBuf);

/* 功能：释放内存资源
 * 参数：pMem
 *			要释放的内存指针
 * 返回：无
 */
void sd_Free(void *pMem);
#ifdef  __cplusplus
}
#endif

#endif //__SD_CRYPTO_STOR_DLL_H__
