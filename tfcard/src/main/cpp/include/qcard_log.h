/*************************************************
 Copyright (C), 2009 Qasky Co., Ltd
 File name: qcard_log.h
 Author: Jianbin Wang    Version:  1.1.0      Date: 2019年5月20日
 Description: 量子移动存储设备日志接口
 *************************************************/
#ifndef QCARD_LOG_H
#define QCARD_LOG_H

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

#define QCard_Error(...) \
                QCard_Output(QLOG_ERROR, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define QCard_Warn(...) \
                QCard_Output(QLOG_WARN, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define QCard_Info(...) \
                QCard_Output(QLOG_INFO, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define QCard_Debug(...) \
                QCard_Output(QLOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

#define QCard_Trace(...) \
                QCard_Output(QLOG_TRACE, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

void QCard_Output(QCard_LogLevel level, const char *file, const char *function, int line, const char *fmt, ...);

void QCard_LogSetOutPut(void(*cb)(QCard_LogLevel level, char * msg));

void QCard_LogSetCallBack(void(*cb)(int level, char * msg), int lverror, int lvwarn, int lvinfo, int lvdebug, int lvtrace);


/* 废弃日志库 */
void QCard_LogInfo(const char *fmt, ...);

void QCard_LogDebug(const char *fmt, ...);

void QCard_LogWarn(const char *fmt, ...);

void QCard_LogError(const char *fmt, ...);

void QCard_LogDebugBin(char *pcFileName, int iFileLen, char *pcName, unsigned char *pucBin, unsigned int uiBinLen);

void QCard_LOG_DATA(char *pcFileName, int iFileLen, char *pcData);

void QCard_LOG_DATA_NAME(char *pcFileName, int iFileLen, char *pcName, char *pcData);

void QCard_LOG_BIN(char *pcFileName, int iFileLen, unsigned char *pucBin, unsigned int uiBinLen);

void QCard_LOG_BIN_NAME(char *pcFileName, int iFileLen, char *pcName, unsigned char *pucBin, unsigned int uiBinLen);

#ifdef  __cplusplus
}
#endif  /* #ifdef  __cplusplus */

#endif