
#ifndef __BASE_TYPE_DEF_H__
#define __BASE_TYPE_DEF_H__

//#define _WINDOWS 1

#ifdef WIN32
#ifndef  _WINDOWS
#define _WINDOWS 1
#endif
#endif

#ifdef _WINDOWS

#ifdef WINCE
#define WINVER _WIN32_WCE
#else
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#endif

//#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef HANDLE	HDEV;

#else /* linux */
typedef int   BOOL;
typedef char* LPSTR;
#define MAX_PATH 260
#define TRUE 1
typedef int		HDEV;
typedef void*	HANDLE;

typedef long long  INT_PTR;

#ifndef  _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef  __USE_GNU
#define __USE_GNU
#endif

#endif

typedef unsigned char	u8;
typedef unsigned short	u16;
#ifndef def_U32
#define def_U32
#ifdef __linux__
typedef unsigned int    u32;
#else
typedef unsigned long   u32;
#endif
#endif

//#include <xchar.h>

#endif /* __BASE_TYPE_DEF_H__ */
