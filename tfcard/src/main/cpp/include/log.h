#include <android/log.h>
#include <cstring>
#include <stdlib.h>

#define LOG_TAG "QaSky"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

inline char *ByteArrayToHexStr(unsigned char *src, int srcLen) {
    int destLen = 2 * srcLen + 1;
    char dest[destLen];
    memset(dest, 0, destLen);
    unsigned char highByte, lowByte;

    for (int i = 0; i < srcLen; i++) {
        highByte = src[i] >> 4;
        lowByte = src[i] & 0x0f;

        highByte += 0x30;
        if (highByte > 0x39) dest[i * 2] = highByte + 0x07;
        else dest[i * 2] = highByte;

        lowByte += 0x30;
        if (lowByte > 0x39) dest[i * 2 + 1] = lowByte + 0x07;
        else dest[i * 2 + 1] = lowByte;
    }

    char *hexStr = static_cast<char *>(malloc(destLen + 2));
    sprintf(hexStr, "%s%s", "0x", dest);
    return hexStr;
}

inline int char_array_cmp(char *s1, int l1, char *s2, int l2)
{
    int lmin = l1>l2? l2:l1; //较小长度者。
    int i;

    for(i = 0; i < lmin; i ++)
        if(s1[i] > s2[i]) return 1;
        else if(s1[i] < s2[i]) return -1;

    //运行到这里，表示所有已判断元素均相等。
    if(l1 == l2) return 0;
    if(l1 > l2) return 1;

    return -1;//l1 < l2的情况。
}