//#include <jni.h>
//#include <cstdio>
//#include <cstdlib>
//#include <unistd.h>
//#include <android/log.h>
//#include "SdCryptoStor.h"
//#include <android/log.h>
//#include <qcard_type.h>
//#include <qcard.h>

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <android/log.h>
#include "SdCryptoStor.h"
#include <android/log.h>
#include "SKF.h"

#define LOG_TAG "Qasky"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

//QHANDLES phStoreHandles = nullptr;
////KEYHANDLEB hKeyHandle = nullptr;
//QCard_BLOCKCIPHERPARAM KeyParam;

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_TFCard_initRes(JNIEnv *env, jobject thiz, jstring pkg_name) {
    char *pkgName = const_cast<char *>(env->GetStringUTFChars(pkg_name, JNI_FALSE));
//    QCard_SetAppPath(pkgName); // 设置包名
//    env->ReleaseStringUTFChars(pkg_name, pkgName);
//
//    int ret = 0;
//
//    int deviceNum = 0;
//    deviceNum = QCard_EnumStoreHandle(&phStoreHandles); // 枚举设备
//    if (deviceNum <= 0) {
//        LOGE("枚举设备错误");
//        return JNI_FALSE;
//    }
//
//    ret = QCard_LOGEn(phStoreHandles[0]); // 登录
//    if (ret) {
//        LOGE("登录错误 ===> %x", ret);
//        return JNI_FALSE;
//    }
//
//    ret = QCard_InitResource(phStoreHandles[0]); // 初始化资源
//    if (ret) {
//        LOGE("初始化资源错误 ===> %x", ret);
//        return JNI_FALSE;
//    }
//
//    return JNI_TRUE;



//    int deviceNum = 0;
//    deviceNum = QCard_EnumStoreHandle(&phStoreHandles, pkgName); // 枚举设备
//
//    LOGE("deviceNum = %x", deviceNum);
//
//    if (deviceNum <= 0) {
//        LOGE("枚举设备错误");
//        return JNI_FALSE;
//    }
//
//    ret = QCard_LOGEn(phStoreHandles[0]); // 登录
//    if (ret) {
//        LOGE("登录错误 ===> %x", ret);
//        return JNI_FALSE;
//    }
//
//    ret = QCard_InitResource(phStoreHandles[0]); // 初始化资源
//    if (ret) {
//        LOGE("初始化资源错误 ===> %x", ret);
//        return JNI_FALSE;
//    }


//    char *buf = 0, *bufName = NULL;
//    int ret = 0, num = 0, len = 0, j = 0;
//    unsigned int ulLength = 0, i = 0;
//    BYTE btHeader[8] = {0x50,0x53,0x57,0x52,0xA1,0xB2,0xC3,0xD4};
//    BYTE btRecv[8] = {0xAF,0xAC,0xA8,0xAD,0x5E,0x4D,0x3C,0x2B};
//    char pszFileName[] = "SECOM.SCT";
//    HDEV hDev = 0;
////    sd_CommInit(btHeader, btRecv, pszFileName);
//    ret = sd_SetPackageName(pkgName);
//    if(ret)
//    {
//        LOGE("sd_SetPackageName error ===> %x", ret);
//    }
//    ret = V_SetAppPath(pkgName);
//    if(ret)
//    {
//        LOGE("V_SetAppPath error ===> %x", ret);
//    }
//    ret = sd_EnumDevice(&bufName,&ulLength);
//    if(ret)
//    {
//        LOGE("sd_EnumDevice error ===> %x", ret);
//    }
//    for(i = 0,num = 0; i< ulLength; i++)
//    {
//        if(bufName[i] != NULL)
//        {
//            num++;
//            i+=strlen(&(bufName[i]));
//        }
//    }
//    LOGE("NUM error ===> %d\n", num);
//
//    ret = sd_OpenDevice(bufName, &hDev);
//    if(ret)
//    {
//        LOGE("sd_OpenDevice error ===> %x", ret);
//    }
//
//    char *pszDevNameList = NULL;
//    ret = SKF_ConnectDev(pszDevNameList, &hDev);

    int ret = 0;
    char* pcDev = NULL;
    unsigned int ReLen = 0x00;
    HDEV hDev = 0;
    char *pszDevNameList = NULL;
    ULONG ulSize = 0;
    DEVHANDLE devHandle = 0;
    HAPPLICATION happ;
    u32 retry_count = 0;
    ret = sd_SetPackageName(pkgName);
    if(ret)
    {
        LOGE("sd_SetPackageName error %x\n", ret);
        return 0;
    }

    ret = sd_EnumDevice(&pcDev,&ReLen);
    if(ret)
    {
        LOGE("sd_EnumDevice error %x\n", ret);
        return 0;
    }

    ret = sd_OpenDevice((const char*)pcDev,&hDev);
    if(ret)
    {
        LOGE("sd_OpenDevice error %x\n", ret);
        return 0;
    }

    ret = V_SetAppPath(pkgName);
    if(ret)
    {
        LOGE("V_SetAppPath error %x\n", ret);
        return 0;
    }

    ret = SKF_EnumDev(TRUE, pszDevNameList, &ulSize) ;
    if(ret)
    {
        LOGE("SKF_EnumDev error %x\n", ret);
        return 0;
    }
    if (ulSize > 0)
        pszDevNameList = (char *)malloc(ulSize);
    else
    {
        LOGE("enumDev error line:%x\n",__LINE__);
        return 0;
    }

    ret = SKF_EnumDev (TRUE, pszDevNameList, &ulSize);
    if(ret)
    {
        LOGE("SKF_EnumDev error %x\n", ret);
        return 0;
    }
    ret = SKF_ConnectDev(pszDevNameList, &devHandle);
    if (ret)
    {
        LOGE("SKF_ConnectDev error %x\n", ret);
        return 0;
    }

    ret = SKF_OpenApplication(devHandle,"DEFAULT",&happ);
    if(ret)
    {
        LOGE("SKF_OpenApplication error %x\n", ret);
        return 0;
    }

    ret = SKF_VerifyPIN(happ, USER_TYPE, "20201818", &retry_count);
    if(ret)
    {
        LOGE("SKF_OpenApplication error %x\n", ret);
        return 0;
    }

    return JNI_TRUE;
}

//extern "C"
//JNIEXPORT void JNICALL
//Java_com_qasky_tfcard_TFCard_destroyRes(JNIEnv *env, jobject thiz) {
//    int ret = 0;
//
//    if (phStoreHandles != nullptr && phStoreHandles[0]) {
//        if (hKeyHandle != nullptr) {
//            QCard_KeyFinal(phStoreHandles[0], hKeyHandle);
//        }
//
//        ret = QCard_UpdateResource(phStoreHandles[0]); // 更新资源
//        if (ret) {
//            LOGE("更新资源失败 ===> %x", ret);
//        }
//        QCard_DestoryResource(phStoreHandles[0]); // 销毁资源
//        ret = QCard_Logout(phStoreHandles[0]);
//        if (ret) {
//            LOGE("退出登录失败 ===> %x", ret);
//        }
//        QCard_FreeStoreHandle(phStoreHandles); // 关闭枚举句柄
//    }
//
//    phStoreHandles = nullptr;
//    hKeyHandle = nullptr;
//    KeyParam.PaddingType = 0;
//}
//
//extern "C"
//JNIEXPORT jstring JNICALL
//Java_com_qasky_tfcard_TFCard_getStoreId(JNIEnv *env, jobject thiz) {
//    int ret = 0;
//    char storeId[64] = {0};
//
//    ret = QCard_GetStoreId(phStoreHandles[0], storeId);  // 获取设备序列号
//    if (ret) {
//        LOGE("获取设备序列号错误 ===> %x", ret);
//        return JNI_FALSE;
//    }
//
//    return env->NewStringUTF(storeId);
//}
//
//extern "C"
//JNIEXPORT jintArray JNICALL
//Java_com_qasky_tfcard_TFCard_queryKeyLength(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jstring store_id) {
//    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
//        LOGE("设备句柄为空");
//        return nullptr;
//    }
//
//    int ret = 0;
//
//    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
//    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
//    char *storeId = const_cast<char *>(env->GetStringUTFChars(store_id, JNI_FALSE));
//    unsigned long uiKeyTotalLen = 0, uiKeyUsedLen = 0;
//    ret = QCard_QueryKey(phStoreHandles[0], storeId, pcAppName, pcConName, &uiKeyTotalLen, &uiKeyUsedLen);
//    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
//    env->ReleaseStringUTFChars(pc_container_name, pcConName);
//    env->ReleaseStringUTFChars(store_id, storeId);
//
//    if (ret) {
//        LOGE("查询密钥错误 ===> %x", ret);
//        return nullptr;
//    }
//
//    unsigned long c_arr[] = {uiKeyTotalLen, uiKeyUsedLen, uiKeyTotalLen - uiKeyUsedLen};
//    jintArray j_arr = env->NewIntArray(3);
//    env->SetIntArrayRegion(j_arr, 0, 3, reinterpret_cast<const jint *>(c_arr));
//
//    return j_arr;
//}
//
//extern "C"
//JNIEXPORT jboolean JNICALL
//Java_com_qasky_tfcard_TFCard_onlineChargingKey(JNIEnv *env, jobject thiz, jstring pc_addr, jstring pc_app_name, jstring pc_container_name, jstring pc_user_pin) {
//    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
//        LOGE("设备句柄为空");
//        return JNI_FALSE;
//    }
//
//    int ret = 0;
//
//    char *pcAddr = const_cast<char *>(env->GetStringUTFChars(pc_addr, JNI_FALSE));
//    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
//    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
//    char *pcUserPin = const_cast<char *>(env->GetStringUTFChars(pc_user_pin, JNI_FALSE));
//    ret = QCard_ProxyOnlineChargingKey(phStoreHandles[0], pcAddr, pcAppName, pcConName, pcUserPin, 2048);
//    env->ReleaseStringUTFChars(pc_addr, pcAddr);
//    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
//    env->ReleaseStringUTFChars(pc_container_name, pcConName);
//    env->ReleaseStringUTFChars(pc_user_pin, pcUserPin);
//
//    if (ret) {
//        LOGE("充注密钥失败 ===> %x", ret);
//        return JNI_FALSE;
//    }
//
//    return JNI_TRUE;
//}
//
//extern "C"
//JNIEXPORT jboolean JNICALL
//Java_com_qasky_tfcard_TFCard_mockC2SNegotiateKey(JNIEnv *env, jobject thiz, jstring pc_addr, jstring pc_app_name, jstring pc_container_name, jstring store_id, jobject c2s_negotiate_info) {
//    if (store_id == nullptr) {
//        LOGE("设备序列号为空");
//        return JNI_FALSE;
//    }
//
//    int ret = 0;
//
//    char *pcAddr = const_cast<char *>(env->GetStringUTFChars(pc_addr, JNI_FALSE));
//    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
//    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
//    char *storeId = const_cast<char *>(env->GetStringUTFChars(store_id, JNI_FALSE));
//
//    char *pcFlag = nullptr;
//    char pcCheckCode[64] = {0};
//    unsigned char pucKey[16] = {0};
//    unsigned char pucSoftKey[128] = {0};
//
//    ret = QCard_RequestCTSKeyByApp(pcAddr, storeId, pcAppName, pcConName, 16, pucKey, pucSoftKey, &pcFlag, pcCheckCode);
//
//    env->ReleaseStringUTFChars(pc_addr, pcAddr);
//    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
//    env->ReleaseStringUTFChars(pc_container_name, pcConName);
//    env->ReleaseStringUTFChars(store_id, storeId);
//
//    if (ret) {
//        LOGE("CTS密钥协商错误 ===> %x", ret);
//        return JNI_FALSE;
//    }
//
//    LOGD("硬密钥（C2S协商）：");
//    LOG_DATA(pucKey, 16);
//    LOGD("软密钥（C2S协商）：");
//    LOG_DATA(pucSoftKey, 16);
//
//    jbyteArray key = env->NewByteArray(16);
//    env->SetByteArrayRegion(key, 0, 16, reinterpret_cast<const jbyte *>(pucKey));
//    jbyteArray softKey = env->NewByteArray(16);
//    env->SetByteArrayRegion(softKey, 0, 16, reinterpret_cast<const jbyte *>(pucSoftKey));
//    jstring flag = env->NewStringUTF(pcFlag);
//    jstring checkCode = env->NewStringUTF(pcCheckCode);
//
//    jclass jclz_c2sNegotiateInfo = env->GetObjectClass(c2s_negotiate_info);
//    jmethodID jmid_setKey = env->GetMethodID(jclz_c2sNegotiateInfo, "setKey", "([B)V");
//    jmethodID jmid_setSoftKey = env->GetMethodID(jclz_c2sNegotiateInfo, "setSoftKey", "([B)V");
//    jmethodID jmid_setFlag = env->GetMethodID(jclz_c2sNegotiateInfo, "setFlag", "(Ljava/lang/String;)V");
//    jmethodID jmid_setCheckCode = env->GetMethodID(jclz_c2sNegotiateInfo, "setCheckCode", "(Ljava/lang/String;)V");
//
//    env->CallVoidMethod(c2s_negotiate_info, jmid_setKey, key);
//    env->CallVoidMethod(c2s_negotiate_info, jmid_setSoftKey, softKey);
//    env->CallVoidMethod(c2s_negotiate_info, jmid_setFlag, flag);
//    env->CallVoidMethod(c2s_negotiate_info, jmid_setCheckCode, checkCode);
//
////    env->DeleteLocalRef(key);
////    env->DeleteLocalRef(softKey);
////    env->ReleaseStringUTFChars(flag, pcFlag);
////    env->ReleaseStringUTFChars(checkCode, pcCheckCode);
//
//    if (pcFlag != nullptr) {
//        free(pcFlag);
//        pcFlag = nullptr;
//    }
//
//    return JNI_TRUE;
//}
//
//extern "C"
//JNIEXPORT jboolean JNICALL
//Java_com_qasky_tfcard_TFCard_getKeyHandle(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jstring pc_user_pin, jstring pc_check_code, jstring pc_flag) {
//    int ret = 0;
//    memset(&KeyParam, 0, sizeof(KeyParam));
//
//    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
//    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
//    char *pcUserPin = const_cast<char *>(env->GetStringUTFChars(pc_user_pin, JNI_FALSE));
//    char *pcCheckCode = const_cast<char *>(env->GetStringUTFChars(pc_check_code, JNI_FALSE));
//    char *pcFlag = const_cast<char *>(env->GetStringUTFChars(pc_flag, JNI_FALSE));
//    ret = QCard_ClientKeyInit(phStoreHandles[0], pcCheckCode, pcFlag, SGD_SMS4_ECB, KeyParam, pcAppName, pcConName, pcUserPin, TAC_SAFE_CLEARR, &hKeyHandle);
//    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
//    env->ReleaseStringUTFChars(pc_container_name, pcConName);
//    env->ReleaseStringUTFChars(pc_user_pin, pcUserPin);
//    env->ReleaseStringUTFChars(pc_check_code, pcCheckCode);
//    env->ReleaseStringUTFChars(pc_flag, pcFlag);
//
//    if (ret) {
//        LOGE("获取密钥句柄错误 ===> %x", ret);
//        return JNI_FALSE;
//    }
//
//    return JNI_TRUE;
//}
//
//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_qasky_tfcard_TFCard_getSoftKey(JNIEnv *env, jobject thiz) {
//    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
//        LOGE("设备句柄为空");
//        return nullptr;
//    }
//    if (hKeyHandle == nullptr) {
//        LOGE("密钥句柄为空");
//        return nullptr;
//    }
//
//    int ret = 0;
//    unsigned char pucSoftKey[16] = {0};
//    unsigned long pucSoftKeyLen = sizeof(pucSoftKey);
//
//    ret = QCard_ExportKey(phStoreHandles[0], hKeyHandle, pucSoftKey, &pucSoftKeyLen);
//    if (ret) {
//        LOGE("获取软密钥错误 ===> %x", ret);
//        return nullptr;
//    }
//
//    LOGD("软密钥（设备导出）：");
//    LOG_DATA(pucSoftKey, 16);
//
//    jbyteArray softKey = env->NewByteArray(16);
//    env->SetByteArrayRegion(softKey, 0, 16, reinterpret_cast<const jbyte *>(pucSoftKey));
//
//    return softKey;
//}

//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_qasky_tfcard_TFCard_hardEncrypt(JNIEnv *env, jobject thiz, jbyteArray data) {
//    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
//        LOGE("设备句柄为空");
//        return nullptr;
//    }
//
//    if (hKeyHandle == nullptr) {
//        LOGE("密钥句柄为空");
//        return nullptr;
//    }
//
//    int ret = 0;
//
//    long len_src = env->GetArrayLength(data);
//    jbyte *data_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
//    unsigned char *data_src = reinterpret_cast<unsigned char *>(data_src_jbyte);
//
//    unsigned char data_dest[len_src];
//    unsigned long len_dest = len_src;
//    memset(data_dest, 0, sizeof(data_dest));
//
//    ret = QCard_Encrypt(phStoreHandles[0], hKeyHandle, data_src, len_src, data_dest, &len_dest);
//
//    env->ReleaseByteArrayElements(data, data_src_jbyte, JNI_FALSE);
//
//    if (ret) {
//        LOGE("硬加密失败 ===> %x", ret);
//        return nullptr;
//    }
//
//    jbyteArray j_data_dest = env->NewByteArray(len_src);
//    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));
//
//    return j_data_dest;
//}
//
//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_qasky_tfcard_TFCard_hardDecrypt(JNIEnv *env, jobject thiz, jbyteArray data) {
//    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
//        LOGE("设备句柄为空");
//        return nullptr;
//    }
//
//    if (hKeyHandle == nullptr) {
//        LOGE("密钥句柄为空");
//        return nullptr;
//    }
//
//    int ret = 0;
//
//    long len_src = env->GetArrayLength(data);
//    jbyte *data_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
//    unsigned char *data_src = reinterpret_cast<unsigned char *>(data_src_jbyte);
//
//    unsigned char data_dest[len_src];
//    unsigned long len_dest = len_src;
//    memset(data_dest, 0, sizeof(data_dest));
//
//    ret = QCard_Decrypt(phStoreHandles[0], hKeyHandle, data_src, len_src, data_dest, &len_dest);
//
//    env->ReleaseByteArrayElements(data, data_src_jbyte, JNI_FALSE);
//
//    if (ret) {
//        LOGE("硬解密失败 ===> %x", ret);
//        return nullptr;
//    }
//
//    jbyteArray j_data_dest = env->NewByteArray(len_src);
//    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));
//
//    return j_data_dest;
//}
//
//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_qasky_tfcard_TFCard_sm4SoftEncrypt(JNIEnv *env, jobject thiz, jbyteArray data, jbyteArray key) {
//    int ret = 0;
//
//    long len_src = env->GetArrayLength(data);
//    jbyte *daata_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
//    unsigned char *data_src = reinterpret_cast<unsigned char *>(daata_src_jbyte);
//    unsigned char *pucKey = reinterpret_cast<unsigned char *>(env->GetByteArrayElements(key, JNI_FALSE));
//
//    qalg_sm4_block_cipher_param qalgSm4BlockCipherParam;
//    memset(&qalgSm4BlockCipherParam, 0, sizeof(qalgSm4BlockCipherParam));
//    qalgSm4BlockCipherParam.alg_id = 1;
//
//    unsigned char data_dest[len_src];
//    unsigned long len_dest = len_src;
//    memset(data_dest, 0, sizeof(data_dest));
//
//    ret = qalg_sm4_encrypt(pucKey, qalgSm4BlockCipherParam, data_src, len_src, data_dest, &len_dest);
//    env->ReleaseByteArrayElements(data, daata_src_jbyte, JNI_FALSE);
//    env->ReleaseByteArrayElements(key, reinterpret_cast<jbyte *>(pucKey), JNI_FALSE);
//
//    if (ret) {
//        LOGE("SM4软加密失败 ===> %x", ret);
//        return nullptr;
//    }
//
//    jbyteArray j_data_dest = env->NewByteArray(len_src);
//    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));
//
//    return j_data_dest;
//}
//
//extern "C"
//JNIEXPORT jbyteArray JNICALL
//Java_com_qasky_tfcard_TFCard_sm4SoftDecrypt(JNIEnv *env, jobject thiz, jbyteArray data, jbyteArray key) {
//    int ret = 0;
//
//    long len_src = env->GetArrayLength(data);
//    jbyte *data_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
//    unsigned char *data_src = reinterpret_cast<unsigned char *>(data_src_jbyte);
//    unsigned char *pucKey = reinterpret_cast<unsigned char *>(env->GetByteArrayElements(key, JNI_FALSE));
//
//    unsigned char data_dest[len_src];
//    unsigned long len_dest = len_src;
//    memset(data_dest, 0, sizeof(data_dest));
//
//    qalg_sm4_block_cipher_param qalgSm4BlockCipherParam;
//    memset(&qalgSm4BlockCipherParam, 0, sizeof(qalgSm4BlockCipherParam));
//    qalgSm4BlockCipherParam.alg_id = 1;
//
//    ret = qalg_sm4_decrypt(pucKey, qalgSm4BlockCipherParam, data_src, len_src, data_dest, &len_dest);
//    env->ReleaseByteArrayElements(data, data_src_jbyte, JNI_FALSE);
//
//    if (ret) {
//        LOGE("SM4软解密失败 ===> %x", ret);
//        return nullptr;
//    }
//
//    jbyteArray j_data_dest = env->NewByteArray(len_src);
//    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));
//    env->ReleaseByteArrayElements(key, reinterpret_cast<jbyte *>(pucKey), JNI_FALSE);
//
//    return j_data_dest;
//}
