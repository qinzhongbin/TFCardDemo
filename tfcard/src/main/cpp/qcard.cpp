#include <jni.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <android/log.h>
#include <qcard.h>
#include <cstring>
#include <curl/curl.h>
#include <iostream>
#include <log.h>
#include <skf.h>
#include "SdCryptoStor.h"

QHANDLES devHandles;
QHANDLE devHandle;

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_enumDevice(JNIEnv *env, jobject thiz, jstring pkg_name) {
    char *pkgName = const_cast<char *>(env->GetStringUTFChars(pkg_name, JNI_FALSE));
    char appPath[128];
    snprintf(appPath, 128, "%s%s", "Android/data/", pkgName);

    devHandles = nullptr;
    int ret = QCard_Android_EnumStoreHandle(&devHandles, pkgName, appPath);
    LOGD("QCard_Android_EnumStoreHandle ret = %X devHandles = %p", ret, devHandles);

    env->ReleaseStringUTFChars(pkg_name, pkgName);

    if (ret > 0) {
        // 默认只取第一个
        devHandle = devHandles[0];
        LOGD("devHandle = %p", devHandle);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_freeDevices(JNIEnv *env, jobject thiz) {
    QCard_FreeStoreHandle(devHandles);
    LOGD("QCard_FreeStoreHandle");
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_loginDevice(JNIEnv *env, jobject thiz) {
    int ret = QCard_Login(devHandle);
    LOGD("QCard_Login ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_logoutDevice(JNIEnv *env, jobject thiz) {
    int ret = QCard_Logout(devHandle);
    LOGD("QCard_Logout ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_initResource(JNIEnv *env, jobject thiz) {
    int ret = QCard_InitResource(devHandle);
    LOGD("QCard_InitResource ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_updateResource(JNIEnv *env, jobject thiz) {
    int ret = QCard_UpdateResource(devHandle);
    LOGD("QCard_UpdateResource ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_destroyResource(JNIEnv *env, jobject thiz) {
    QCard_DestoryResource(devHandle);
    LOGD("QCard_DestoryResource");
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_getDeviceId(JNIEnv *env, jobject thiz) {
    char storeId[64] = {0};
    int ret = QCard_GetStoreId(devHandle, storeId);
    LOGD("QCard_GetStoreId ret = %X storeId = %s", ret, storeId);
    return env->NewStringUTF(storeId);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_getSystemId(JNIEnv *env, jobject thiz, jstring app_name, jstring con_name) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char systemId[64] = {0};
    int ret = QCard_GetSysTemId(devHandle, appName, conName, systemId);
    LOGD("QCard_GetSysTemId ret = %X systemId = %s", ret, systemId);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return env->NewStringUTF(systemId);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_qasky_tfcard_QTF_queryKeyLength(JNIEnv *env, jobject thiz, jstring device_id, jstring app_name, jstring con_name) {
    char *deviceId = const_cast<char *>(env->GetStringUTFChars(device_id, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    unsigned long totalLen = 0;
    unsigned long usedLen = 0;

    int ret = QCard_QueryKey(devHandle, deviceId, appName, conName, &totalLen, &usedLen);
    LOGD("QCard_QueryKey ret = %X totalLen = %lu usedLen = %lu", ret, totalLen, usedLen);

    env->ReleaseStringUTFChars(device_id, deviceId);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return (int) (totalLen - usedLen);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_chargeKey(JNIEnv *env, jobject thiz, jstring _host, jstring app_name, jstring con_name, jstring user_pin) {
    char *host = const_cast<char *>(env->GetStringUTFChars(_host, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *userPIN = const_cast<char *>(env->GetStringUTFChars(user_pin, JNI_FALSE));

    int ret = QCard_ProxyOnlineChargingKey(devHandle, host, appName, conName, userPIN, 1024);
    LOGD("QCard_ProxyOnlineChargingKey ret = %X", ret);

    env->ReleaseStringUTFChars(_host, host);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(user_pin, userPIN);

    return !ret;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_qasky_tfcard_QTF_getKeyHandle(JNIEnv *env, jobject thiz, jstring app_name, jstring con_name, jstring user_pin, jstring check_code, jstring _flag) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *userPin = const_cast<char *>(env->GetStringUTFChars(user_pin, JNI_FALSE));
    char *checkCode = const_cast<char *>(env->GetStringUTFChars(check_code, JNI_FALSE));
    char *flag = const_cast<char *>(env->GetStringUTFChars(_flag, JNI_FALSE));
    QCard_BLOCKCIPHERPARAM KeyParam;
    memset(&KeyParam, 0, sizeof(KeyParam));
    KeyParam.PaddingType = 1;
    KEYHANDLE keyHandle = nullptr;

    int ret = QCard_ClientKeyInit(devHandle, checkCode, flag, SGD_SMS4_ECB, KeyParam, appName, conName, userPin, TAC_SAFE_CLEARR, &keyHandle);
    LOGD("QCard_ClientKeyInit ret = %X keyHandle = %p", ret, keyHandle);

    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(user_pin, userPin);
    env->ReleaseStringUTFChars(check_code, checkCode);
    env->ReleaseStringUTFChars(_flag, flag);
    return reinterpret_cast<jlong>(keyHandle);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_qasky_tfcard_QTF_importExternalSessionKey(JNIEnv *env, jobject thiz, jbyteArray _key) {
    long keyLen = env->GetArrayLength(_key);
    jbyte *jbp_key = env->GetByteArrayElements(_key, JNI_FALSE);
    auto *key = (unsigned char *) jbp_key;

    QCard_BLOCKCIPHERPARAM KeyParam;
    KEYHANDLE keyHandle = nullptr;

    memset(&KeyParam, 0, sizeof(KeyParam));
    KeyParam.PaddingType = 1;
    KeyParam.IVLen = 16;
    int ret = QCard_ExternalKeyInit(devHandle, key, keyLen, SGD_SMS4_CBC, KeyParam, &keyHandle);
    LOGD("QCard_ExternalKeyInit ret = %X keyHandle = %p", ret, keyHandle);

    env->ReleaseByteArrayElements(_key, jbp_key, JNI_FALSE);

    return reinterpret_cast<jlong>(keyHandle);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_freeKeyHandle(JNIEnv *env, jobject thiz, jlong key_handle) {
    QCard_KeyFinal(devHandle, reinterpret_cast<KEYHANDLE>(key_handle));
    LOGD("QCard_KeyFinal");
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_getSoftKey(JNIEnv *env, jobject thiz, jlong key_handle, jlong key_len) {
    unsigned char softKey[key_len];
    memset(softKey, 0, key_len);

    int ret = QCard_ExportKey(devHandle, reinterpret_cast<KEYHANDLE>(key_handle), softKey, reinterpret_cast<unsigned long *>(&key_len));
    LOGD("QCard_ExportKey ret = %X softKey = %s", ret, ByteArrayToHexStr(softKey, key_len));

    jbyteArray jbyteArray_softKey = env->NewByteArray(key_len);
    env->SetByteArrayRegion(jbyteArray_softKey, 0, key_len, reinterpret_cast<const jbyte *>(softKey));
    return jbyteArray_softKey;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_encrypt(JNIEnv *env, jobject thiz, jlong key_handle, jbyteArray plain) {
    long srcLen = env->GetArrayLength(plain);
    jbyte *src = env->GetByteArrayElements(plain, JNI_FALSE);
    auto *srcData = (unsigned char *) src;
    unsigned long destLen = srcLen + 16;
    unsigned char destData[destLen];
    memset(destData, 0, destLen);

    int ret = QCard_Encrypt(devHandle, reinterpret_cast<KEYHANDLE>(key_handle), srcData, srcLen, destData, &destLen);
    LOGD("QCard_Encrypt ret = %X", ret);
    LOGD("QCard_Encrypt plain = %s", ByteArrayToHexStr(srcData, srcLen));
    LOGD("QCard_Encrypt cipher = %s", ByteArrayToHexStr(destData, destLen));

    jbyteArray jbyteArray_dest = env->NewByteArray(destLen);
    env->SetByteArrayRegion(jbyteArray_dest, 0, destLen, reinterpret_cast<const jbyte *>(destData));
    env->ReleaseByteArrayElements(plain, src, JNI_FALSE);
    return jbyteArray_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_decrypt(JNIEnv *env, jobject thiz, jlong key_handle, jbyteArray cipher) {
    long srcLen = env->GetArrayLength(cipher);
    jbyte *src = env->GetByteArrayElements(cipher, JNI_FALSE);
    auto *srcData = (unsigned char *) src;
    unsigned long destLen = srcLen;
    unsigned char destData[destLen];
    memset(destData, 0, sizeof(destData));

    int ret = QCard_Decrypt(devHandle, reinterpret_cast<KEYHANDLE>(key_handle), srcData, srcLen, destData, &destLen);
    LOGD("QCard_Decrypt ret = %X", ret);
    LOGD("QCard_Decrypt cipher = %s", ByteArrayToHexStr(srcData, srcLen));
    LOGD("QCard_Decrypt plain = %s", ByteArrayToHexStr(destData, destLen));

    jbyteArray jbyteArray_dest = env->NewByteArray(destLen);
    env->SetByteArrayRegion(jbyteArray_dest, 0, destLen, reinterpret_cast<const jbyte *>(destData));

    env->ReleaseByteArrayElements(cipher, src, JNI_FALSE);
    return jbyteArray_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_exportCert(JNIEnv *env, jobject thiz, jint type, jstring app_name, jstring con_name) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    unsigned long certLen = 0, timeOut = 0;

    int ret = QCard_ExportCertificate(devHandle, appName, conName, type, nullptr, &certLen, &timeOut);
    LOGD("QCard_ExportCertificate ret = %X certLen = %lu", ret, certLen);
    unsigned char cert[certLen];
    memset(cert, 0, certLen);
    ret = QCard_ExportCertificate(devHandle, appName, conName, type, cert, &certLen, &timeOut);
    LOGD("QCard_ExportCertificate ret = %X cert = %s", ret, ByteArrayToHexStr(cert, certLen));

    jbyteArray jbyteArray_cert = env->NewByteArray(certLen);
    env->SetByteArrayRegion(jbyteArray_cert, 0, certLen, reinterpret_cast<const jbyte *>(cert));
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return jbyteArray_cert;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_exportPubKey(JNIEnv *env, jobject thiz, jint type, jstring app_name, jstring con_name) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    unsigned long keyLen = 0;

    int ret = QCard_ExportPublicKey(devHandle, appName, conName, type, nullptr, &keyLen);
    LOGD("QCard_ExportPublicKey ret = %X keyLen = %lu", ret, keyLen);
    unsigned char key[keyLen];
    memset(key, 0, keyLen);
    ret = QCard_ExportPublicKey(devHandle, appName, conName, type, key, &keyLen);
    LOGD("QCard_ExportPublicKey ret = %X key = %s", ret, ByteArrayToHexStr(key, keyLen));

    jbyteArray jbyteArray_key = env->NewByteArray(keyLen);
    env->SetByteArrayRegion(jbyteArray_key, 0, keyLen, reinterpret_cast<const jbyte *>(key));
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return jbyteArray_key;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_verifyAppPIN(JNIEnv *env, jobject thiz, jstring app_name, jstring _pin) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *pin = const_cast<char *>(env->GetStringUTFChars(_pin, JNI_FALSE));
    unsigned long retryCount;

    int ret = QCard_VerifyAppPIN(devHandle, appName, pin, &retryCount);
    LOGD("QCard_VerifyAppPIN ret = %X retryCount = %lu", ret, retryCount);

    env->ReleaseStringUTFChars(app_name, appName);
    return !ret;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_qasky_tfcard_QTF_negoOLBizKey(JNIEnv *env, jobject thiz, jstring _host, jstring device_id, jstring system_id, jstring secret_id, jstring server_id, jstring visit_key_base64, jstring protect_key) {
    char *host = const_cast<char *>(env->GetStringUTFChars(_host, JNI_FALSE));
    char *deviceId = const_cast<char *>(env->GetStringUTFChars(device_id, JNI_FALSE));
    char *systemId = const_cast<char *>(env->GetStringUTFChars(system_id, JNI_FALSE));
    char *secretId = const_cast<char *>(env->GetStringUTFChars(secret_id, JNI_FALSE));
    char *serverId = const_cast<char *>(env->GetStringUTFChars(server_id, JNI_FALSE));
    char *visitKeyBase64 = const_cast<char *>(env->GetStringUTFChars(visit_key_base64, JNI_FALSE));
    char *protectKey = const_cast<char *>(env->GetStringUTFChars(protect_key, JNI_FALSE));
    char *flag = nullptr;
    char checkCode[64] = {0};

    int ret = QCard_ClientRequestOnlineBizKey(host, deviceId, systemId, secretId, serverId, visitKeyBase64, reinterpret_cast<const unsigned char *>(protectKey), &flag, checkCode);
    LOGD("QCard_ClientRequestOnlineBizKey ret = %X \nflag = \n%s\ncheckCode = %s", ret, flag, checkCode);

    env->ReleaseStringUTFChars(_host, host);
    env->ReleaseStringUTFChars(device_id, deviceId);
    env->ReleaseStringUTFChars(system_id, systemId);
    env->ReleaseStringUTFChars(secret_id, secretId);
    env->ReleaseStringUTFChars(server_id, serverId);
    env->ReleaseStringUTFChars(visit_key_base64, visitKeyBase64);
    env->ReleaseStringUTFChars(protect_key, protectKey);

    if (ret) {
        return nullptr;
    } else {
        jclass clz_NegotiateInfo = env->FindClass("com/qasky/tfcard/NegotiateInfo");
        jobject obj_NegotiateInfo = env->NewObject(clz_NegotiateInfo, env->GetMethodID(clz_NegotiateInfo, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V"), env->NewStringUTF(flag), env->NewStringUTF(checkCode));
        return obj_NegotiateInfo;
    }
}

//extern "C"
//JNIEXPORT jlong JNICALL
//Java_com_qasky_tfcard_QTF_negoOLKey(JNIEnv *env, jobject thiz) {
//    auto devHandle = devHandle;
//
//    char appName[] = "QSKCTS";
//    char conName[] = "QSKCTS";
//    char pin[] = "12222222";
//
//    char qccsId[] = "WT-QRMS100-20201116";
//    char id[] = "WT-QKMS100_001";
//    char visitKeyBase64[] = "JLz3wNv1g8cTbiOBMaE+xl+lEzvqeqYKghYk+rJZxAa8c+Aq8VCeMxi7u0a7vaHVWOjuePeXoM7JFEeAZy64xA==";
//    char protectKey[] = "123456";
//    char host[] = "112.27.97.202:18895";
//
//    char linkId[64] = {0};
//    char keyId[64] = {0};
//    unsigned char flagChkV[16] = {0};
//    char flag[512] = {0};
//
//    void *secTunnelHandle;
//
//    unsigned long keyLen = 16;
//    unsigned int cipherQKeyLen = (keyLen / 16) * 272;
//    auto *cipherQKey = (unsigned char *) malloc(cipherQKeyLen);
//    memset(cipherQKey, 0, cipherQKeyLen);
//
//    int offerSoftKey = 0;
//
//    // 服务端 创建安全通道，代理协商密钥
//    int ret = QCard_SetServerAuthorizeKey(visitKeyBase64, protectKey);
//    LOGD("QCard_SetServerAuthorizeKey ret = %08x", ret);
//    void *arg = nullptr;
//    ret = QCard_CreateSecTunnel(PROTOCOL_TYPE_TCP, host, qccsId, id, arg, &secTunnelHandle);
//    LOGD("QCard_CreateSecTunnel ret = %08x secTunnelHandle = %p", ret, secTunnelHandle);
//
//    char devId[64] = {0};
//    ret = QCard_GetStoreId(devHandle, devId);
//    LOGD("QCard_GetStoreId ret = %08x devId = %s", ret, devId);
//
//    ret = QCard_GetLinkId(secTunnelHandle, devId, qccsId, linkId);
//    LOGD("QCard_GetLinkId ret = %08x linkId = %s", ret, linkId);
//
//    char systemId[32] = {0};
//    ret = QCard_GetSysTemId(devHandle, appName, conName, systemId);
//    LOGD("QCard_GetSysTemId ret = %08x systemId = %s", ret, systemId);
//
//    ret = QCard_ServerProxyRequestQkey(secTunnelHandle, devId, linkId, systemId, keyLen, keyId, flagChkV, flag, &offerSoftKey, cipherQKey, &cipherQKeyLen);
//    LOGD("QCard_ServerProxyRequestQkey ret = %X", ret);
//    LOGD("QCard_ServerProxyRequestQkey devId = %s", devId);
//    LOGD("QCard_ServerProxyRequestQkey linkId = %s", linkId);
//    LOGD("QCard_ServerProxyRequestQkey systemId = %s", systemId);
//    LOGD("QCard_ServerProxyRequestQkey keyLen = %lu", keyLen);
//    LOGD("QCard_ServerProxyRequestQkey keyId = %s", keyId);
//    LOGD("QCard_ServerProxyRequestQkey flagChkV = %s", ByteArrayToHexStr(flagChkV, 16));
//    LOGD("QCard_ServerProxyRequestQkey flag = %s", flag);
//    LOGD("QCard_ServerProxyRequestQkey offerSoftKey = %d", offerSoftKey);
//    LOGD("QCard_ServerProxyRequestQkey cipherQKey = %s", ByteArrayToHexStr(cipherQKey, cipherQKeyLen));
//    LOGD("QCard_ServerProxyRequestQkey cipherQKeyLen = %d", cipherQKeyLen);
//
//    unsigned int qkeyReadLen = 256;
//    auto *qkeyRead = (unsigned char *) calloc(1, qkeyReadLen);
//    ret = QCard_ReadQKey(secTunnelHandle, keyId, qkeyRead, &qkeyReadLen);
//    LOGD("QCard_ReadQKey ret = %08x qkeyReadLen = %d qkeyRead = %s", ret, qkeyReadLen, ByteArrayToHexStr(qkeyRead, qkeyReadLen));
//
//    QCard_DestroySecTunnel(secTunnelHandle);
//
//    // 客户端 根据协商参数获取密钥句柄
//    KEYHANDLE keyHandle = nullptr;
//    unsigned int plainKeyLen = 16;
//
//    if (1 == offerSoftKey) {
//        unsigned int qkeyLen = plainKeyLen;
//        auto *qkey = static_cast<unsigned char *>(malloc(qkeyLen));
//
//        ret = QCard_ClientGetQkey(devHandle, qccsId, systemId, pin, flagChkV, flag, offerSoftKey, cipherQKey, cipherQKeyLen, qkey, &qkeyLen);
//        LOGD("QCard_ClientGetQkey ret = %08x qkeyLen = %d qkey = %s", ret, qkeyLen, ByteArrayToHexStr(qkey, qkeyLen));
//
//        ret = char_array_cmp(reinterpret_cast<char *>(qkeyRead), (int) qkeyReadLen, reinterpret_cast<char *>(qkey), (int) qkeyLen);
//        LOGD("compare key ret = %d", ret);
//
//        QCard_BLOCKCIPHERPARAM KeyParam;
//        memset(&KeyParam, 0, sizeof(KeyParam));
//        KeyParam.PaddingType = 1;
//        KeyParam.IVLen = 16;
//
//        ret = QCard_ExternalKeyInit(devHandle, qkey, qkeyLen, SGD_SMS4_CBC, KeyParam, &keyHandle);
//        LOGD("QCard_ExternalKeyInit ret = %08x keyHandle = %p", ret, keyHandle);
//
//        unsigned long tryTimes = 0;
//        ret = QCard_KeyToConVerifyPIN(devHandle, keyHandle, appName, conName, pin, &tryTimes);
//        LOGD("QCard_KeyToConVerifyPIN ret = %08x tryTimes = %lu", ret, tryTimes);
//
////        QCard_KeyFinal(devHandle, keyHandle);
////        LOGD("QCard_KeyFinal");
//    } else {
//        DEVQKEYPARAM devKeyParam = nullptr;
//        unsigned int qKeyNum = 0;
//
//        ret = QCard_ClientGetDeviceQkey(devHandle, qccsId, systemId, pin, flagChkV, flag, offerSoftKey, cipherQKey, cipherQKeyLen, plainKeyLen, &devKeyParam, &qKeyNum);
//        LOGD("QCard_ClientGetDeviceQkey ret = %08x", ret);
//
//        QCard_BLOCKCIPHERPARAM KeyParam;
//        memset(&KeyParam, 0, sizeof(KeyParam));
//        KeyParam.PaddingType = 1;
//        KeyParam.IVLen = 16;
//        auto *keyHandles = (KEYHANDLE *) malloc(qKeyNum * sizeof(KEYHANDLE));
//        memset(keyHandles, 0, qKeyNum * sizeof(KEYHANDLE));
//
//        ret = QCard_deviceQKeyHandlesInit(devHandle, devKeyParam, 0, qKeyNum, SGD_SMS4_CBC, KeyParam, keyHandles);
//        keyHandle = keyHandles[0];
//        LOGD("QCard_deviceQKeyHandlesInit ret = %08x keyHandle = %p", ret, keyHandle);
//
////        QCard_DestroyDevQkeyParam(devKeyParam);
////        LOGD("QCard_DestroyDevQkeyParam ret = %08x", ret);
////
////        QCard_DestroyDeviceKeyHandles(devHandle, keyHandles, qKeyNum);
////        LOGD("QCard_DestroyDeviceKeyHandles ret = %08x", ret);
//    }
//
//    unsigned long plainLen = 16;
//    unsigned char plain[] = "1234567890123456";
//
//    unsigned long cipherLen = plainLen + 16;
//    unsigned char cipher[cipherLen];
//    memset(cipher, 0, cipherLen);
//
//    ret = QCard_Encrypt(devHandle, keyHandle, plain, plainLen, cipher, &cipherLen);
//    LOGD("QCard_Encrypt ret = %08x cipherLen = %lu cipher = %s", ret, cipherLen, ByteArrayToHexStr(cipher, cipherLen));
//
//    unsigned long destLen = cipherLen;
//    unsigned char dest[destLen];
//    memset(dest, 0, sizeof(dest));
//
//    ret = QCard_Decrypt(devHandle, keyHandle, cipher, cipherLen, dest, &destLen);
//    LOGD("QCard_Decrypt ret = %X destLen = %lu dest = %s", ret, destLen, ByteArrayToHexStr(dest, destLen));
//
//    ret = char_array_cmp(reinterpret_cast<char *>(plain), (int) plainLen, reinterpret_cast<char *>(dest), (int) destLen);
//    LOGD("compare enc and dec ret = %d", ret);
//
//    return reinterpret_cast<jlong>(keyHandle);
//}


char *g_szDevName;
void *g_hdev = 0;
void *g_hKey = NULL;
void *g_hKey1 = NULL;


#define DevAuth_PIN "C*CORE SYS @ SZ "

BYTE xData[] = {0x09, 0xf9, 0xdf, 0x31, 0x1e, 0x54, 0x21, 0xa1,
                0x50, 0xdd, 0x7d, 0x16, 0x1e, 0x4b, 0xc5, 0xc6,
                0x72, 0x17, 0x9f, 0xad, 0x18, 0x33, 0xfc, 0x07,
                0x6b, 0xb0, 0x8f, 0xf3, 0x56, 0xf3, 0x50, 0x20};

BYTE yData[] = {0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5,
                0x2d, 0xc6, 0xea, 0x71, 0x8c, 0xc1, 0xaa, 0x60,
                0x0a, 0xed, 0x05, 0xfb, 0xf3, 0x5e, 0x08, 0x4a,
                0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9, 0xad, 0x13};

BYTE pData[] = {0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1,
                0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95,
                0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a,
                0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8};



//#ifdef  __cplusplus
//extern "C" {
//#endif
//extern void sd_CommInit(PUCHAR pucSendHeader, PUCHAR pucRecvHeader, PCHAR pszFileName);
//
//extern int sd_SetPackageName(const char *szPackageName);
//
//extern int sd_EnumDevice(char **szDevNames, DWORD *pulLen);
//
//#ifdef  __cplusplus
//}
//#endif


void getSzDevName() {
    unsigned int i = 0;
    unsigned int ret = 0;
    unsigned int start = 0;
    u32 pulSize = 0;
    char *szNameList = NULL;
    char SzDevName[128] = {0};

    ret = SKF_EnumDev(1, szNameList, &pulSize);
    if (ret) {
        LOGD("%s %d 0x%x\n", __FUNCTION__, __LINE__, ret);
        return;
    }

    if (pulSize > 2) {
        szNameList = (char *) malloc(pulSize);
        if (NULL == szNameList) {
            LOGD("%s %d 0x%x\n", __FUNCTION__, __LINE__, ret);
            return;
        }
        memset(szNameList, 0, pulSize);
    } else {
        LOGD("%s %d 0x%x\n", __FUNCTION__, __LINE__, ret);
        return;
    }

    ret = SKF_EnumDev(1, szNameList, &pulSize);
    if (ret) {
        free(szNameList);
        LOGD("%s %d 0x%x\n", __FUNCTION__, __LINE__, ret);
        return;
    }


    for (i = 1; i <= pulSize; i++) {

        if (0 == szNameList[i - 1]) {
            if (start) {
                sprintf(SzDevName, "%s", &szNameList[start - 1]);
                //LOGD("|%s|\n", SzDevName);

                if (NULL == g_szDevName) {
                    g_szDevName = static_cast<char *>(malloc(strlen(SzDevName) + 1));
                    if (NULL == g_szDevName) {
                        free(szNameList);
                        LOGD("%s %d 0x%x\n", __FUNCTION__, __LINE__, ret);
                        return;
                    }
                    memcpy(g_szDevName, SzDevName, strlen(SzDevName));
                    g_szDevName[strlen(SzDevName)] = '\0';
                }
                start = 0;
            }
        } else {
            if (0 == start) {
                start = i;
            }
        }

    }


    free(szNameList);
    LOGD("%s %d 0x%x\n", __FUNCTION__, __LINE__, ret);
    return;
}

int ImportECCKeyPair(void *hdev, void *hcon) {

    int xlen = 32;
    int ylen = 32;
    int dlen = 32;
    unsigned int ret = 0;
    u32 len = 128;

    HANDLE hKey;
    ECCPUBLICKEYBLOB pub;
    BLOCKCIPHERPARAM bp;

    uint8_t encryptkey[1024] = {0};
    unsigned char keypair[96] = {0};

    uint8_t key[16] = {0x47, 0x50, 0x42, 0x02, 0x20, 0x3F, 0xE1, 0x92, 0x66, 0x2A, 0xCB, 0xD2, 0x9D, 0, 0, 0};

    struct SKF_ENVELOPEDKEYBLOB *env = (struct SKF_ENVELOPEDKEYBLOB *) encryptkey;


    bp.PaddingType = 0;
    bp.IVLen = 0;
    bp.FeedBitLen = 0;

    memset(encryptkey, 0, 1024);

    //sm2_keygen(keypair, &xlen, &keypair[32], &ylen, &keypair[64], &dlen);
    memcpy(keypair, xData, 32);
    memcpy(keypair + 32, yData, 32);
    memcpy(keypair + 64, pData, 32);

    env->Version = 1;
    env->ulBits = 256;
    env->PubKey.BitLen = 256;
    env->ulSymmAlgID = SGD_SMS4_ECB;
    memcpy(env->PubKey.XCoordinate + 32, keypair, 32);
    memcpy(env->PubKey.YCoordinate + 32, keypair + 32, 32);

    len = 1024;
    ret = SKF_ExportPublicKey(hcon, 0, encryptkey, &len);
    if (ret == 0)
        return 0;

    len = sizeof(ECCPUBLICKEYBLOB);
    ret = SKF_ExportPublicKey(hcon, 1, (uint8_t *) &pub, &len);
    if (ret) {
        if (ret == SAR_KEYNOTFOUNTERR) {
            ret = SKF_GenECCKeyPair(hcon, SGD_SM2_1, &pub);
            if (ret) {
                LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
                return ret;
            }
        } else {
            LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
            return ret;
        }
    }

    ret = SKF_ExtECCEncrypt(hdev, &pub, key, 16, &env->ECCCipherBlob);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        return ret;
    }
    ret = SKF_SetSymmKey(hdev, key, SGD_SMS4_ECB, &hKey);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    ret = SKF_EncryptInit(hKey, bp);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    len = 64;
    ret = SKF_Encrypt(hKey, keypair + 64, 32, env->cbEncryptedPriKey + 32, &len);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    ret = SKF_ImportECCKeyPair(hcon, env);
    LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);

    return ret;
}


int DoDevAuth(char *DevAuthPIN) {
    unsigned int l = 32;
    unsigned int ret = 0;
    uint8_t rand[16] = {0};
    uint8_t authdata[32] = {0};
    char ss[12];
    char *szAlgo = NULL;
    DEVINFO info;

    ret = SKF_GetDevInfo(g_hdev, &info);
    if (ret) {
        return ret;
    }
    switch (info.DevAuthAlgId) {
        case SGD_SM1_ECB:
            szAlgo = "SGD_SM1_ECB";
            break;
        case SGD_SMS4_ECB:
            szAlgo = "SGD_SMS4_ECB";
            break;
        default:
            sprintf(ss, "0x%x", info.DevAuthAlgId);
            szAlgo = ss;
    }
    LOGD("%x %x %x\n", info.DevAuthAlgId, SGD_SM1_ECB, SGD_SMS4_ECB);
    if (info.DevAuthAlgId == SGD_SM1_ECB || info.DevAuthAlgId == SGD_SMS4_ECB) {
        HANDLE hKey;
        BLOCKCIPHERPARAM bp;

        bp.IVLen = 0;
        bp.PaddingType = NO_PADDING;
        bp.FeedBitLen = 0;

        ret = SKF_GenRandom(g_hdev, rand, 8);
        if (ret) {
            return ret;
        }

        ret = SKF_SetSymmKey(g_hdev, (uint8_t *) DevAuthPIN, info.DevAuthAlgId, &hKey);
        if (ret) {
            SKF_CloseHandle(hKey);
            return ret;
        }

        ret = SKF_EncryptInit(hKey, bp);
        if (ret) {
            SKF_CloseHandle(hKey);
            return ret;
        }

        ret = SKF_Encrypt(hKey, rand, 16, authdata, &l);
        SKF_CloseHandle(hKey);
        if (ret) {
            return ret;
        }
    } else {
        return 1;
    }
    ret = SKF_DevAuth(g_hdev, authdata, l);
    return ret;
}

int create_app() {
    int trytimes = 0;
    unsigned char tdata[513] = {0};
    unsigned int tdataLen = 512;
    unsigned char digest1[32] = {0};
    unsigned char digest2[32] = {0};
    unsigned char digest3[32] = {0};
    unsigned long ret = 0, len = 0;
    void *sk_dev;
    void *happ;
    void *hcon;
    char pcPin[] = "20201818";
    unsigned int i;
    char szDevName[128] = {0};
    void *happ1;

    ECCPUBLICKEYBLOB tmpECCPUBLICKEYBLOB;

    uint8_t data1[2048] = {0};
    ECCCIPHERBLOB *p_ECCWrappedKey = (ECCCIPHERBLOB *) data1;
    ECCPUBLICKEYBLOB ECCEncryptPubKeyBlob;
    unsigned int ECCEncryptPubKeyBlob_len = sizeof(ECCPUBLICKEYBLOB);

    //删除应用
    ret = SKF_DeleteApplication(g_hdev, "test");
    if (ret && (ret != SAR_APPLICATION_NOT_EXISTS && ret != SAR_FILE_NOT_EXIST)) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }

    DoDevAuth(DevAuth_PIN);

    //创建应用
    ret = SKF_CreateApplication(g_hdev, "test", "1234567812345678",
                                6, "12222222", 6,
                                SECURE_ANYONE_ACCOUNT, &happ);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }

    //校验用户pin码
    ret = SKF_VerifyPIN(happ, USER_TYPE, "12222222", reinterpret_cast<u32 *>(&trytimes));
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }


    //创建容器
    ret = SKF_CreateContainer(happ, "test", &hcon);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }

    //生成签名密钥对
    ret = SKF_GenECCKeyPair(hcon, SGD_SM2_1, &tmpECCPUBLICKEYBLOB);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }

    //导入加密密钥对
    ret = ImportECCKeyPair(g_hdev, hcon);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }


    ret = SKF_ExportPublicKey(hcon, 0, (uint8_t *) &ECCEncryptPubKeyBlob, &ECCEncryptPubKeyBlob_len);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }


#if 0
    ret = SKF_ECCExportSessionKey(hcon, SGD_SM1_ECB, &ECCEncryptPubKeyBlob, p_ECCWrappedKey, &hsess);
    if(ret)
    {
        LOGD("%s %d ret %x\n", __FUNCTION__,__LINE__,ret);
        goto end;
    }
    SKF_CloseHandle(hsess);
#else

    ret = SKF_ExtECCEncrypt(g_hdev, &ECCEncryptPubKeyBlob, (u8 *) "1234567812345678", 16, p_ECCWrappedKey);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        return ret;
    }

#endif

    ret = SKF_CUSTOM_ImportSymmKey(hcon, (BYTE *) p_ECCWrappedKey, sizeof(ECCCIPHERBLOB) + p_ECCWrappedKey->CipherLen - 1);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        return ret;
    }

    end:

    if (hcon) {
        SKF_CloseContainer(hcon);
    }

    if (happ) {
        SKF_CloseApplication(happ);
    }

    return ret;
}


extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_test(JNIEnv *env, jobject thiz) {
    unsigned long ret = 0, len = 0;
    void *sk_dev;
    void *hcon;
    char pcPin[] = "20201818";
    char szDevName[128] = {0};
    void *happ;
    unsigned char key[17] = "1122334455667788";
    unsigned long ulEncryptedLen = 4096;
    unsigned char in[4096] = {0};
    unsigned char outenc[4096] = {0};
    unsigned char outdec[4096] = {0};
    unsigned char plain[] = "hello world";
    int trytimes = 0;
    BLOCKCIPHERPARAM bp;
//        getSzDevName();

    int i;
    u8 *d1 = (u8 *)malloc(100*1024*1024);
    u32 d1Len = 0;
    u8 *d2 = (u8 *)malloc(100*1024*1024+16);
    u32 d2Len = 0;
    int peer_encrypt_len = 1024*100;
    sd_SetPackageName("com.qasky.tfcarddemo");
    V_SetAppPath("Android/data/com.qasky.tfcarddemo");

//    char *bufname = NULL;
    unsigned int ullength = 0;

    sd_EnumDevice(&g_szDevName, reinterpret_cast<DWORD *>(&ullength));
    LOGD("bufname = %s", g_szDevName);
//    return;

    if (NULL == g_szDevName) {
        LOGD("getSzDevName failed\n");
        goto end;
    }

    ret = SKF_ConnectDev(g_szDevName, &g_hdev);
    LOGD("SKF_ConnectDev @ret = 0x%x @g_szDevName=%s\n", ret, g_szDevName);
    if (SAR_OK != ret) {
        goto end;
    }

    ret = DoDevAuth(DevAuth_PIN);
    LOGD("DoDevAuth @ret = 0x%x @g_szDevName=%s\n", ret, g_szDevName);
    if (SAR_OK != ret) {
        goto end;
    }
//    ret = SKF_DeleteApplication(g_hdev, "test");
    ret = SKF_OpenApplication(g_hdev, "test", &happ);
    if (ret) {
        ret = create_app();
        if (ret) {
            LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
            goto end;
        }

        ret = SKF_OpenApplication(g_hdev, "test", &happ);
        if (ret) {
            LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
            goto end;
        }
    }

    ret = SKF_OpenContainer(happ, "test", &hcon);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }

    ret = SKF_SetSymmKey(g_hdev, (u8 *) "1234567812345678", SGD_SMS4_CBC, &g_hKey);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }
    ret = SKF_SetSymmKey(g_hdev, (u8 *) "1234567812345678", SGD_SMS4_CBC, &g_hKey1);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }


    memset(&bp, 0x0, sizeof(bp));

    bp.IVLen = 0;
    bp.PaddingType = 1;
    bp.FeedBitLen = 0;

    //初始化解密句柄
    ret = SKF_EncryptInit(g_hKey, bp);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }

    ret = SKF_DecryptInit(g_hKey1, bp);
    if (ret) {
        LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
        goto end;
    }

    for(i = 01; i < 100*1024*1024; i++)
    {
        d1[i] = i;
    }


    for(i = 1; i* peer_encrypt_len< 100*1024*1024; i++)
    {
        LOGD("%s %d cur encrypt data len is  %u \n", __FUNCTION__, __LINE__, i*peer_encrypt_len);
        d2Len = 100*1024*1024;
        ret = SKF_Encrypt(g_hKey, reinterpret_cast<u8 *>(d1), i * peer_encrypt_len, reinterpret_cast<u8 *>(d2), reinterpret_cast<u32 *>(&d2Len));
        if (ret) {
            LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
            goto end;
        }

        d1Len = 100*1024*1024;
        ret = SKF_Decrypt(g_hKey1, d2, d2Len, d1, &d1Len);
        if (ret) {
            LOGD("%s %d ret %x\n", __FUNCTION__, __LINE__, ret);
            goto end;
        }
    }



end:
    if (d1) {
        free(d1);
    }
    if (d2) {
        free(d2);
    }
    if (g_hKey) {
        SKF_CloseHandle(g_hKey);
    }
    if (g_hKey1) {
        SKF_CloseHandle(g_hKey1);
    }
    if (hcon) {
        SKF_CloseContainer(hcon);
    }

    if (happ) {
        SKF_CloseApplication(happ);
    }

    if (g_hdev) {
        SKF_DisConnectDev(g_hdev);
    }
#ifdef _WIN32
    system("pause");
#endif
}