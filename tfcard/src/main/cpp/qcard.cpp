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

QHANDLES devHandles;

extern "C"
JNIEXPORT jlongArray JNICALL
Java_com_qasky_tfcard_QTF_enumDev(JNIEnv *env, jobject thiz, jstring pkg_name) {
    char *pkgName = const_cast<char *>(env->GetStringUTFChars(pkg_name, JNI_FALSE));
    char appPath[128];
    devHandles = nullptr;
    snprintf(appPath, 128, "%s%s", "Android/data/", pkgName);

    int ret = QCard_EnumStoreHandle(&devHandles, pkgName, appPath);
    LOGD("QCard_EnumStoreHandle ret = 0x%08x", ret);

    env->ReleaseStringUTFChars(pkg_name, pkgName);

    if (ret > 0) {
        jlong handles[ret];
        for (int i = 0; i < ret; ++i) {
            handles[i] = reinterpret_cast<jlong>(devHandles[i]);
        }
        jlongArray jlongArray = env->NewLongArray(ret);
        env->SetLongArrayRegion(jlongArray, 0, ret, handles);
        return jlongArray;
    } else {
        return nullptr;
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_freeDevs(JNIEnv *env, jobject thiz) {
    QCard_FreeStoreHandle(devHandles);
    LOGD("QCard_FreeStoreHandle");
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_loginDev(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_Login(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_Login ret = 0x%08x", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_logoutDev(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_Logout(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_Logout ret = 0x%08x", ret);
    return !ret;
}


extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_initResource(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_InitResource(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_InitResource ret = 0x%08x", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_updateResource(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_UpdateResource(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_UpdateResource ret = 0x%08x", ret);
    return !ret;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_destroyResource(JNIEnv *env, jobject thiz, jlong dev_handle) {
    QCard_DestoryResource(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_DestoryResource");
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_getDeviceId(JNIEnv *env, jobject thiz, jlong dev_handle) {
    char storeId[64] = {0};
    int ret = QCard_GetStoreId(reinterpret_cast<QHANDLE>(dev_handle), storeId);
    LOGD("QCard_GetStoreId ret = 0x%08x storeId = %s", ret, storeId);
    return env->NewStringUTF(storeId);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_getSystemId(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring con_name) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char systemId[64] = {0};
    int ret = QCard_GetSysTemId(reinterpret_cast<QHANDLE>(dev_handle), appName, conName, systemId);
    LOGD("QCard_GetSysTemId ret = 0x%08x systemId = %s", ret, systemId);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return env->NewStringUTF(systemId);
}

extern "C"
JNIEXPORT jlongArray JNICALL
Java_com_qasky_tfcard_QTF_queryKeyLength(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring con_name) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    unsigned long totalLen;
    unsigned long usedLen;
    char devId[64] = {0};
    int ret = 0;

    ret = QCard_GetStoreId(reinterpret_cast<QHANDLE>(dev_handle), devId);
    LOGD("QCard_GetStoreId ret = 0x%08x devId = %s", ret, devId);

    ret = QCard_QueryKey(reinterpret_cast<QHANDLE>(dev_handle), devId, appName, conName, &totalLen, &usedLen);
    LOGD("QCard_QueryKey ret = 0x%08x totalLen = %lu usedLen = %lu", ret, totalLen, usedLen);

    unsigned long KeyLenInfo[] = {totalLen, usedLen};
    jlongArray longArray = env->NewLongArray(2);
    env->SetLongArrayRegion(longArray, 0, 2, reinterpret_cast<const jlong *>(KeyLenInfo));
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return longArray;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_chargeKey(JNIEnv *env, jobject thiz, jlong dev_handle, jstring _host, jstring app_name, jstring con_name, jstring user_pin) {
    char *host = const_cast<char *>(env->GetStringUTFChars(_host, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *userPIN = const_cast<char *>(env->GetStringUTFChars(user_pin, JNI_FALSE));

    int ret = QCard_ProxyOnlineChargingKey(reinterpret_cast<QHANDLE>(dev_handle), host, appName, conName, userPIN, 1024);
    LOGD("QCard_ProxyOnlineChargingKey ret = 0x%08x", ret);

    env->ReleaseStringUTFChars(_host, host);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(user_pin, userPIN);

    return !ret;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_qasky_tfcard_QTF_getKeyHandle(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring con_name, jstring user_pin, jstring check_code, jstring _flag) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *userPin = const_cast<char *>(env->GetStringUTFChars(user_pin, JNI_FALSE));
    char *checkCode = const_cast<char *>(env->GetStringUTFChars(check_code, JNI_FALSE));
    char *flag = const_cast<char *>(env->GetStringUTFChars(_flag, JNI_FALSE));
    QCard_BLOCKCIPHERPARAM KeyParam;
    memset(&KeyParam, 0, sizeof(KeyParam));
    KeyParam.PaddingType = 1;
    KEYHANDLE keyHandle = nullptr;

    int ret = QCard_ClientKeyInit(reinterpret_cast<QHANDLE>(dev_handle), checkCode, flag, SGD_SMS4_ECB, KeyParam, appName, conName, userPin, TAC_SAFE_CLEARR, &keyHandle);
    LOGD("QCard_ClientKeyInit ret = 0x%08x keyHandle = %p", ret, keyHandle);

    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(user_pin, userPin);
    env->ReleaseStringUTFChars(check_code, checkCode);
    env->ReleaseStringUTFChars(_flag, flag);
    return reinterpret_cast<jlong>(keyHandle);
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_qasky_tfcard_QTF_importExternalSessionKey(JNIEnv *env, jobject thiz, jlong dev_handle, jbyteArray _key) {
    long keyLen = env->GetArrayLength(_key);
    jbyte *jbp_key = env->GetByteArrayElements(_key, JNI_FALSE);
    auto *key = (unsigned char *) jbp_key;

    QCard_BLOCKCIPHERPARAM KeyParam;
    KEYHANDLE keyHandle = nullptr;

    memset(&KeyParam, 0, sizeof(KeyParam));
    KeyParam.PaddingType = 1;
    KeyParam.IVLen = 16;
    int ret = QCard_ExternalKeyInit(reinterpret_cast<QHANDLE>(dev_handle), key, keyLen, SGD_SMS4_CBC, KeyParam, &keyHandle);
    LOGD("QCard_ExternalKeyInit ret = 0x%08x keyHandle = %p", ret, keyHandle);

    env->ReleaseByteArrayElements(_key, jbp_key, JNI_FALSE);

    return reinterpret_cast<jlong>(keyHandle);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_freeKeyHandle(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle) {
    QCard_KeyFinal(reinterpret_cast<QHANDLE>(dev_handle), reinterpret_cast<KEYHANDLE>(key_handle));
    LOGD("QCard_KeyFinal");
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_getSoftKey(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle, jlong key_len) {
    unsigned char softKey[key_len];
    memset(softKey, 0, key_len);

    int ret = QCard_ExportKey(reinterpret_cast<QHANDLE>(dev_handle), reinterpret_cast<KEYHANDLE>(key_handle), softKey, reinterpret_cast<unsigned long *>(&key_len));
    LOGD("QCard_ExportKey ret = 0x%08x softKey = %s", ret, ByteArrayToHexStr(softKey, key_len));

    jbyteArray jbyteArray_softKey = env->NewByteArray(key_len);
    env->SetByteArrayRegion(jbyteArray_softKey, 0, key_len, reinterpret_cast<const jbyte *>(softKey));
    return jbyteArray_softKey;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_encrypt(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle, jbyteArray plain) {
    long srcLen = env->GetArrayLength(plain);
    jbyte *src = env->GetByteArrayElements(plain, JNI_FALSE);
    auto *srcData = (unsigned char *) src;
    unsigned long destLen = srcLen + 16;
    unsigned char destData[destLen];
    memset(destData, 0, destLen);

    int ret = QCard_Encrypt(reinterpret_cast<QHANDLE>(dev_handle), reinterpret_cast<KEYHANDLE>(key_handle), srcData, srcLen, destData, &destLen);
    LOGD("QCard_Encrypt ret = 0x%08x", ret);
    LOGD("QCard_Encrypt plain = %s", ByteArrayToHexStr(srcData, srcLen));
    LOGD("QCard_Encrypt cipher = %s", ByteArrayToHexStr(destData, destLen));

    jbyteArray jbyteArray_dest = env->NewByteArray(destLen);
    env->SetByteArrayRegion(jbyteArray_dest, 0, destLen, reinterpret_cast<const jbyte *>(destData));
    env->ReleaseByteArrayElements(plain, src, JNI_FALSE);
    return jbyteArray_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_decrypt(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle, jbyteArray cipher) {
    long srcLen = env->GetArrayLength(cipher);
    jbyte *src = env->GetByteArrayElements(cipher, JNI_FALSE);
    auto *srcData = (unsigned char *) src;
    unsigned long destLen = srcLen;
    unsigned char destData[destLen];
    memset(destData, 0, sizeof(destData));

    int ret = QCard_Decrypt(reinterpret_cast<QHANDLE>(dev_handle), reinterpret_cast<KEYHANDLE>(key_handle), srcData, srcLen, destData, &destLen);
    LOGD("QCard_Decrypt ret = 0x%08x", ret);
    LOGD("QCard_Decrypt cipher = %s", ByteArrayToHexStr(srcData, srcLen));
    LOGD("QCard_Decrypt plain = %s", ByteArrayToHexStr(destData, destLen));

    jbyteArray jbyteArray_dest = env->NewByteArray(destLen);
    env->SetByteArrayRegion(jbyteArray_dest, 0, destLen, reinterpret_cast<const jbyte *>(destData));

    env->ReleaseByteArrayElements(cipher, src, JNI_FALSE);
    return jbyteArray_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_exportCert(JNIEnv *env, jobject thiz, jlong dev_handle, jint type, jstring app_name, jstring con_name) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    unsigned long certLen = 0, timeOut = 0;

    int ret = QCard_ExportCertificate(reinterpret_cast<QHANDLE>(dev_handle), appName, conName, type, nullptr, &certLen, &timeOut);
    LOGD("QCard_ExportCertificate ret = 0x%08x certLen = %lu", ret, certLen);
    unsigned char cert[certLen];
    memset(cert, 0, certLen);
    ret = QCard_ExportCertificate(reinterpret_cast<QHANDLE>(dev_handle), appName, conName, type, cert, &certLen, &timeOut);
    LOGD("QCard_ExportCertificate ret = 0x%08x cert = %s", ret, ByteArrayToHexStr(cert, certLen));

    jbyteArray jbyteArray_cert = env->NewByteArray(certLen);
    env->SetByteArrayRegion(jbyteArray_cert, 0, certLen, reinterpret_cast<const jbyte *>(cert));
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return jbyteArray_cert;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_exportPubKey(JNIEnv *env, jobject thiz, jlong dev_handle, jint type, jstring app_name, jstring con_name) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    unsigned long keyLen = 0;

    int ret = QCard_ExportPublicKey(reinterpret_cast<QHANDLE>(dev_handle), appName, conName, type, nullptr, &keyLen);
    LOGD("QCard_ExportPublicKey ret = 0x%08x keyLen = %lu", ret, keyLen);
    unsigned char key[keyLen];
    memset(key, 0, keyLen);
    ret = QCard_ExportPublicKey(reinterpret_cast<QHANDLE>(dev_handle), appName, conName, type, key, &keyLen);
    LOGD("QCard_ExportPublicKey ret = 0x%08x key = %s", ret, ByteArrayToHexStr(key, keyLen));

    jbyteArray jbyteArray_key = env->NewByteArray(keyLen);
    env->SetByteArrayRegion(jbyteArray_key, 0, keyLen, reinterpret_cast<const jbyte *>(key));
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return jbyteArray_key;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_verifyAppPIN(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring _pin) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *pin = const_cast<char *>(env->GetStringUTFChars(_pin, JNI_FALSE));
    unsigned long retryCount;

    int ret = QCard_VerifyAppPIN(reinterpret_cast<QHANDLE>(dev_handle), appName, pin, &retryCount);
    LOGD("QCard_VerifyAppPIN ret = 0x%08x retryCount = %lu", ret, retryCount);

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
    LOGD("QCard_ClientRequestOnlineBizKey ret = 0x%08x \nflag = \n%s\ncheckCode = %s", ret, flag, checkCode);

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

extern "C"
JNIEXPORT jlong JNICALL
Java_com_qasky_tfcard_QTF_negoOLKey(JNIEnv *env, jobject thiz, jlong dev_handle) {
    auto devHandle = reinterpret_cast<QHANDLE>(dev_handle);

    char appName[] = "QSKCTS";
    char conName[] = "QSKCTS";
    char pin[] = "12222222";

    char qccsId[] = "WT-QRMS100-20201116";
    char id[] = "WT-QKMS100_001";
    char visitKeyBase64[] = "JLz3wNv1g8cTbiOBMaE+xl+lEzvqeqYKghYk+rJZxAa8c+Aq8VCeMxi7u0a7vaHVWOjuePeXoM7JFEeAZy64xA==";
    char protectKey[] = "123456";
    char host[] = "112.27.97.202:18895";

    char linkId[64] = {0};
    char keyId[64] = {0};
    unsigned char flagChkV[16] = {0};
    char flag[512] = {0};

    void *secTunnelHandle;

    unsigned long keyLen = 16;
    unsigned int cipherQKeyLen = (keyLen / 16) * 272;
    auto *cipherQKey = (unsigned char *) malloc(cipherQKeyLen);
    memset(cipherQKey, 0, cipherQKeyLen);

    int offerSoftKey = 0;

    // 服务端 创建安全通道，代理协商密钥
    int ret = QCard_SetServerAuthorizeKey(visitKeyBase64, protectKey);
    LOGD("QCard_SetServerAuthorizeKey ret = %08x", ret);
    void *arg = nullptr;
    ret = QCard_CreateSecTunnel(PROTOCOL_TYPE_TCP, host, qccsId, id, arg, &secTunnelHandle);
    LOGD("QCard_CreateSecTunnel ret = %08x secTunnelHandle = %p", ret, secTunnelHandle);

    char devId[64] = {0};
    ret = QCard_GetStoreId(devHandle, devId);
    LOGD("QCard_GetStoreId ret = %08x devId = %s", ret, devId);

    ret = QCard_GetLinkId(secTunnelHandle, devId, qccsId, linkId);
    LOGD("QCard_GetLinkId ret = %08x linkId = %s", ret, linkId);

    char systemId[32] = {0};
    ret = QCard_GetSysTemId(devHandle, appName, conName, systemId);
    LOGD("QCard_GetSysTemId ret = %08x systemId = %s", ret, systemId);

    ret = QCard_ServerProxyRequestQkey(secTunnelHandle, devId, linkId, systemId, keyLen, keyId, flagChkV, flag, &offerSoftKey, cipherQKey, &cipherQKeyLen);
    LOGD("QCard_ServerProxyRequestQkey ret = 0x%08x", ret);
    LOGD("QCard_ServerProxyRequestQkey devId = %s", devId);
    LOGD("QCard_ServerProxyRequestQkey linkId = %s", linkId);
    LOGD("QCard_ServerProxyRequestQkey systemId = %s", systemId);
    LOGD("QCard_ServerProxyRequestQkey keyLen = %lu", keyLen);
    LOGD("QCard_ServerProxyRequestQkey keyId = %s", keyId);
    LOGD("QCard_ServerProxyRequestQkey flagChkV = %s", ByteArrayToHexStr(flagChkV, 16));
    LOGD("QCard_ServerProxyRequestQkey flag = %s", flag);
    LOGD("QCard_ServerProxyRequestQkey offerSoftKey = %d", offerSoftKey);
    LOGD("QCard_ServerProxyRequestQkey cipherQKey = %s", ByteArrayToHexStr(cipherQKey, cipherQKeyLen));
    LOGD("QCard_ServerProxyRequestQkey cipherQKeyLen = %d", cipherQKeyLen);

    unsigned int qkeyReadLen = 256;
    auto *qkeyRead = (unsigned char *) calloc(1, qkeyReadLen);
    ret = QCard_ReadQKey(secTunnelHandle, keyId, qkeyRead, &qkeyReadLen);
    LOGD("QCard_ReadQKey ret = %08x qkeyReadLen = %d qkeyRead = %s", ret, qkeyReadLen, ByteArrayToHexStr(qkeyRead, qkeyReadLen));

    QCard_DestroySecTunnel(secTunnelHandle);

    // 客户端 根据协商参数获取密钥句柄
    KEYHANDLE keyHandle = nullptr;
    unsigned int plainKeyLen = 16;

    if (1 == offerSoftKey) {
        unsigned int qkeyLen = plainKeyLen;
        auto *qkey = static_cast<unsigned char *>(malloc(qkeyLen));

        ret = QCard_ClientGetQkey(devHandle, qccsId, systemId, pin, flagChkV, flag, offerSoftKey, cipherQKey, cipherQKeyLen, qkey, &qkeyLen);
        LOGD("QCard_ClientGetQkey ret = %08x qkeyLen = %d qkey = %s", ret, qkeyLen, ByteArrayToHexStr(qkey, qkeyLen));

        ret = char_array_cmp(reinterpret_cast<char *>(qkeyRead), (int)qkeyReadLen, reinterpret_cast<char *>(qkey), (int)qkeyLen);
        LOGD("compare key ret = %d", ret);

        QCard_BLOCKCIPHERPARAM KeyParam;
        memset(&KeyParam, 0, sizeof(KeyParam));
        KeyParam.PaddingType = 1;
        KeyParam.IVLen = 16;

        ret = QCard_ExternalKeyInit(devHandle, qkey, qkeyLen, SGD_SMS4_CBC, KeyParam, &keyHandle);
        LOGD("QCard_ExternalKeyInit ret = %08x keyHandle = %p", ret, keyHandle);

        unsigned long tryTimes = 0;
        ret = QCard_KeyToConVerifyPIN(devHandle, keyHandle, appName, conName, pin, &tryTimes);
        LOGD("QCard_KeyToConVerifyPIN ret = %08x tryTimes = %lu", ret, tryTimes);

//        QCard_KeyFinal(devHandle, keyHandle);
//        LOGD("QCard_KeyFinal");
    } else {
        DEVQKEYPARAM devKeyParam = nullptr;
        unsigned int qKeyNum = 0;

        ret = QCard_ClientGetDeviceQkey(devHandle, qccsId, systemId, pin, flagChkV, flag, offerSoftKey, cipherQKey, cipherQKeyLen, plainKeyLen, &devKeyParam, &qKeyNum);
        LOGD("QCard_ClientGetDeviceQkey ret = %08x", ret);

        QCard_BLOCKCIPHERPARAM KeyParam;
        memset(&KeyParam, 0, sizeof(KeyParam));
        KeyParam.PaddingType = 1;
        KeyParam.IVLen = 16;
        auto *keyHandles = (KEYHANDLE *) malloc(qKeyNum * sizeof(KEYHANDLE));
        memset(keyHandles, 0, qKeyNum * sizeof(KEYHANDLE));

        ret = QCard_deviceQKeyHandlesInit(devHandle, devKeyParam, 0, qKeyNum, SGD_SMS4_CBC, KeyParam, keyHandles);
        keyHandle = keyHandles[0];
        LOGD("QCard_deviceQKeyHandlesInit ret = %08x keyHandle = %p", ret, keyHandle);

//        QCard_DestroyDevQkeyParam(devKeyParam);
//        LOGD("QCard_DestroyDevQkeyParam ret = %08x", ret);
//
//        QCard_DestroyDeviceKeyHandles(devHandle, keyHandles, qKeyNum);
//        LOGD("QCard_DestroyDeviceKeyHandles ret = %08x", ret);
    }

    unsigned long plainLen = 16;
    unsigned char plain[] = "1234567890123456";

    unsigned long cipherLen = plainLen + 16;
    unsigned char cipher[cipherLen];
    memset(cipher, 0, cipherLen);

    ret = QCard_Encrypt(devHandle, keyHandle, plain, plainLen, cipher, &cipherLen);
    LOGD("QCard_Encrypt ret = %08x cipherLen = %lu cipher = %s", ret, cipherLen, ByteArrayToHexStr(cipher, cipherLen));

    unsigned long destLen = cipherLen;
    unsigned char dest[destLen];
    memset(dest, 0, sizeof(dest));

    ret = QCard_Decrypt(devHandle, keyHandle, cipher, cipherLen, dest, &destLen);
    LOGD("QCard_Decrypt ret = 0x%08x destLen = %lu dest = %s", ret, destLen, ByteArrayToHexStr(dest, destLen));

    ret = char_array_cmp(reinterpret_cast<char *>(plain), (int)plainLen, reinterpret_cast<char *>(dest), (int)destLen);
    LOGD("compare enc and dec ret = %d", ret);

    return reinterpret_cast<jlong>(keyHandle);
}