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

QHANDLES devHandles = nullptr;
QHANDLE devHandle = nullptr;


void debug_print(int level, char *msg) {
    LOGE("%d:%s", level, msg);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_LogSetCallBack(JNIEnv *env, jobject thiz) {
    QCard_LogSetCallBack(debug_print, 1, 2, 3, 4, 5);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_EnumStoreHandle(JNIEnv *env, jobject thiz, jstring pkg_name) {
    char *pkgName = const_cast<char *>(env->GetStringUTFChars(pkg_name, JNI_FALSE));
    char appPath[128];
    snprintf(appPath, 128, "%s%s", "Android/data/", pkgName);

    devHandles = nullptr;
    int ret = QCard_Android_EnumStoreHandle(&devHandles, pkgName, appPath);
    LOGD("QCard_EnumStoreHandle ret = %X devHandles = %p", ret, devHandles);

    env->ReleaseStringUTFChars(pkg_name, pkgName);

    if (ret > 0) {
        devHandle = devHandles[0]; // 默认只取第一个
        LOGD("devHandle = %p", devHandle);
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_FreeStoreHandle(JNIEnv *env, jobject thiz) {
    QCard_FreeStoreHandle(devHandles);
    LOGD("QCard_FreeStoreHandle");
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_Login(JNIEnv *env, jobject thiz) {
    int ret = QCard_Login(devHandle);
    LOGD("QCard_Login ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_Logout(JNIEnv *env, jobject thiz) {
    int ret = QCard_Logout(devHandle);
    LOGD("QCard_Logout ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_InitResource(JNIEnv *env, jobject thiz) {
    int ret = QCard_InitResource(devHandle);
    LOGD("QCard_InitResource ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_UpdateResource(JNIEnv *env, jobject thiz) {
    int ret = QCard_UpdateResource(devHandle);
    LOGD("QCard_UpdateResource ret = %X", ret);
    return !ret;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_DestroyResource(JNIEnv *env, jobject thiz) {
    QCard_DestoryResource(devHandle);
    LOGD("QCard_DestoryResource");
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_GetStoreId(JNIEnv *env, jobject thiz) {
    char storeId[64] = {0};
    int ret = QCard_GetStoreId(devHandle, storeId);
    LOGD("QCard_GetStoreId ret = %X storeId = %s", ret, storeId);
    return env->NewStringUTF(storeId);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_GetSystemId(JNIEnv *env, jobject thiz, jstring app_name, jstring con_name) {
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
Java_com_qasky_tfcard_QTF_QueryKey(JNIEnv *env, jobject thiz, jstring store_id, jstring app_name, jstring con_name) {
    char *storeId = const_cast<char *>(env->GetStringUTFChars(store_id, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    unsigned long totalLen = 0;
    unsigned long usedLen = 0;

    int ret = QCard_QueryKey(devHandle, storeId, appName, conName, &totalLen, &usedLen);
    LOGD("QCard_QueryKey ret = %X totalLen = %lu usedLen = %lu", ret, totalLen, usedLen);

    env->ReleaseStringUTFChars(store_id, storeId);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return (int) (totalLen - usedLen);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_ProxyOnlineChargingKey(JNIEnv *env, jobject thiz, jstring _host, jstring app_name, jstring con_name, jstring user_pin, jlong min_key_quantity) {
    char *host = const_cast<char *>(env->GetStringUTFChars(_host, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *userPIN = const_cast<char *>(env->GetStringUTFChars(user_pin, JNI_FALSE));

    int ret = QCard_ProxyOnlineChargingKey(devHandle, host, appName, conName, userPIN, min_key_quantity);
    LOGD("QCard_ProxyOnlineChargingKey ret = %X", ret);

    env->ReleaseStringUTFChars(_host, host);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(user_pin, userPIN);

    return !ret;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_Encrypt(JNIEnv *env, jobject thiz, jlong key_handle, jbyteArray plain) {
    long srcLen = env->GetArrayLength(plain);
    jbyte *src = env->GetByteArrayElements(plain, JNI_FALSE);
    auto *srcData = (unsigned char *) src;
    unsigned long destLen = srcLen + 16;
    auto *destData = (unsigned char *)malloc(destLen);
    memset(destData, 0, destLen);

    int ret = QCard_Encrypt(devHandle, reinterpret_cast<KEYHANDLE>(key_handle), srcData, srcLen, destData, &destLen);
    LOGD("QCard_Encrypt ret = %X", ret);

    jbyteArray jbyteArray_dest = env->NewByteArray(destLen);
    env->SetByteArrayRegion(jbyteArray_dest, 0, destLen, reinterpret_cast<const jbyte *>(destData));

    env->ReleaseByteArrayElements(plain, src, JNI_FALSE);
    return jbyteArray_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_Decrypt(JNIEnv *env, jobject thiz, jlong key_handle, jbyteArray cipher) {
    long srcLen = env->GetArrayLength(cipher);
    jbyte *src = env->GetByteArrayElements(cipher, JNI_FALSE);
    auto *srcData = (unsigned char *) src;
    unsigned long destLen = srcLen;
    auto *destData =(unsigned char *) malloc(destLen);
    memset(destData, 0, destLen);

    int ret = QCard_Decrypt(devHandle, reinterpret_cast<KEYHANDLE>(key_handle), srcData, srcLen, destData, &destLen);
    LOGD("QCard_Decrypt ret = %X", ret);

    jbyteArray jbyteArray_dest = env->NewByteArray(destLen);
    env->SetByteArrayRegion(jbyteArray_dest, 0, destLen, reinterpret_cast<const jbyte *>(destData));

    env->ReleaseByteArrayElements(cipher, src, JNI_FALSE);
    return jbyteArray_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_ExportCertificate(JNIEnv *env, jobject thiz, jint type, jstring app_name, jstring con_name) {
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
Java_com_qasky_tfcard_QTF_ExportPublicKey(JNIEnv *env, jobject thiz, jint type, jstring app_name, jstring con_name) {
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
Java_com_qasky_tfcard_QTF_VerifyAppPIN(JNIEnv *env, jobject thiz, jstring app_name, jstring _pin) {
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *pin = const_cast<char *>(env->GetStringUTFChars(_pin, JNI_FALSE));
    unsigned long retryCount;

    int ret = QCard_VerifyAppPIN(devHandle, appName, pin, &retryCount);
    LOGD("QCard_VerifyAppPIN ret = %X retryCount = %lu", ret, retryCount);

    env->ReleaseStringUTFChars(app_name, appName);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_KeyToConVerifyPIN(JNIEnv *env, jobject thiz, jstring app_name, jstring pin) {
    // TODO: implement KeyToConVerifyPIN()
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_qasky_tfcard_QTF_ClientKeyInit(JNIEnv *env, jobject thiz, jstring app_name, jstring con_name, jstring user_pin, jstring check_code, jstring _flag) {
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
Java_com_qasky_tfcard_QTF_ExternalKeyInit(JNIEnv *env, jobject thiz, jbyteArray _key) {
    long keyLen = env->GetArrayLength(_key);
    jbyte *bp_key = env->GetByteArrayElements(_key, JNI_FALSE);
    auto *key = (unsigned char *) bp_key;

    QCard_BLOCKCIPHERPARAM KeyParam;
    memset(&KeyParam, 0, sizeof(KeyParam));
    KeyParam.PaddingType = 1;
    KeyParam.IVLen = 16;
    KEYHANDLE keyHandle = nullptr;

    int ret = QCard_ExternalKeyInit(devHandle, key, keyLen, SGD_SMS4_CBC, KeyParam, &keyHandle);
    LOGD("QCard_ExternalKeyInit ret = %X keyHandle = %p", ret, keyHandle);

    env->ReleaseByteArrayElements(_key, bp_key, JNI_FALSE);

    return reinterpret_cast<jlong>(keyHandle);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_KeyFinal(JNIEnv *env, jobject thiz, jlong key_handle) {
    QCard_KeyFinal(devHandle, reinterpret_cast<KEYHANDLE>(key_handle));
    LOGD("QCard_KeyFinal");
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_ExportKey(JNIEnv *env, jobject thiz, jlong key_handle, jlong key_len) {
    unsigned char softKey[key_len];
    memset(softKey, 0, key_len);

    int ret = QCard_ExportKey(devHandle, reinterpret_cast<KEYHANDLE>(key_handle), softKey, reinterpret_cast<unsigned long *>(&key_len));
    LOGD("QCard_ExportKey ret = %X softKey = %s", ret, ByteArrayToHexStr(softKey, key_len));

    jbyteArray jbyteArray_softKey = env->NewByteArray(key_len);
    env->SetByteArrayRegion(jbyteArray_softKey, 0, key_len, reinterpret_cast<const jbyte *>(softKey));
    return jbyteArray_softKey;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_qasky_tfcard_QTF_ClientRequestOnlineBizKey(JNIEnv *env, jobject thiz, jstring _host, jstring device_id, jstring system_id, jstring secret_id, jstring server_id, jstring visit_key_base64, jstring protect_key) {
    char *host = const_cast<char *>(env->GetStringUTFChars(_host, JNI_FALSE));
    char *deviceId = const_cast<char *>(env->GetStringUTFChars(device_id, JNI_FALSE));
    char *systemId = const_cast<char *>(env->GetStringUTFChars(system_id, JNI_FALSE));
    char *secretId = const_cast<char *>(env->GetStringUTFChars(secret_id, JNI_FALSE));
    char *serverId = const_cast<char *>(env->GetStringUTFChars(server_id, JNI_FALSE));
    char *visitKeyBase64 = const_cast<char *>(env->GetStringUTFChars(visit_key_base64, JNI_FALSE));
    const auto *protectKey = reinterpret_cast<const unsigned char *>(env->GetStringUTFChars(protect_key, JNI_FALSE));

    char *flag = nullptr;
    char checkCode[64] = {0};

    int ret = QCard_ClientRequestOnlineBizKey(host, deviceId, systemId, secretId, serverId, visitKeyBase64, protectKey, &flag, checkCode);
    LOGD("QCard_ClientRequestOnlineBizKey ret = %X \nflag = \n%s\ncheckCode = %s", ret, flag, checkCode);

    env->ReleaseStringUTFChars(_host, host);
    env->ReleaseStringUTFChars(device_id, deviceId);
    env->ReleaseStringUTFChars(system_id, systemId);
    env->ReleaseStringUTFChars(secret_id, secretId);
    env->ReleaseStringUTFChars(server_id, serverId);
    env->ReleaseStringUTFChars(visit_key_base64, visitKeyBase64);

    if (ret) {
        return nullptr;
    } else {
        jclass clz_NegotiateInfo = env->FindClass("com/qasky/tfcard/NegotiateInfo");
        jobject obj_NegotiateInfo = env->NewObject(clz_NegotiateInfo, env->GetMethodID(clz_NegotiateInfo, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V"), env->NewStringUTF(flag), env->NewStringUTF(checkCode));
        return obj_NegotiateInfo;
    }
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_ReadAuthSynFlag(JNIEnv *env, jobject thiz, jstring peer_store_id, jstring app_name, jstring con_name, jstring _pin) {
    char *syncFlag = nullptr;
    unsigned long flagLen = 0;

    char *peerStoreId = const_cast<char *>(env->GetStringUTFChars(peer_store_id, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *pin = const_cast<char *>(env->GetStringUTFChars(_pin, JNI_FALSE));

    int ret = QCard_ReadAuthSynFlag(devHandle, peerStoreId, appName, conName, pin, syncFlag, &flagLen);
    LOGD("QCard_ReadAuthSynFlag ret = %X flagLen = %d syncFlag = %s", ret, flagLen, syncFlag);

    syncFlag = (char *) malloc(flagLen);
    memset(syncFlag, 0, flagLen);

    ret = QCard_ReadAuthSynFlag(devHandle, peerStoreId, appName, conName, pin, syncFlag, &flagLen);
    LOGD("QCard_ReadAuthSynFlag ret = %X flagLen = %d syncFlag = %s", ret, flagLen, syncFlag);

    env->ReleaseStringUTFChars(peer_store_id, peerStoreId);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(_pin, pin);

    return env->NewStringUTF(syncFlag);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_AuthSynFlag(JNIEnv *env, jobject thiz, jstring peer_store_id, jstring app_name, jstring con_name, jstring _pin, jstring sync_flag) {
    char *peerStoreId = const_cast<char *>(env->GetStringUTFChars(peer_store_id, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *pin = const_cast<char *>(env->GetStringUTFChars(_pin, JNI_FALSE));
    char *syncFlag = const_cast<char *>(env->GetStringUTFChars(sync_flag, JNI_FALSE));

    int ret = QCard_AuthSynFlag(devHandle, peerStoreId, appName, conName, pin, syncFlag);
    LOGD("QCard_AuthSynFlag ret = %X", ret);

    env->ReleaseStringUTFChars(peer_store_id, peerStoreId);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(_pin, pin);
    env->ReleaseStringUTFChars(sync_flag, syncFlag);

    return !ret;
}
extern "C"
JNIEXPORT jlong JNICALL
Java_com_qasky_tfcard_QTF_AuthSynFlagKeyInit(JNIEnv *env, jobject thiz, jstring peer_store_id, jstring app_name, jstring con_name, jstring _pin, jstring sync_flag) {
    char *peerStoreId = const_cast<char *>(env->GetStringUTFChars(peer_store_id, JNI_FALSE));
    char *appName = const_cast<char *>(env->GetStringUTFChars(app_name, JNI_FALSE));
    char *conName = const_cast<char *>(env->GetStringUTFChars(con_name, JNI_FALSE));
    char *pin = const_cast<char *>(env->GetStringUTFChars(_pin, JNI_FALSE));
    char *syncFlag = const_cast<char *>(env->GetStringUTFChars(sync_flag, JNI_FALSE));

    QCard_BLOCKCIPHERPARAM KeyParam;
    memset(&KeyParam, 0, sizeof(KeyParam));
//    KeyParam.PaddingType = 1;
    KEYHANDLE keyHandle = nullptr;

    int ret = QCard_AuthSynFlagKeyInit(devHandle, peerStoreId, syncFlag, SGD_SM1_CBC, KeyParam, appName, conName, pin, TAC_SAFE_CLEARR, &keyHandle);
    LOGD("QCard_AuthSynFlagKeyInit ret = %X keyHandle = %p", ret, keyHandle);

    env->ReleaseStringUTFChars(peer_store_id, peerStoreId);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    env->ReleaseStringUTFChars(_pin, pin);
    env->ReleaseStringUTFChars(sync_flag, syncFlag);

    return reinterpret_cast<jlong>(keyHandle);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_test(JNIEnv *env, jobject thiz) {

    char appPath[128];
    snprintf(appPath, 128, "%s%s", "Android/data/", "com.qasky.tfcarddemo");

    devHandles = nullptr;
    int ret = QCard_Android_EnumStoreHandle(&devHandles, "com.qasky.tfcarddemo", appPath);
    LOGD("QCard_EnumStoreHandle ret = %X devHandles = %p", ret, devHandles);
    devHandle = devHandles[0]; // 默认只取第一个

    ret = QCard_Login(devHandle);
    LOGD("QCard_Login ret = %X", ret);

    QCard_InitResource(devHandle);
    LOGD("QCard_InitResource ret = %X", ret);


    char *syncFlag = nullptr;
    unsigned long flagLen = 0;
     ret = QCard_ReadAuthSynFlag(devHandle, "343048353201454EFFFFFFFF", "QTFCTC", "QTFCTC", "12222222", syncFlag, &flagLen);
    LOGD("QCard_ReadAuthSynFlag ret = %X flagLen = %d syncFlag = %s", ret, flagLen, syncFlag);
    syncFlag = (char *) malloc(flagLen);
    memset(syncFlag, 0, flagLen);
    ret = QCard_ReadAuthSynFlag(devHandle, "343048353201454EFFFFFFFF", "QTFCTC", "QTFCTC", "12222222", syncFlag, &flagLen);
    LOGD("QCard_ReadAuthSynFlag ret = %X flagLen = %d syncFlag = %s", ret, flagLen, syncFlag);

    ret = QCard_AuthSynFlag(devHandle, "343048353201454EFFFFFFFF", "QTFCTC", "QTFCTC", "12222222", syncFlag);
    LOGD("QCard_AuthSynFlag ret = %X", ret);

    QCard_BLOCKCIPHERPARAM KeyParam;
    memset(&KeyParam, 0, sizeof(KeyParam));
    KeyParam.PaddingType = 0;
    KEYHANDLE keyHandle = nullptr;

    ret = QCard_AuthSynFlagKeyInit(devHandle, "343048353201454EFFFFFFFF", syncFlag, SGD_SM1_CBC, KeyParam, "QTFCTC", "QTFCTC", "12222222", TAC_SAFE_CLEARR, &keyHandle);
    LOGD("QCard_AuthSynFlagKeyInit ret = %X keyHandle = %p", ret, keyHandle);
}