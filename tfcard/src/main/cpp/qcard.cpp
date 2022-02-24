#include <jni.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <android/log.h>
#include <qcard_type.h>
#include <qcard.h>
#include <cstring>
#include <qalg_sm4.h>
#include <curl/curl.h>
#include <iostream>
#include <skf_type.h>
#include <SKF.h>
#include <log.h>

extern "C"
JNIEXPORT jlongArray JNICALL
Java_com_qasky_tfcard_QCard_enumDev(JNIEnv *env, jobject thiz, jstring pkg_name) {
    char *pkgName = const_cast<char *>(env->GetStringUTFChars(pkg_name, JNI_FALSE));
    char appPath[128];
    QHANDLES devHandles = nullptr;
    snprintf(appPath, 128, "%s%s", "Android/data/", pkgName);

    int ret = QCard_EnumStoreHandle(&devHandles, pkgName, appPath);
    LOGD("QCard_EnumStoreHandle ret = 0x%08x", ret);

    env->ReleaseStringUTFChars(pkg_name, pkgName);

    if (ret > 0) {
        long handleInfo[1 + ret];
        handleInfo[0] = reinterpret_cast<long>(devHandles);
        for (int i = 1; i <= ret; ++i) {
            handleInfo[i] = reinterpret_cast<long>(devHandles[i - 1]);
        }
        jlongArray longArray = env->NewLongArray(1 + ret);
        env->SetLongArrayRegion(longArray, 0, 1 + ret, handleInfo);
        return longArray;
    } else {
        return nullptr;
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QCard_freeDev(JNIEnv *env, jobject thiz, jlong dev_handles) {
    QCard_FreeStoreHandle(reinterpret_cast<QHANDLES>(dev_handles));
    LOGD("QCard_FreeStoreHandle");
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QCard_loginDev(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_Login(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_Login ret = 0x%08x", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QCard_logoutDev(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_Logout(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_Logout ret = 0x%08x", ret);
    return !ret;
}


extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QCard_initResource(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_InitResource(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_InitResource ret = 0x%08x", ret);
    return !ret;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QCard_updateResource(JNIEnv *env, jobject thiz, jlong dev_handle) {
    int ret = QCard_UpdateResource(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_UpdateResource ret = 0x%08x", ret);
    return !ret;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QCard_destroyResource(JNIEnv *env, jobject thiz, jlong dev_handle) {
    QCard_DestoryResource(reinterpret_cast<QHANDLE>(dev_handle));
    LOGD("QCard_DestoryResource");
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QCard_getDeviceId(JNIEnv *env, jobject thiz, jlong dev_handle) {
    char storeId[64] = {0};
    int ret = QCard_GetStoreId(reinterpret_cast<QHANDLE>(dev_handle), storeId);
    LOGD("QCard_GetStoreId ret = 0x%08x storeId = %s", ret, storeId);
    return env->NewStringUTF(storeId);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QCard_getSystemId(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring con_name) {
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
Java_com_qasky_tfcard_QCard_queryKeyLength(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring con_name) {
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
Java_com_qasky_tfcard_QCard_chargeKey(JNIEnv *env, jobject thiz, jlong dev_handle, jstring _host, jstring app_name, jstring con_name, jstring user_pin) {
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
Java_com_qasky_tfcard_QCard_getKeyHandle(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring con_name, jstring user_pin, jstring check_code, jstring _flag) {
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
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QCard_freeKeyHandle(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle) {
    QCard_KeyFinal(reinterpret_cast<QHANDLE>(dev_handle), reinterpret_cast<KEYHANDLE>(key_handle));
    LOGD("QCard_KeyFinal");
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QCard_getSoftKey(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle, jlong key_len) {
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
Java_com_qasky_tfcard_QCard_encrypt(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle, jbyteArray plain) {
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
Java_com_qasky_tfcard_QCard_decrypt(JNIEnv *env, jobject thiz, jlong dev_handle, jlong key_handle, jbyteArray cipher) {
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
Java_com_qasky_tfcard_QCard_exportCert(JNIEnv *env, jobject thiz, jlong dev_handle, jint type, jstring app_name, jstring con_name) {
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
    free(cert);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return jbyteArray_cert;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QCard_exportPubKey(JNIEnv *env, jobject thiz, jlong dev_handle, jint type, jstring app_name, jstring con_name) {
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
    free(key);
    env->ReleaseStringUTFChars(app_name, appName);
    env->ReleaseStringUTFChars(con_name, conName);
    return jbyteArray_key;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QCard_verifyAppPIN(JNIEnv *env, jobject thiz, jlong dev_handle, jstring app_name, jstring _pin) {
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
Java_com_qasky_tfcard_QCard_negoOLBizKey(JNIEnv *env, jobject thiz, jstring _host, jstring device_id, jstring system_id, jstring secret_id, jstring server_id, jstring visit_key_base64, jstring protect_key) {
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