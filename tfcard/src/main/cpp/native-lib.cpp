#include <jni.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <android/log.h>
#include <android/log.h>
#include <qcard_type.h>
#include <qcard.h>
#include <cstring>
#include <qalg_sm4.h>

#define LOG_TAG "Qasky"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOG_DATA(d, l)\
    do\
{\
    int i;\
    for(i=0;i<l;i++)\
{\
    if((i+1) % 16) \
    LOGD("%02X ", d[i]);\
        else\
        LOGD("%02X", d[i]);\
}\
}\
    while(0)

QHANDLES phStoreHandles = nullptr;
KEYHANDLE hKeyHandle = nullptr;
QCard_BLOCKCIPHERPARAM KeyParam;

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_initRes(JNIEnv *env, jobject thiz, jstring pkg_name) {
    char *pkgName = const_cast<char *>(env->GetStringUTFChars(pkg_name, JNI_FALSE));
    LOGE("pkgName = %s", pkgName);

    int ret = 0;

    const char *appPath_pre = "Android/data/";
    char *appPath = static_cast<char *>(malloc(strlen(appPath_pre) + strlen(pkgName)));
    strcpy(appPath, appPath_pre);
    strcat(appPath, pkgName);
    ret = QCard_EnumStoreHandle(&phStoreHandles, pkgName, appPath);
    env->ReleaseStringUTFChars(pkg_name, pkgName);

    LOGE("deviceNum = %d", ret);
    if (ret <= 0) {
        LOGE("QCard_EnumStoreHandle error: %x", ret);
        return JNI_FALSE;
    }

    ret = QCard_Login(phStoreHandles[0]);
    if (ret) {
        LOGE("QCard_Login error: %x", ret);
        return JNI_FALSE;
    }

    ret = QCard_InitResource(phStoreHandles[0]);
    if (ret) {
        LOGE("QCard_InitResource error: %x", ret);
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_exportStoreId(JNIEnv *env, jobject thiz) {
    char pcStoreId[32] = {0};
    int ret = 0;

    ret = QCard_GetStoreId(phStoreHandles[0], pcStoreId);
    if (ret) {
        LOGE("QCard_GetStoreId error: %x", ret);
    }
    LOGE("storeId = %s", pcStoreId);
    return env->NewStringUTF(pcStoreId);
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_com_qasky_tfcard_QTF_queryKeyLength(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jstring store_id) {
    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
        LOGE("设备句柄为空");
        return nullptr;
    }

    int ret = 0;

    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *storeId = const_cast<char *>(env->GetStringUTFChars(store_id, JNI_FALSE));
    unsigned long uiKeyTotalLen = 0, uiKeyUsedLen = 0;
    ret = QCard_QueryKey(phStoreHandles[0], storeId, pcAppName, pcConName, &uiKeyTotalLen, &uiKeyUsedLen);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcConName);
    env->ReleaseStringUTFChars(store_id, storeId);

    if (ret) {
        LOGE("查询密钥错误 ===> %x", ret);
        return nullptr;
    }

    unsigned long c_arr[] = {uiKeyTotalLen, uiKeyUsedLen, uiKeyTotalLen - uiKeyUsedLen};
    jintArray j_arr = env->NewIntArray(3);
    env->SetIntArrayRegion(j_arr, 0, 3, reinterpret_cast<const jint *>(c_arr));

    return j_arr;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_onlineChargingKey(JNIEnv *env, jobject thiz, jstring pc_addr, jstring pc_app_name, jstring pc_container_name, jstring pc_user_pin) {
    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
        LOGE("设备句柄为空");
        return JNI_FALSE;
    }

    int ret = 0;

    char *pcAddr = const_cast<char *>(env->GetStringUTFChars(pc_addr, JNI_FALSE));
    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcUserPin = const_cast<char *>(env->GetStringUTFChars(pc_user_pin, JNI_FALSE));
    ret = QCard_ProxyOnlineChargingKey(phStoreHandles[0], pcAddr, pcAppName, pcConName, pcUserPin, 2048);
    env->ReleaseStringUTFChars(pc_addr, pcAddr);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcConName);
    env->ReleaseStringUTFChars(pc_user_pin, pcUserPin);

    if (ret) {
        LOGE("充注密钥失败 ===> %x", ret);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_mockC2SNegotiateKey(JNIEnv *env, jobject thiz, jstring pc_addr, jstring pc_app_name, jstring pc_container_name, jstring store_id, jobject c2s_negotiate_info) {
    if (store_id == nullptr) {
        LOGE("设备序列号为空");
        return JNI_FALSE;
    }

    int ret = 0;

    char *pcAddr = const_cast<char *>(env->GetStringUTFChars(pc_addr, JNI_FALSE));
    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *storeId = const_cast<char *>(env->GetStringUTFChars(store_id, JNI_FALSE));

    char *pcFlag = nullptr;
    char pcCheckCode[64] = {0};
    unsigned char pucKey[16] = {0};
    unsigned char pucSoftKey[128] = {0};

    ret = QCard_RequestCTSKeyByApp(pcAddr, storeId, pcAppName, pcConName, 16, pucKey, pucSoftKey, &pcFlag, pcCheckCode);

    env->ReleaseStringUTFChars(pc_addr, pcAddr);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcConName);
    env->ReleaseStringUTFChars(store_id, storeId);

    if (ret) {
        LOGE("CTS密钥协商错误 ===> %x", ret);
        return JNI_FALSE;
    }

    LOGD("硬密钥（C2S协商）：");
    LOG_DATA(pucKey, 16);
    LOGD("软密钥（C2S协商）：");
    LOG_DATA(pucSoftKey, 16);

    jbyteArray key = env->NewByteArray(16);
    env->SetByteArrayRegion(key, 0, 16, reinterpret_cast<const jbyte *>(pucKey));
    jbyteArray softKey = env->NewByteArray(16);
    env->SetByteArrayRegion(softKey, 0, 16, reinterpret_cast<const jbyte *>(pucSoftKey));
    jstring flag = env->NewStringUTF(pcFlag);
    jstring checkCode = env->NewStringUTF(pcCheckCode);

    jclass jclz_c2sNegotiateInfo = env->GetObjectClass(c2s_negotiate_info);
    jmethodID jmid_setKey = env->GetMethodID(jclz_c2sNegotiateInfo, "setKey", "([B)V");
    jmethodID jmid_setSoftKey = env->GetMethodID(jclz_c2sNegotiateInfo, "setSoftKey", "([B)V");
    jmethodID jmid_setFlag = env->GetMethodID(jclz_c2sNegotiateInfo, "setFlag", "(Ljava/lang/String;)V");
    jmethodID jmid_setCheckCode = env->GetMethodID(jclz_c2sNegotiateInfo, "setCheckCode", "(Ljava/lang/String;)V");

    env->CallVoidMethod(c2s_negotiate_info, jmid_setKey, key);
    env->CallVoidMethod(c2s_negotiate_info, jmid_setSoftKey, softKey);
    env->CallVoidMethod(c2s_negotiate_info, jmid_setFlag, flag);
    env->CallVoidMethod(c2s_negotiate_info, jmid_setCheckCode, checkCode);

//    env->DeleteLocalRef(key);
//    env->DeleteLocalRef(softKey);
//    env->ReleaseStringUTFChars(flag, pcFlag);
//    env->ReleaseStringUTFChars(checkCode, pcCheckCode);

    if (pcFlag != nullptr) {
        free(pcFlag);
        pcFlag = nullptr;
    }

    return JNI_TRUE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_getKeyHandleByC2S(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jstring pc_user_pin, jstring pc_check_code, jstring pc_flag) {
    int ret = 0;

    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcConName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcUserPin = const_cast<char *>(env->GetStringUTFChars(pc_user_pin, JNI_FALSE));
    char *pcCheckCode = const_cast<char *>(env->GetStringUTFChars(pc_check_code, JNI_FALSE));
    char *pcFlag = const_cast<char *>(env->GetStringUTFChars(pc_flag, JNI_FALSE));
    ret = QCard_ClientKeyInit(phStoreHandles[0], pcCheckCode, pcFlag, SGD_SM1_ECB, KeyParam, pcAppName, pcConName, pcUserPin, TAC_SAFE_CLEARR, &hKeyHandle);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcConName);
    env->ReleaseStringUTFChars(pc_user_pin, pcUserPin);
    env->ReleaseStringUTFChars(pc_check_code, pcCheckCode);
    env->ReleaseStringUTFChars(pc_flag, pcFlag);

    if (ret) {
        LOGE("QCard_ClientKeyInit error: %x", ret);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_qasky_tfcard_QTF_getAuthSynFlag(JNIEnv *env, jobject thiz, jstring pc_other_store_id, jstring pc_app_name, jstring pc_container_name, jstring pc_user_pin) {
    int ret = 0;
    char *pcFlag = nullptr;
    unsigned long ulFlagLen = 0;

    char *pcOtherStoreId = const_cast<char *>(env->GetStringUTFChars(pc_other_store_id, JNI_FALSE));
    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcUserPin = const_cast<char *>(env->GetStringUTFChars(pc_user_pin, JNI_FALSE));

    ret = QCard_ReadAuthSynFlag(phStoreHandles[0], pcOtherStoreId, pcAppName, pcContainerName, pcUserPin, pcFlag, &ulFlagLen);
    if (ret) {
        LOGE("QCard_ReadAuthSynFlag first time error: %x", ret);
        return nullptr;
    }

    pcFlag = (char *) malloc(ulFlagLen);
    memset(pcFlag, 0, ulFlagLen);

    ret = QCard_ReadAuthSynFlag(phStoreHandles[0], pcOtherStoreId, pcAppName, pcContainerName, pcUserPin, pcFlag, &ulFlagLen);
    env->ReleaseStringUTFChars(pc_other_store_id, pcOtherStoreId);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    env->ReleaseStringUTFChars(pc_user_pin, pcUserPin);

    if (ret) {
        LOGE("QCard_ReadAuthSynFlag second time error: %x", ret);
        return nullptr;
    }

    return env->NewStringUTF(pcFlag);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_authSynFlag(JNIEnv *env, jobject thiz, jstring pc_other_store_id, jstring pc_app_name, jstring pc_container_name, jstring pc_pin, jstring pc_flag) {
    int ret = 0;

    char *pcOtherStoreId = const_cast<char *>(env->GetStringUTFChars(pc_other_store_id, JNI_FALSE));
    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcPin = const_cast<char *>(env->GetStringUTFChars(pc_pin, JNI_FALSE));
    char *pcFlag = const_cast<char *>(env->GetStringUTFChars(pc_flag, JNI_FALSE));

    ret = QCard_AuthSynFlag(phStoreHandles[0], pcOtherStoreId, pcAppName, pcContainerName, pcPin, pcFlag);
    env->ReleaseStringUTFChars(pc_other_store_id, pcOtherStoreId);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    env->ReleaseStringUTFChars(pc_pin, pcPin);
    env->ReleaseStringUTFChars(pc_flag, pcFlag);
    if (ret) {
        LOGE("QCard_AuthSynFlag error: %x", ret);
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_qasky_tfcard_QTF_getKeyHandleByC2C(JNIEnv *env, jobject thiz, jstring pc_other_store_id, jstring pc_flag, jstring pc_app_name, jstring pc_container_name, jstring pc_pin) {
    int ret = 0;

    char *pcOtherStoreId = const_cast<char *>(env->GetStringUTFChars(pc_other_store_id, JNI_FALSE));
    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcPin = const_cast<char *>(env->GetStringUTFChars(pc_pin, JNI_FALSE));
    char *pcFlag = const_cast<char *>(env->GetStringUTFChars(pc_flag, JNI_FALSE));

    memset(&KeyParam, 0, sizeof(KeyParam));
    ret = QCard_AuthSynFlagKeyInit(phStoreHandles[0], pcOtherStoreId, pcFlag, SGD_SM1_CBC, KeyParam, pcAppName, pcContainerName, pcPin, TAC_SAFE_CLEARR, &hKeyHandle);
    env->ReleaseStringUTFChars(pc_other_store_id, pcOtherStoreId);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    env->ReleaseStringUTFChars(pc_pin, pcPin);
    env->ReleaseStringUTFChars(pc_flag, pcFlag);
    if (ret) {
        LOGE("QCard_AuthSynFlagKeyInit error: %x", ret);
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_hardEncrypt(JNIEnv *env, jobject thiz, jbyteArray data) {
    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
        LOGE("设备句柄为空");
        return nullptr;
    }

    if (hKeyHandle == nullptr) {
        LOGE("密钥句柄为空");
        return nullptr;
    }

    int ret = 0;

    long len_src = env->GetArrayLength(data);
    jbyte *data_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
    unsigned char *data_src = reinterpret_cast<unsigned char *>(data_src_jbyte);

    unsigned char data_dest[len_src];
    unsigned long len_dest = len_src;
    memset(data_dest, 0, sizeof(data_dest));

    ret = QCard_Encrypt(phStoreHandles[0], hKeyHandle, data_src, len_src, data_dest, &len_dest);

    env->ReleaseByteArrayElements(data, data_src_jbyte, JNI_FALSE);

    if (ret) {
        LOGE("硬加密失败 ===> %x", ret);
        return nullptr;
    }

    jbyteArray j_data_dest = env->NewByteArray(len_src);
    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));

    return j_data_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_hardDecrypt(JNIEnv *env, jobject thiz, jbyteArray data) {
    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
        LOGE("设备句柄为空");
        return nullptr;
    }

    if (hKeyHandle == nullptr) {
        LOGE("密钥句柄为空");
        return nullptr;
    }

    int ret = 0;

    long len_src = env->GetArrayLength(data);
    jbyte *data_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
    unsigned char *data_src = reinterpret_cast<unsigned char *>(data_src_jbyte);

    unsigned char data_dest[len_src];
    unsigned long len_dest = len_src;
    memset(data_dest, 0, sizeof(data_dest));

    ret = QCard_Decrypt(phStoreHandles[0], hKeyHandle, data_src, len_src, data_dest, &len_dest);

    env->ReleaseByteArrayElements(data, data_src_jbyte, JNI_FALSE);

    if (ret) {
        LOGE("硬解密失败 ===> %x", ret);
        return nullptr;
    }

    jbyteArray j_data_dest = env->NewByteArray(len_src);
    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));

    return j_data_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_getSoftKey(JNIEnv *env, jobject thiz) {
    if (phStoreHandles == nullptr || phStoreHandles[0] == nullptr) {
        LOGE("设备句柄为空");
        return nullptr;
    }
    if (hKeyHandle == nullptr) {
        LOGE("密钥句柄为空");
        return nullptr;
    }

    int ret = 0;
    unsigned char pucSoftKey[1024] = {0};
    unsigned long pucSoftKeyLen = sizeof(pucSoftKey);

    ret = QCard_ExportKey(phStoreHandles[0], hKeyHandle, pucSoftKey, &pucSoftKeyLen);
    if (ret) {
        LOGE("获取软密钥错误 ===> %x", ret);
        return nullptr;
    }

    LOGD("软密钥（设备导出）：");
    LOG_DATA(pucSoftKey, 16);

    jbyteArray softKey = env->NewByteArray(16);
    env->SetByteArrayRegion(softKey, 0, 16, reinterpret_cast<const jbyte *>(pucSoftKey));

    return softKey;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_sm4SoftEncrypt(JNIEnv *env, jobject thiz, jbyteArray data, jbyteArray key) {
    int ret = 0;

    long len_src = env->GetArrayLength(data);
    jbyte *daata_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
    unsigned char *data_src = reinterpret_cast<unsigned char *>(daata_src_jbyte);
    unsigned char *pucKey = reinterpret_cast<unsigned char *>(env->GetByteArrayElements(key, JNI_FALSE));

    qalg_sm4_block_cipher_param qalgSm4BlockCipherParam;
    memset(&qalgSm4BlockCipherParam, 0, sizeof(qalgSm4BlockCipherParam));
    qalgSm4BlockCipherParam.alg_id = QALG_SM4_SMS4_ECB;

    unsigned char data_dest[len_src];
    unsigned long len_dest = len_src;
    memset(data_dest, 0, sizeof(data_dest));

    ret = qalg_sm4_encrypt(pucKey, qalgSm4BlockCipherParam, data_src, len_src, data_dest, &len_dest);
    env->ReleaseByteArrayElements(data, daata_src_jbyte, JNI_FALSE);
    env->ReleaseByteArrayElements(key, reinterpret_cast<jbyte *>(pucKey), JNI_FALSE);

    if (ret) {
        LOGE("SM4软加密失败 ===> %x", ret);
        return nullptr;
    }

    jbyteArray j_data_dest = env->NewByteArray(len_src);
    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));

    return j_data_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_sm4SoftDecrypt(JNIEnv *env, jobject thiz, jbyteArray data, jbyteArray key) {
    int ret = 0;

    long len_src = env->GetArrayLength(data);
    jbyte *data_src_jbyte = env->GetByteArrayElements(data, JNI_FALSE);
    unsigned char *data_src = reinterpret_cast<unsigned char *>(data_src_jbyte);
    unsigned char *pucKey = reinterpret_cast<unsigned char *>(env->GetByteArrayElements(key, JNI_FALSE));

    unsigned char data_dest[len_src];
    unsigned long len_dest = len_src;
    memset(data_dest, 0, sizeof(data_dest));

    qalg_sm4_block_cipher_param qalgSm4BlockCipherParam;
    memset(&qalgSm4BlockCipherParam, 0, sizeof(qalgSm4BlockCipherParam));
    qalgSm4BlockCipherParam.alg_id = QALG_SM4_SMS4_ECB;

    ret = qalg_sm4_decrypt(pucKey, qalgSm4BlockCipherParam, data_src, len_src, data_dest, &len_dest);
    env->ReleaseByteArrayElements(data, data_src_jbyte, JNI_FALSE);

    if (ret) {
        LOGE("SM4软解密失败 ===> %x", ret);
        return nullptr;
    }

    jbyteArray j_data_dest = env->NewByteArray(len_src);
    env->SetByteArrayRegion(j_data_dest, 0, len_src, reinterpret_cast<const jbyte *>(data_dest));
    env->ReleaseByteArrayElements(key, reinterpret_cast<jbyte *>(pucKey), JNI_FALSE);

    return j_data_dest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_exportCert(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jint cert_type) {
    int ret = 0;

    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    unsigned char *pucCert = nullptr;
    unsigned long ulCertLen = 0, ulTimeOut = 0;


    ret = QCard_ExportCertificate(phStoreHandles[0], pcAppName, pcContainerName, cert_type, pucCert, &ulCertLen, &ulTimeOut);
    if (ret) {
        LOGE("QCard_ExportCertificate ERROR: %x", ret);
    }

    LOGD("ulCertLen = %lu", ulCertLen);
    pucCert = (unsigned char *) malloc(ulCertLen);
    memset(pucCert, 0, ulCertLen);

    ret = QCard_ExportCertificate(phStoreHandles[0], pcAppName, pcContainerName, cert_type, pucCert, &ulCertLen, &ulTimeOut);
    if (ret) {
        LOGE("QCard_ExportCertificate ERROR: %x", ret);
    }

    jbyteArray j_cert = env->NewByteArray(ulCertLen);
    env->SetByteArrayRegion(j_cert, 0, ulCertLen, reinterpret_cast<const jbyte *>(pucCert));

    free(pucCert);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    return j_cert;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_exportPubKey(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jint key_type) {
    int ret = 0;

    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    unsigned char *pucPubKey = nullptr;
    unsigned long ulPubKeyLen = 0;

    ret = QCard_ExportPublicKey(phStoreHandles[0], pcAppName, pcContainerName, key_type, pucPubKey, &ulPubKeyLen);

    if (ret) {
        LOGE("QCard_ExportPublicKey ERROR: %x", ret);
    }

    LOGD("ulPubKeyLen = %lu", ulPubKeyLen);
    pucPubKey = (unsigned char *) malloc(ulPubKeyLen);
    memset(pucPubKey, 0, ulPubKeyLen);

    ret = QCard_ExportPublicKey(phStoreHandles[0], pcAppName, pcContainerName, key_type, pucPubKey, &ulPubKeyLen);

    if (ret) {
        LOGE("QCard_ExportPublicKey ERROR: %x", ret);
    }

    jbyteArray j_cert = env->NewByteArray(ulPubKeyLen);
    env->SetByteArrayRegion(j_cert, 0, ulPubKeyLen, reinterpret_cast<const jbyte *>(pucPubKey));

    free(pucPubKey);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    return j_cert;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_sm3Digest(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jstring pc_pin, jbyteArray data) {
    int ret = 0;

    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcUserPin = const_cast<char *>(env->GetStringUTFChars(pc_pin, JNI_FALSE));
    unsigned char *pucData = reinterpret_cast<unsigned char *>(data);
    unsigned long ulDataLen = sizeof(pucData), ulUserPinRetry = 0, digestLen = 0;
    char *digest = nullptr;

    ret = QCard_SM3DigestData(phStoreHandles[0], pcAppName, pcContainerName, pucData, ulDataLen, pcUserPin, &ulUserPinRetry, &digest, &digestLen);
    if (ret) {
        LOGE("QCard_SM3DigestData ERROR: %x", ret);
    }
    LOGD("digestLen = %lu", digestLen);
    digest = static_cast<char *>(malloc(digestLen));
    memset(digest, 0, ulDataLen);
    ret = QCard_SM3DigestData(phStoreHandles[0], pcAppName, pcContainerName, pucData, ulDataLen, pcUserPin, &ulUserPinRetry, &digest, &digestLen);
    if (ret) {
        LOGE("QCard_SM3DigestData ERROR: %x", ret);
    }
    LOG_DATA(digest, digestLen);

    jbyteArray j_digest = env->NewByteArray(digestLen);
    env->SetByteArrayRegion(j_digest, 0, digestLen, reinterpret_cast<const jbyte *>(digest));

    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    env->ReleaseStringUTFChars(pc_pin, pcUserPin);
    return j_digest;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_RSASignDigest(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jstring pc_pin, jbyteArray digest) {
    int ret = 0;

    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcPin = const_cast<char *>(env->GetStringUTFChars(pc_pin, JNI_FALSE));

    unsigned char *pucSignature = nullptr;
    unsigned long ulUserPinRetry = 0, ulSignatureLen = 0;
    unsigned long len_digest = env->GetArrayLength(digest);
    jbyte *j_digest = env->GetByteArrayElements(digest, JNI_FALSE);
    unsigned char *pucDigest = reinterpret_cast<unsigned char *>(j_digest);

    ret = QCard_RSASignData(phStoreHandles[0], pcAppName, pcContainerName, pcPin, &ulUserPinRetry, pucDigest, len_digest, pucSignature, &ulSignatureLen);
    if (ret) {
        LOGE("QCard_RSASignData ERROR: %x", ret);
    }

    LOGD("ulSignatureLen = %lu", ulSignatureLen);
    pucSignature = (unsigned char *) malloc(ulSignatureLen);
    memset(pucSignature, 0, ulSignatureLen);

    ret = QCard_RSASignData(phStoreHandles[0], pcAppName, pcContainerName, pcPin, &ulUserPinRetry, pucDigest, len_digest, pucSignature, &ulSignatureLen);
    if (ret) {
        LOGE("QCard_RSASignData ERROR: %x", ret);
    }

    jbyteArray j_signature = env->NewByteArray(ulSignatureLen);
    env->SetByteArrayRegion(j_signature, 0, ulSignatureLen, reinterpret_cast<const jbyte *>(pucSignature));

    free(pucSignature);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    env->ReleaseStringUTFChars(pc_pin, pcPin);
    return j_signature;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_qasky_tfcard_QTF_ECCSignDigest(JNIEnv *env, jobject thiz, jstring pc_app_name, jstring pc_container_name, jstring pc_pin, jbyteArray digest) {
    int ret = 0;

    char *pcAppName = const_cast<char *>(env->GetStringUTFChars(pc_app_name, JNI_FALSE));
    char *pcContainerName = const_cast<char *>(env->GetStringUTFChars(pc_container_name, JNI_FALSE));
    char *pcPin = const_cast<char *>(env->GetStringUTFChars(pc_pin, JNI_FALSE));

    char *pcSignature = nullptr;
    unsigned long ulUserPinRetry = 0, ulSignatureLen = 0;
    unsigned long len_digest = env->GetArrayLength(digest);
    jbyte *j_digest = env->GetByteArrayElements(digest, JNI_FALSE);
    unsigned char *pucDigest = reinterpret_cast<unsigned char *>(j_digest);

    ret = QCard_SM2SignSM3Data(phStoreHandles[0], pcAppName, pcContainerName, pucDigest, len_digest, pcPin, &ulUserPinRetry, pcSignature, &ulSignatureLen);
    if (ret) {
        LOGE("QCard_SM2SignSM3Data : %x", ret);
    }

    LOGD("ulSignatureLen = %lu", ulSignatureLen);
    pcSignature = (char *) malloc(ulSignatureLen);
    memset(pcSignature, 0, ulSignatureLen);

    ret = QCard_SM2SignSM3Data(phStoreHandles[0], pcAppName, pcContainerName, pucDigest, len_digest, pcPin, &ulUserPinRetry, pcSignature, &ulSignatureLen);
    if (ret) {
        LOGE("QCard_SM2SignSM3Data ERROR: %x", ret);
    }


    jbyteArray j_signature = env->NewByteArray(ulSignatureLen);
    env->SetByteArrayRegion(j_signature, 0, ulSignatureLen, reinterpret_cast<const jbyte *>(pcSignature));

    free(pcSignature);
    env->ReleaseStringUTFChars(pc_app_name, pcAppName);
    env->ReleaseStringUTFChars(pc_container_name, pcContainerName);
    env->ReleaseStringUTFChars(pc_pin, pcPin);
    return j_signature;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_qasky_tfcard_QTF_destroyRes(JNIEnv *env, jobject thiz) {
    int ret = 0;

    if (phStoreHandles != nullptr && phStoreHandles[0]) {
        if (hKeyHandle != nullptr) {
            QCard_KeyFinal(phStoreHandles[0], hKeyHandle);
        }

        ret = QCard_UpdateResource(phStoreHandles[0]); // 更新资源
        if (ret) {
            LOGE("更新资源失败 ===> %x", ret);
        }
        QCard_DestoryResource(phStoreHandles[0]); // 销毁资源
        ret = QCard_Logout(phStoreHandles[0]);
        if (ret) {
            LOGE("退出登录失败 ===> %x", ret);
        }
        QCard_FreeStoreHandle(phStoreHandles); // 关闭枚举句柄
    }

    phStoreHandles = nullptr;
    hKeyHandle = nullptr;
    KeyParam.PaddingType = 0;
}

