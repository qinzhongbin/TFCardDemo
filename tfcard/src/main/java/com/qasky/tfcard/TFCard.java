package com.qasky.tfcard;

public class TFCard {
    static {
        System.loadLibrary("skf");
        System.loadLibrary("SdCryptoStor");
        System.loadLibrary("qtf3302");
        System.loadLibrary("TFCard");
    }

    /**
     * 资源初始化
     *
     * @param pkgName 应用包名
     * @return 是否成功
     */
    public native boolean initRes(String pkgName);

//    /**
//     * 销毁资源
//     */
//    public native void destroyRes();
//
//    /**
//     * 获取设备序列号
//     *
//     * @return 设备序列号
//     */
//    public native String getStoreId();
//
//    /**
//     * 查询密钥长度（字节Byte）
//     *
//     * @param pcAppName       应用名称
//     * @param pcContainerName 容器名称
//     * @param storeId         设备序列号
//     * @return [总长度, 已使用长度, 剩余长度]
//     */
//    public native int[] queryKeyLength(String pcAppName, String pcContainerName, String storeId);
//
//    /**
//     * 在线充注密钥，充注成功密钥长度不低于2048K
//     *
//     * @param pcAddr          服务器IP地址
//     * @param pcAppName       应用名称
//     * @param pcContainerName 容器名称
//     * @param pcUserPin       应用用户PIN
//     * @return 是否充注成功
//     */
//    public native boolean onlineChargingKey(String pcAddr, String pcAppName, String pcContainerName, String pcUserPin);
//
//    /**
//     * 模拟C2S协商密钥
//     *
//     * @param pcAddr          服务器IP地址
//     * @param pcAppName       应用名称
//     * @param pcContainerName 容器名称
//     * @param storeId         设备序列号
//     * @return 协商是否成功
//     */
//    public native boolean mockC2SNegotiateKey(String pcAddr, String pcAppName, String pcContainerName, String storeId, C2SNegotiateInfo c2SNegotiateInfo);
//
//    /**
//     * 获取密钥句柄
//     *
//     * @param pcAppName       应用名称
//     * @param pcContainerName 容器名称
//     * @param pcUserPin       应用用户PIN
//     * @param pcCheckCode     C2S协商数据
//     * @param pcFlag          C2S协商数据
//     * @return 是否获取成功
//     */
//    public native boolean getKeyHandle(String pcAppName, String pcContainerName, String pcUserPin, String pcCheckCode, String pcFlag);
//
//    /**
//     * 初始化资源后，通过CTS协商获取软密钥
//     *
//     * @return 软密钥
//     */
//    public native byte[] getSoftKey();

//    /**
//     * 硬件加密
//     */
//    public native byte[] hardEncrypt(byte[] data);
//
//    /**
//     * 硬件解密
//     */
//    public native byte[] hardDecrypt(byte[] data);
//
//    /**
//     * SM4软算法加密
//     */
//    public native byte[] sm4SoftEncrypt(byte[] data, byte[] key);
//
//    /**
//     * SM4软算法解密
//     */
//    public native byte[] sm4SoftDecrypt(byte[] data, byte[] key);
}
