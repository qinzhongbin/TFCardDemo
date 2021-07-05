package com.qasky.tfcard;

public class QTF {
    static {
        System.loadLibrary("QTF");
    }

    /**
     * 资源初始化
     * @param pkgName 应用包名
     */
    public native boolean initRes(String pkgName);

    /**
     * 导出设备序列号
     */
    public native String exportStoreId();

    /**
     * 查询密钥长度（字节Byte）
     *
     * @param pcAppName       应用名称
     * @param pcContainerName 容器名称
     * @param storeId         设备序列号
     * @return [总长度, 已使用长度, 剩余长度]
     */
    public native int[] queryKeyLength(String pcAppName, String pcContainerName, String storeId);

    /**
     * 在线充注密钥，充注成功密钥长度不低于2048K
     *
     * @param pcAddr          服务器IP地址
     * @param pcAppName       应用名称
     * @param pcContainerName 容器名称
     * @param pcUserPin       应用用户PIN
     * @return 是否充注成功
     */
    public native boolean onlineChargingKey(String pcAddr, String pcAppName, String pcContainerName, String pcUserPin);

    /**
     * C2S协商密钥
     *
     * @param pcAddr          服务器IP地址
     * @param pcAppName       应用名称
     * @param pcContainerName 容器名称
     * @param storeId         设备序列号
     * @return 协商是否成功
     */
    public native boolean mockC2SNegotiateKey(String pcAddr, String pcAppName, String pcContainerName, String storeId, C2SNegotiateInfo c2SNegotiateInfo);

    /**
     * C2S获取密钥句柄
     *
     * @param pcAppName       应用名称
     * @param pcContainerName 容器名称
     * @param pcUserPin       应用用户PIN
     * @param pcCheckCode     C2S协商数据
     * @param pcFlag          C2S协商数据
     * @return 是否获取成功
     */
    public native boolean getKeyHandleByC2S(String pcAppName, String pcContainerName, String pcUserPin, String pcCheckCode, String pcFlag);

    /**
     * C2C获取认证同步码
     * @param pcOtherStoreId    对端设备序列号
     * @param pcAppName         应用名称
     * @param pcContainerName   容器名称
     * @param pcUserPin         容器名称
     * @return  认证同步码
     */
    public native String getAuthSynFlag(String pcOtherStoreId, String pcAppName, String pcContainerName, String pcUserPin);

    /**
     * C2C同步认证
     * @param pcOtherStoreId    对端设备序列号
     * @param pcAppName         应用名称
     * @param pcContainerName   容器名称
     * @param pcPin             容器名称
     * @param pcFlag            对端认证同步码
     * @return 是否认证成功
     */
    public native boolean authSynFlag(String pcOtherStoreId, String pcAppName, String pcContainerName, String pcPin, String pcFlag);

    /**
     * C2C获取密钥句柄
     */
    public native boolean getKeyHandleByC2C(String pcOtherStoreId, String pcFlag, String pcAppName, String pcContainerName, String pcPin);

    /**
     * 硬件加密
     */
    public native byte[] hardEncrypt(byte[] data);

    /**
     * 硬件解密
     */
    public native byte[] hardDecrypt(byte[] data);

    /**
     * 获取软密钥
     */
    public native byte[] getSoftKey();

    /**
     * SM4软算法加密
     */
    public native byte[] sm4SoftEncrypt(byte[] data, byte[] key);

    /**
     * SM4软算法解密
     */
    public native byte[] sm4SoftDecrypt(byte[] data, byte[] key);

    /**
     * 销毁资源
     */
    public native void destroyRes();
}
