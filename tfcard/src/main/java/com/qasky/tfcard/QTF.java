package com.qasky.tfcard;

public class QTF {

    static {
        System.loadLibrary("QTF");
    }

    /**
     * 枚举设备
     *
     * @param pkgName 应用包名
     * @return 是否枚举成功
     */
    public native boolean enumDevice(String pkgName);

    /**
     * 释放所有设备句柄
     */
    public native void freeDevices();

    /**
     * 登录设备
     *
     * @return 是否登录成功
     */
    public native boolean loginDevice();

    /**
     * 登出设备
     *
     * @return 是否登出成功
     */
    public native boolean logoutDevice();

    /**
     * 初始化资源
     *
     * @return 是否初始化成功
     */
    public native boolean initResource();

    /**
     * 更新资源
     *
     * @return 是否更新成功
     */
    public native boolean updateResource();

    /**
     * 销毁资源
     *
     */
    public native void destroyResource();

    /**
     * 获取设备ID
     *
     * @return 设备ID
     */
    public native String getDeviceId();

    /**
     * 获取系统ID
     *
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 系统ID
     */
    public native String getSystemId(String appName, String conName);

    /**
     * 查询密钥长度（单位：字节）
     *
     * @param deviceId  设备Id
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 剩余密钥长度
     */
    public native int queryKeyLength(String deviceId, String appName, String conName);

    /**
     * 充注密钥
     *
     * @param host      主机地址
     * @param appName   应用名称
     * @param conName   容器名称
     * @param userPIN   用户PIN
     * @param minKeyQuantity   最低密钥量，低于该值则启动在线充注密钥
     * @return 是否充注成功
     */
    public native boolean chargeKey(String host, String appName, String conName, String userPIN, long minKeyQuantity);

    /**
     * 获取密钥句柄
     *
     * @param appName   应用名称
     * @param conName   容器名称
     * @param userPIN   用户PIN
     * @param checkCode 校验码
     * @param flag      协商标志
     * @return 密钥句柄
     */
    public native long getKeyHandle(String appName, String conName, String userPIN, String checkCode, String flag);

    /**
     * 导入外部会话密钥
     * @param _key      外部会话密钥
     * @return          密钥句柄
     */
    public native long importExternalSessionKey(byte[] _key);

    /**
     * 释放密钥句柄
     *
     * @param keyHandle 密钥句柄
     */
    public native void freeKeyHandle(long keyHandle);

    public native long negoOLKey();

    /**
     * 加密
     *
     * @param keyHandle 密钥句柄
     * @param plain     明文
     * @return 密文
     */
    public native byte[] encrypt(long keyHandle, byte[] plain);

    /**
     * 解密
     *
     * @param keyHandle 密钥句柄
     * @param cipher    密文
     * @return 明文
     */
    public native byte[] decrypt(long keyHandle, byte[] cipher);

    /**
     * 获取软密钥
     *
     * @param keyHandle 密钥句柄
     * @param keyLen    密钥长度
     * @return 软密钥
     */
    public native byte[] getSoftKey(long keyHandle, long keyLen);

    /**
     * 导出证书
     *
     * @param type      证书类型 0-加密证书 1-签名证书 2-根证书
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 证书
     */
    public native byte[] exportCert(int type, String appName, String conName);

    /**
     * 导出公钥
     *
     * @param type      公钥类型 0-加密公钥 1-签名公钥
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 公钥
     */
    public native byte[] exportPubKey(int type, String appName, String conName);

    /**
     * 验证应用PIN
     *
     * @param appName   应用名称
     * @param PIN       PIN
     * @return 是否验证成功
     */
    public native boolean verifyAppPIN(String appName, String PIN);

    /**
     * 协商在线业务密钥
     *
     * @param host           主机
     * @param deviceId       设备ID
     * @param systemId       系统ID
     * @param secretId       密钥ID
     * @param serverId       密钥应用服务ID
     * @param visitKeyBase64 安全认证密钥
     * @param protectKey     保护密钥
     * @return 协商信息
     */
    public native NegotiateInfo negoOLBizKey(String host, String deviceId, String systemId, String secretId, String serverId, String visitKeyBase64, String protectKey);


    /**
     * 获取认证同步码
     * @param peerDeviceId 对端设备id
     * @param appName       应用名
     * @param conName       容器名
     * @param pin           用户PIN
     * @return              同步认证标志
     */
    public native String readAuthSynFlag(String peerDeviceId, String appName, String conName, String pin);


    public native String authSynFlag(String peerDeviceId, String appName, String conName, String pin);



}
