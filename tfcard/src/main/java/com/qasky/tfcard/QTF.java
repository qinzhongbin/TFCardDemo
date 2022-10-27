package com.qasky.tfcard;

public class QTF {

    static {
        System.loadLibrary("QTF");
    }

    /**
     * 枚举设备
     *
     * @param pkgName 应用包名
     * @return 设备句柄数组，若枚举失败返回null。
     */
    public native long[] enumDev(String pkgName);

    /**
     * 释放所有设备句柄
     */
    public native void freeDevs();

    /**
     * 登录设备
     *
     * @param devHandle 设备句柄
     * @return 是否登录成功
     */
    public native boolean loginDev(long devHandle);

    /**
     * 登出设备
     *
     * @param devHandle 设备句柄
     * @return 是否登出成功
     */
    public native boolean logoutDev(long devHandle);

    /**
     * 初始化资源
     *
     * @param devHandle 设备句柄
     * @return 是否初始化成功
     */
    public native boolean initResource(long devHandle);

    /**
     * 更新资源
     *
     * @param devHandle 设备句柄
     * @return 是否更新成功
     */
    public native boolean updateResource(long devHandle);

    /**
     * 销毁资源
     *
     * @param devHandle 设备句柄
     */
    public native void destroyResource(long devHandle);

    /**
     * 获取设备ID
     *
     * @param devHandle 设备句柄
     * @return 设备ID
     */
    public native String getDeviceId(long devHandle);

    /**
     * 获取系统ID
     *
     * @param devHandle 设备句柄
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 系统ID
     */
    public native String getSystemId(long devHandle, String appName, String conName);

    /**
     * 查询密钥长度（单位：字节）
     *
     * @param devHandle 设备句柄
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 密钥长度数组 [总长度,已使用]
     */
    public native long[] queryKeyLength(long devHandle, String appName, String conName);

    /**
     * 充注密钥
     *
     * @param devHandle 设备句柄
     * @param host      主机地址
     * @param appName   应用名称
     * @param conName   容器名称
     * @param userPIN   用户PIN
     * @return 是否充注成功
     */
    public native boolean chargeKey(long devHandle, String host, String appName, String conName, String userPIN);

    /**
     * 获取密钥句柄
     *
     * @param devHandle 设备句柄
     * @param appName   应用名称
     * @param conName   容器名称
     * @param userPIN   用户PIN
     * @param checkCode 校验码
     * @param flag      协商标志
     * @return 密钥句柄
     */
    public native long getKeyHandle(long devHandle, String appName, String conName, String userPIN, String checkCode, String flag);

    /**
     * 导入外部会话密钥
     * @param devHandle 设备句柄
     * @param _key      外部会话密钥
     * @return          密钥句柄
     */
    public native long importExternalSessionKey(long devHandle, byte[] _key);

    /**
     * 释放密钥句柄
     *
     * @param devHandle 设备句柄
     * @param keyHandle 密钥句柄
     */
    public native void freeKeyHandle(long devHandle, long keyHandle);

    /**
     * 加密
     *
     * @param devHandle 设备句柄
     * @param keyHandle 密钥句柄
     * @param plain     明文
     * @return 密文
     */
    public native byte[] encrypt(long devHandle, long keyHandle, byte[] plain);

    /**
     * 解密
     *
     * @param devHandle 设备句柄
     * @param keyHandle 密钥句柄
     * @param cipher    密文
     * @return 明文
     */
    public native byte[] decrypt(long devHandle, long keyHandle, byte[] cipher);

    /**
     * 获取软密钥
     *
     * @param devHandle 设备句柄
     * @param keyHandle 密钥句柄
     * @param keyLen    密钥长度
     * @return 软密钥
     */
    public native byte[] getSoftKey(long devHandle, long keyHandle, long keyLen);

    /**
     * 导出证书
     *
     * @param devHandle 设备句柄
     * @param type      证书类型 0-加密证书 1-签名证书 2-根证书
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 证书
     */
    public native byte[] exportCert(long devHandle, int type, String appName, String conName);

    /**
     * 导出公钥
     *
     * @param devHandle 设备句柄
     * @param type      公钥类型 0-加密公钥 1-签名公钥
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 公钥
     */
    public native byte[] exportPubKey(long devHandle, int type, String appName, String conName);

    /**
     * 验证应用PIN
     *
     * @param devHandle 设备句柄
     * @param appName   应用名称
     * @param PIN       PIN
     * @return 是否验证成功
     */
    public native boolean verifyAppPIN(long devHandle, String appName, String PIN);

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
}
