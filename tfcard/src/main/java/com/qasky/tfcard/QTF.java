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
    public native boolean EnumStoreHandle(String pkgName);

    /**
     * 释放所有设备句柄
     */
    public native void FreeStoreHandle();

    /**
     * 登录设备
     *
     * @return 是否登录成功
     */
    public native boolean Login();

    /**
     * 登出设备
     *
     * @return 是否登出成功
     */
    public native boolean Logout();

    /**
     * 初始化资源
     *
     * @return 是否初始化成功
     */
    public native boolean InitResource();

    /**
     * 更新资源
     *
     * @return 是否更新成功
     */
    public native boolean UpdateResource();

    /**
     * 销毁资源
     *
     */
    public native void DestroyResource();

    /**
     * 获取设备ID
     *
     * @return 设备ID
     */
    public native String GetStoreId();

    /**
     * 获取系统ID
     *
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 系统ID
     */
    public native String GetSystemId(String appName, String conName);

    /**
     * 查询密钥长度（单位：字节）
     *
     * @param storeId  设备Id
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 剩余密钥长度
     */
    public native int QueryKey(String storeId, String appName, String conName);

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
    public native boolean ProxyOnlineChargingKey(String host, String appName, String conName, String userPIN, long minKeyQuantity);

    /**
     * 加密
     *
     * @param keyHandle 密钥句柄
     * @param plain     明文
     * @return 密文
     */
    public native byte[] Encrypt(long keyHandle, byte[] plain);

    /**
     * 解密
     *
     * @param keyHandle 密钥句柄
     * @param cipher    密文
     * @return 明文
     */
    public native byte[] Decrypt(long keyHandle, byte[] cipher);



    /**
     * 导出证书
     *
     * @param type      证书类型 0-加密证书 1-签名证书 2-根证书
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 证书
     */
    public native byte[] ExportCertificate(int type, String appName, String conName);

    /**
     * 导出公钥
     *
     * @param type      公钥类型 0-加密公钥 1-签名公钥
     * @param appName   应用名称
     * @param conName   容器名称
     * @return 公钥
     */
    public native byte[] ExportPublicKey(int type, String appName, String conName);

    /**
     * 验证应用PIN
     *
     * @param appName   应用名称
     * @param PIN       PIN
     * @return 是否验证成功
     */
    public native boolean VerifyAppPIN(String appName, String PIN);

    public native boolean KeyToConVerifyPIN(String appName, String PIN);

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
    public native long ClientKeyInit(String appName, String conName, String userPIN, String checkCode, String flag);

    /**
     * 导入外部会话密钥
     * @param _key      外部会话密钥
     * @return          密钥句柄
     */
    public native long ExternalKeyInit(byte[] _key);

    /**
     * 释放密钥句柄
     *
     * @param keyHandle 密钥句柄
     */
    public native void KeyFinal(long keyHandle);

    /**
     * 获取软密钥
     *
     * @param keyHandle 密钥句柄
     * @param keyLen    密钥长度
     * @return 软密钥
     */
    public native byte[] ExportKey(long keyHandle, long keyLen);

    /**
     * 协商在线业务密钥
     *
     * @param host           主机
     * @param storeId       设备ID
     * @param systemId       系统ID
     * @param secretId       密钥ID
     * @param serverId       密钥应用服务ID
     * @param visitKeyBase64 安全认证密钥
     * @param protectKey     保护密钥
     * @return 协商信息
     */
    public native NegotiateInfo ClientRequestOnlineBizKey(String host, String storeId, String systemId, String secretId, String serverId, String visitKeyBase64, String protectKey);


    /**
     * 获取认证同步码
     * @param peerStoreId 对端设备id
     * @param appName       应用名
     * @param conName       容器名
     * @param pin           用户PIN
     * @return 认证同步码
     */
    public native String ReadAuthSynFlag(String peerStoreId, String appName, String conName, String pin);


    /**
     * 同步认证
     * @param peerStoreId 对端设备id
     * @param appName       应用名
     * @param conName       容器名
     * @param pin           用户PIN
     * @param syncFlag      认证同步码
     * @return 是否同步认证成功
     */
    public native boolean AuthSynFlag(String peerStoreId, String appName, String conName, String pin, String syncFlag);

    /**
     * 获取密钥句柄, 通过认证同步码获取。（CTC模式）
     * @param peerStoreId 对端设备id
     * @param appName       应用名
     * @param conName       容器名
     * @param pin           用户PIN
     * @param syncFlag      认证同步码
     * @return 密钥句柄
     */
    public native long AuthSynFlagKeyInit(String peerStoreId, String appName, String conName, String pin, String syncFlag);
}
