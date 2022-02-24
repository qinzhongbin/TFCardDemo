package com.qasky.tfcard;

public class QCard {

    static {
        System.loadLibrary("QTF");
    }

    public native long[] enumDev(String pkgName);
    public native void freeDev(long devHandles);

    public native boolean loginDev(long devHandle);
    public native boolean logoutDev(long devHandle);

    public native boolean initResource(long devHandle);
    public native boolean updateResource(long devHandle);
    public native void destroyResource(long devHandle);

    public native String getDeviceId(long devHandle);
    public native String getSystemId(long devHandle, String appName, String conName);

    public native long[] queryKeyLength(long devHandle, String appName, String conName);
    public native boolean chargeKey(long devHandle, String host, String appName, String conName, String userPIN);

    public native long getKeyHandle(long devHandle, String appName, String conName, String userPIN, String checkCode, String flag);
    public native void freeKeyHandle(long devHandle, long keyHandle);

    public native byte[] encrypt(long devHandle, long keyHandle, byte[] plain);
    public native byte[] decrypt(long devHandle, long keyHandle, byte[] cipher);

    public native byte[] getSoftKey(long devHandle, long keyHandle, long keyLen);

    public native byte[] exportCert(long devHandle, int type, String appName, String conName);
    public native byte[] exportPubKey(long devHandle, int type, String appName, String conName);

    public native boolean verifyAppPIN(long devHandle, String appName, String PIN);

    public native NegotiateInfo negoOLBizKey(String host, String deviceId, String systemId, String secretId, String serverId, String visitKeyBase64, String protectKey);
}
