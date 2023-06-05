package com.qasky.tfcard;

public class OLNegoInfo {
    private String keyId;
    private String flag;
    private byte[] flagChkV;
    private int encKey;
    private byte[] cipherQKey;
    private int cipherQKeyLen;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getFlag() {
        return flag;
    }

    public void setFlag(String flag) {
        this.flag = flag;
    }

    public byte[] getFlagChkV() {
        return flagChkV;
    }

    public void setFlagChkV(byte[] flagChkV) {
        this.flagChkV = flagChkV;
    }

    public int getEncKey() {
        return encKey;
    }

    public void setEncKey(int encKey) {
        this.encKey = encKey;
    }

    public byte[] getCipherQKey() {
        return cipherQKey;
    }

    public void setCipherQKey(byte[] cipherQKey) {
        this.cipherQKey = cipherQKey;
    }

    public int getCipherQKeyLen() {
        return cipherQKeyLen;
    }

    public void setCipherQKeyLen(int cipherQKeyLen) {
        this.cipherQKeyLen = cipherQKeyLen;
    }
}
