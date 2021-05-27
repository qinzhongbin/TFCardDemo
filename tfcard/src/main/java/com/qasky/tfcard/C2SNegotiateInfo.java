package com.qasky.tfcard;

import java.util.Arrays;

/**
 * Author: Endless
 * Date: 4/6/21
 * Desc: C2SNegotiateInfo协商信息实体类
 */
public class C2SNegotiateInfo {
    byte[] key;
    byte[] softKey;
    String flag;
    String checkCode;

    public byte[] getKey() {
        return key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public byte[] getSoftKey() {
        return softKey;
    }

    public void setSoftKey(byte[] softKey) {
        this.softKey = softKey;
    }

    public String getFlag() {
        return flag;
    }

    public void setFlag(String flag) {
        this.flag = flag;
    }

    public String getCheckCode() {
        return checkCode;
    }

    public void setCheckCode(String checkCode) {
        this.checkCode = checkCode;
    }

    @Override
    public String toString() {
        return "C2SNegotiateInfo{" +
                "key=" + Arrays.toString(key) +
                ", softKey=" + Arrays.toString(softKey) +
                ", flag='" + flag + '\'' +
                ", checkCode='" + checkCode + '\'' +
                '}';
    }
}
