package com.qasky.tfcard;

public class NegotiateInfo {
    public String flag;
    public String checkCode;

    public NegotiateInfo(String flag, String checkCode) {
        this.flag = flag;
        this.checkCode = checkCode;
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
}
