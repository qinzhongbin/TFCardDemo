package com.qasky.tfcarddemo.dto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;

public class AgreementFillQKeyResponse {
    private String keyId;
    private String checkCode;
    private Flag flag;
    private String qkey;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getCheckCode() {
        return checkCode;
    }

    public void setCheckCode(String checkCode) {
        this.checkCode = checkCode;
    }

    public Flag getFlag() {
        return flag;
    }

    public void setFlag(Flag flag) {
        this.flag = flag;
    }

    public String getQkey() {
        return qkey;
    }

    public void setQkey(String qkey) {
        this.qkey = qkey;
    }

    public static class Flag {
        private String blockId;
        private String encodeType;
        private Integer offsetIndex;
        private String unitId;
        private Integer softQkeyLen;
        private Integer keyLen;
        private String storeId;
        private String encSoftQkey;
        private String errorCode;
        private String errorMsg;

        public String getBlockId() {
            return blockId;
        }

        public void setBlockId(String blockId) {
            this.blockId = blockId;
        }

        public String getEncodeType() {
            return encodeType;
        }

        public void setEncodeType(String encodeType) {
            this.encodeType = encodeType;
        }

        public int getOffsetIndex() {
            return offsetIndex;
        }

        public void setOffsetIndex(int offsetIndex) {
            this.offsetIndex = offsetIndex;
        }

        public String getUnitId() {
            return unitId;
        }

        public void setUnitId(String unitId) {
            this.unitId = unitId;
        }

        public int getSoftQkeyLen() {
            return softQkeyLen;
        }

        public void setSoftQkeyLen(int softQkeyLen) {
            this.softQkeyLen = softQkeyLen;
        }

        public int getKeyLen() {
            return keyLen;
        }

        public void setKeyLen(int keyLen) {
            this.keyLen = keyLen;
        }

        public String getStoreId() {
            return storeId;
        }

        public void setStoreId(String storeId) {
            this.storeId = storeId;
        }

        public String getEncSoftQkey() {
            return encSoftQkey;
        }

        public void setEncSoftQkey(String encSoftQkey) {
            this.encSoftQkey = encSoftQkey;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public void setErrorCode(String errorCode) {
            this.errorCode = errorCode;
        }

        public String getErrorMsg() {
            return errorMsg;
        }

        public void setErrorMsg(String errorMsg) {
            this.errorMsg = errorMsg;
        }

        // 转化为原始顺序的json（gson会自动按字母顺序排序）
        public String toOriginalOrderJson() {
            Gson gson = new GsonBuilder().registerTypeAdapter(Flag.class, new TypeAdapter<Flag>() {
                @Override
                public void write(JsonWriter out, Flag value) throws IOException {
                    out.beginObject();
                    out.name("blockId").value(value.getBlockId());
                    out.name("encodeType").value(value.getEncodeType());
                    out.name("offsetIndex").value(value.getOffsetIndex());
                    out.name("unitId").value(value.getUnitId());
                    out.name("softQkeyLen").value(value.getSoftQkeyLen());
                    out.name("keyLen").value(value.getKeyLen());
                    out.name("storeId").value(value.getStoreId());
                    out.name("encSoftQkey").value(value.getEncSoftQkey());
//                    out.name("errorCode").value(value.getErrorCode());
//                    out.name("errorMsg").value(value.getErrorMsg());
                    out.endObject();
                }

                @Override
                public Flag read(JsonReader in) throws IOException {
                    return null;
                }
            }).create();

            return gson.toJson(Flag.this, Flag.class);
        }
    }
}
