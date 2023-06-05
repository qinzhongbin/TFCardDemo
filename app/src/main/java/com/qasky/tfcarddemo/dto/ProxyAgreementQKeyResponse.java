package com.qasky.tfcarddemo.dto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;

public class ProxyAgreementQKeyResponse {
    private String keyId;
    private String flagChkV;
    private Flag flag;
    private Integer keyLen;
    private String cipherType;
    private String ciphreQKey;
    private Object plainQKey;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getFlagChkV() {
        return flagChkV;
    }

    public void setFlagChkV(String flagChkV) {
        this.flagChkV = flagChkV;
    }

    public Flag getFlag() {
        return flag;
    }

    public void setFlag(Flag flag) {
        this.flag = flag;
    }

    public Integer getKeyLen() {
        return keyLen;
    }

    public void setKeyLen(Integer keyLen) {
        this.keyLen = keyLen;
    }

    public String getCipherType() {
        return cipherType;
    }

    public void setCipherType(String cipherType) {
        this.cipherType = cipherType;
    }

    public String getCiphreQKey() {
        return ciphreQKey;
    }

    public void setCiphreQKey(String ciphreQKey) {
        this.ciphreQKey = ciphreQKey;
    }

    public Object getPlainQKey() {
        return plainQKey;
    }

    public void setPlainQKey(Object plainQKey) {
        this.plainQKey = plainQKey;
    }

    public static class Flag {
        private String unitId;
        private String blockId;
        private Integer offsetIndex;
        private String chkVAlg;

        public String getUnitId() {
            return unitId;
        }

        public void setUnitId(String unitId) {
            this.unitId = unitId;
        }

        public String getBlockId() {
            return blockId;
        }

        public void setBlockId(String blockId) {
            this.blockId = blockId;
        }

        public Integer getOffsetIndex() {
            return offsetIndex;
        }

        public void setOffsetIndex(Integer offsetIndex) {
            this.offsetIndex = offsetIndex;
        }

        public String getChkVAlg() {
            return chkVAlg;
        }

        public void setChkVAlg(String chkVAlg) {
            this.chkVAlg = chkVAlg;
        }

        // 转化为原始顺序的json（gson会自动按字母顺序排序）
        public String toOriginalOrderJson() {
            Gson gson = new GsonBuilder().registerTypeAdapter(Flag.class, new TypeAdapter<Flag>() {
                @Override
                public void write(JsonWriter out, Flag value) throws IOException {
                    out.beginObject();
                    out.name("unitId").value(value.getUnitId());
                    out.name("blockId").value(value.getBlockId());
                    out.name("offsetIndex").value(value.getOffsetIndex());
                    out.name("chkVAlg").value(value.getChkVAlg());
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
