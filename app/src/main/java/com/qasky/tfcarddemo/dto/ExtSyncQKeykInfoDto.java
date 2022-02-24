package com.qasky.tfcarddemo.dto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;

import lombok.Data;

/**
 * Copyright © 2009 Qasky. All rights reserved.
 * <p>
 *
 * 扩展提供软加密会话密钥,对称密钥协商标志信息回话类
 * @author Long cheng
 * @version 1.0.0 2018/08/12
 * <p>
 * History:
 * (author, date, desc)
 * (long cheng 20180812, 创建文件)
 */
@Data
public class ExtSyncQKeykInfoDto {

    private static final long serialVersionUID = 1L;

    /**
     * 移动设备业务ID
     */
    private String storeId;

    /**
     * 当前使用的存储单元ID
     */
    private String unitId;

    /**
     *  当前使用的密钥存储id
     */
    private String blockId;

    /**
     * 当前block密钥偏移量
     */
    private int offsetIndex;

    /**
     * 验证方式：SM3-以SM3方式转32验证码,
     * MD5-以MD5方式转验证码
     */
    private String encodeType;

    /**
     * 协商的量子密钥长度
     */
    private int keyLen;

    /**
     * 软件加密会话密钥长度
     */
    private int softQkeyLen;

    /**
     * 密文软件加密会话密钥:
     *  以协商的量子密钥为密钥，加密生成量随机数密钥
     */
    private String encSoftQkey;

    /**
     * 同步操作结果码:0-同步成功、-1-同步失败
     */
    private String errorCode;

    /**
     * 同步异常信息提示
     */
    private String errorMsg;

    // 转化为原始顺序的json（gson会自动按字母顺序排序）
    public String toOriginalOrderJson() {
        Gson gson = new GsonBuilder().registerTypeAdapter(ExtSyncQKeykInfoDto.class, new TypeAdapter<ExtSyncQKeykInfoDto>() {
            @Override
            public void write(JsonWriter out, ExtSyncQKeykInfoDto value) throws IOException {
                out.beginObject();
                out.name("storeId").value(value.getStoreId());
                out.name("unitId").value(value.getUnitId());
                out.name("blockId").value(value.getBlockId());
                out.name("offsetIndex").value(value.getOffsetIndex());
                out.name("encodeType").value(value.getEncodeType());
                out.name("keyLen").value(value.getKeyLen());
                out.name("softQkeyLen").value(value.getSoftQkeyLen());
                out.name("encSoftQkey").value(value.getEncSoftQkey());
                out.name("errorCode").value(value.getErrorCode());
                out.name("errorMsg").value(value.getErrorMsg());
                out.endObject();
            }

            @Override
            public ExtSyncQKeykInfoDto read(JsonReader in) throws IOException {
                return null;
            }
        }).create();

        return gson.toJson(ExtSyncQKeykInfoDto.this, ExtSyncQKeykInfoDto.class);
    }
}
