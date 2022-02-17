package com.qasky.tfcarddemo.dto;

import lombok.Data;

/**
 * Copyright © 2009 Qasky. All rights reserved.
 * <p>
 *
 * 扩展提供软加密会话密钥对称密钥协商回话类
 * @author Long cheng
 * @version 1.0.0 2018/08/12
 * <p>
 * History:
 * (author, date, desc)
 * (long cheng 20180812, 创建文件)
 */
@Data
public class ExtServerConsultInfo {

    /**
     * 验证码
     */
    private String checkCode;

    /**
     * 协商内容
     */
    private ExtSyncQKeykInfoDto flag;

    /**
     * 密钥
     */
    private String qkey;

    /**
     * 软件加密码密钥
     */
    private String softQkey;

    /**
     * 消息鉴别码
     */
    private String hmac;

    /**
     * 时间戳字符串
     */
    private String timestamp;

    /**
     * 转鉴别消息参数数组
     * @return
     */
    public String[] toAuthMsgParams() {
        return new String[] {
                checkCode,flag.getStoreId(),flag.getUnitId(),flag.getBlockId(),Integer.toString(flag.getOffsetIndex()),
                flag.getEncodeType(),Integer.toString(flag.getKeyLen()),Integer.toString(flag.getSoftQkeyLen()),
                flag.getEncSoftQkey(),flag.getErrorCode(),flag.getErrorMsg(),softQkey,qkey
        };
    }
}