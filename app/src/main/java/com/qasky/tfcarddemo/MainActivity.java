package com.qasky.tfcarddemo;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

import com.blankj.utilcode.util.ConvertUtils;
import com.blankj.utilcode.util.GsonUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.TimeUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.google.gson.reflect.TypeToken;
import com.qasky.tfcard.NegotiateInfo;
import com.qasky.tfcard.OLNegoInfo;
import com.qasky.tfcard.QTF;
import com.qasky.tfcarddemo.dto.AgreementFillQKeyRequest;
import com.qasky.tfcarddemo.dto.AgreementFillQKeyResponse;
import com.qasky.tfcarddemo.dto.CleanOLBizKeyReq;
import com.qasky.tfcarddemo.dto.CleanOLBizKeyResp;
import com.qasky.tfcarddemo.dto.CreateOLBizKeyReq;
import com.qasky.tfcarddemo.dto.CreateOLBizKeyResp;
import com.qasky.tfcarddemo.dto.ExtServerConsultInfo;
import com.qasky.tfcarddemo.dto.ProxyAgreementQKeyRequest;
import com.qasky.tfcarddemo.dto.ProxyAgreementQKeyResponse;
import com.qasky.tfcarddemo.dto.RestResult;
import com.qasky.tfcarddemo.dto.SvrNegoOLBizKeyReq;
import com.qasky.tfcarddemo.dto.SvrNegoOLBizKeyResp;
import com.qasky.tfcarddemo.gm.SM3Util;
import com.qasky.tfcarddemo.gm.SM4Util;
import com.qasky.tfcarddemo.okhttp.OkHttpUtil;

import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import okhttp3.FormBody;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class MainActivity extends AppCompatActivity {
    private final QTF qtf = new QTF();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        init();
    }

    byte[] zeroIV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte[] encryptKey;
    byte[] decryptKey;
    byte[] hmacKey;

    private void init() {
        byte[] cutProtectKey = Arrays.copyOfRange(SM3Util.hash("123456".getBytes(StandardCharsets.UTF_8)), 0, 16);
        byte[] keys = new byte[0];
        try {
            keys = SM4Util.decrypt_CBC_Padding(cutProtectKey, zeroIV, Base64.decode("JLz3wNv1g8cTbiOBMaE+xl+lEzvqeqYKghYk+rJZxAa8c+Aq8VCeMxi7u0a7vaHVWOjuePeXoM7JFEeAZy64xA==".getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        encryptKey = Arrays.copyOfRange(keys, 0, 16);
        decryptKey = Arrays.copyOfRange(keys, 16, 32);
        hmacKey = Arrays.copyOfRange(keys, 32, 48);
    }

    OkHttpClient okHttpClient = OkHttpUtil.getClient();

    public void CTSNegoChargingKey(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (qtf.EnumStoreHandle(getPackageName())) {
                        if (qtf.Login()) {
                            if (qtf.InitResource()) {
                                String storeId = qtf.GetStoreId();
                                int keyLength = qtf.QueryKey(storeId, "QTFCTS", "QTFCTS");
                                qtf.ProxyOnlineChargingKey("112.27.97.202:8890", "QTFCTS", "QTFCTS", "12222222", 16);

                                // 协商
                                String timestamp = String.valueOf(System.currentTimeMillis());
                                String authMsg = storeId + "," + "QTFCTS" + "," + "QTFCTS" + "," + 16 + "," + "WT-QKMS100_001" + "," + timestamp;
                                String hmac = Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg.getBytes(StandardCharsets.UTF_8)));
                                Request request = new Request.Builder()
                                        .url("https://112.27.97.202:8890/qkeyapply/serverConsultInfosByApp")
                                        .post(new FormBody.Builder()
                                                .add("storeId", storeId)
                                                .add("appName", "QTFCTS")
                                                .add("containerName", "QTFCTS")
                                                .add("keyLen", "16")
                                                .add("serverId", "WT-QKMS100_001")
                                                .add("timestamp", timestamp)
                                                .add("hmac", hmac)
                                                .build())
                                        .build();

                                Response response = okHttpClient.newCall(request).execute();
                                if (response.isSuccessful()) {
                                    RestResult<ExtServerConsultInfo> restResult = GsonUtils.fromJson(response.body().string(), new TypeToken<RestResult<ExtServerConsultInfo>>() {
                                    }.getType());
                                    if (restResult.getCode() == 0) {
                                        ExtServerConsultInfo data = restResult.getData();
                                        String hmac_expect = Base64.toBase64String(SM3Util.hmac(hmacKey, String.join(",", data.toAuthMsgParams()).getBytes(StandardCharsets.UTF_8)));

                                        boolean useKeyAppSrv = data.getTimestamp() != null && data.getHmac() != null; // 使用密钥应用服务
                                        if (useKeyAppSrv) {
                                            if (!timestamp.equals(data.getTimestamp()) || !hmac_expect.equals(data.getHmac())) { // 校验时间戳与hmac
                                                LogUtils.d("协商参数校验错误");
                                            }
                                        }

                                        String softQkey_encrypted_encoded = data.getSoftQkey();
                                        byte[] softQkey_encrypted = Base64.decode(softQkey_encrypted_encoded);
                                        byte[] softQkey;
                                        if (useKeyAppSrv) {
                                            softQkey = SM4Util.decrypt_CBC_Padding(decryptKey, zeroIV, softQkey_encrypted);
                                        } else {
                                            softQkey = softQkey_encrypted;
                                        }
                                        LogUtils.d("服务端软密钥：" + ConvertUtils.bytes2HexString(softQkey)); // 客户端导出软密钥对比是否与服务端一致
                                        LogUtils.d("CTS密钥协商成功");

                                        LogUtils.d(data.getCheckCode());
                                        LogUtils.d(data.getFlag().toOriginalOrderJson());
                                        long keyHandle = qtf.ClientKeyInit("QTFCTS", "QTFCTS", "12222222", data.getCheckCode(), data.getFlag().toOriginalOrderJson());

                                        byte[] cipher = qtf.Encrypt(keyHandle, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                                        byte[] plain = qtf.Decrypt(keyHandle, cipher);
                                        LogUtils.d("明文：" + new String(plain, StandardCharsets.UTF_8));

                                        byte[] softKey = qtf.ExportKey(keyHandle, 16);
                                        LogUtils.d("客户端软密钥：" + ConvertUtils.bytes2HexString(softKey));

                                        cipher = SM4Util.encrypt_CBC_Padding(softKey, zeroIV, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                                        plain = SM4Util.decrypt_CBC_Padding(softKey, zeroIV, cipher);
                                        LogUtils.d("明文：" + new String(plain, StandardCharsets.UTF_8));

                                        qtf.KeyFinal(keyHandle);
                                    } else {
                                        LogUtils.d(restResult.getMessage());
                                    }
                                } else {
                                    LogUtils.d(response.message());
                                }

                                qtf.UpdateResource();
                                qtf.DestroyResource();
                            }
                            qtf.Logout();
                        }
                        qtf.FreeStoreHandle();
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public void CTSNegoOLBizQKey(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (qtf.EnumStoreHandle(getPackageName())) {
                        if (qtf.Login()) {
                            if (qtf.InitResource()) {
                                String storeId = qtf.GetStoreId();
                                int keyLength = qtf.QueryKey(storeId, "QTFCTS", "QTFCTS");
                                qtf.ProxyOnlineChargingKey("112.27.97.202:8890", "QTFCTS", "QTFCTS", "12222222", 16);
                                String systemId = qtf.GetSystemId("QTFCTS", "QTFCTS");

                                // step 1: 服务端创建在线业务密钥
                                Calendar calendar = Calendar.getInstance();
                                calendar.add(Calendar.YEAR, 1);
                                CreateOLBizKeyReq createRequest = new CreateOLBizKeyReq();
                                createRequest.setSecretSize("16");
                                createRequest.setValidityDate(TimeUtils.date2String(calendar.getTime()));
                                createRequest.setSystemId(systemId);
                                createRequest.setServerId("WT-QKMS100_001");
                                createRequest.setTimestamp(System.currentTimeMillis());
                                String authMsg_create = createRequest.getSecretSize() + "," + createRequest.getValidityDate() + "," + createRequest.getSystemId() + "," + createRequest.getServerId() + "," + createRequest.getTimestamp();
                                createRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_create.getBytes(StandardCharsets.UTF_8))));

                                Response response_create = okHttpClient.newCall(new Request.Builder()
                                        .url("https://112.27.97.202:8890/onlinebizkey/createOnlineBizKey")
                                        .post(RequestBody.create(GsonUtils.toJson(createRequest), MediaType.parse("application/json; charset=utf-8")))
                                        .build()).execute();
                                if (response_create.isSuccessful()) {
                                    CreateOLBizKeyResp createOLBizKeyResp = GsonUtils.fromJson(response_create.body().string(), CreateOLBizKeyResp.class);
                                    if (createOLBizKeyResp.getCode() == 0) {
                                        String secretId = createOLBizKeyResp.getData().getSecretId();

                                        // step 2: 服务端协商在线业务密钥
                                        SvrNegoOLBizKeyReq svrNegoReq = new SvrNegoOLBizKeyReq();
                                        svrNegoReq.setSecretId(secretId);
                                        svrNegoReq.setSystemId(systemId);
                                        svrNegoReq.setServerId("WT-QKMS100_001");
                                        svrNegoReq.setTimestamp(String.valueOf(System.currentTimeMillis()));
                                        String authMsg_svrNego = svrNegoReq.getSecretId() + "," + svrNegoReq.getSystemId() + "," + svrNegoReq.getServerId() + "," + svrNegoReq.getTimestamp();
                                        svrNegoReq.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_svrNego.getBytes(StandardCharsets.UTF_8))));
                                        Response response_svrNego = okHttpClient.newCall(new Request.Builder()
                                                .url("https://112.27.97.202:8890/onlinebizkey/serverNegotiateOnlineBizKey")
                                                .post(RequestBody.create(GsonUtils.toJson(svrNegoReq), MediaType.parse("application/json; charset=utf-8")))
                                                .build()).execute();
                                        if (response_svrNego.isSuccessful()) {
                                            SvrNegoOLBizKeyResp srvNegoResponse = GsonUtils.fromJson(response_svrNego.body().string(), SvrNegoOLBizKeyResp.class);
                                            if (srvNegoResponse.getCode() == 0) {
                                                String secretKey_encrypted_encoded = srvNegoResponse.getData().getSecretKey();
                                                byte[] secretKey_encrypted = Base64.decode(secretKey_encrypted_encoded);
                                                byte[] secretKey = SM4Util.decrypt_CBC_Padding(decryptKey, zeroIV, secretKey_encrypted);
                                                LogUtils.d("服务端软密钥：" + ConvertUtils.bytes2HexString(secretKey));

                                                // step 3: 客户端协商在线业务密钥
                                                Thread.sleep(1000L); // 客户端协商时间应比服务端协商时间晚，模拟延时操作。
                                                NegotiateInfo negotiateInfo = qtf.ClientRequestOnlineBizKey("112.27.97.202:8890", storeId, systemId, secretId, "WT-QKMS100_001", "JLz3wNv1g8cTbiOBMaE+xl+lEzvqeqYKghYk+rJZxAa8c+Aq8VCeMxi7u0a7vaHVWOjuePeXoM7JFEeAZy64xA==", "123456");

                                                long keyHandle = qtf.ClientKeyInit("QTFCTS", "QTFCTS", "12222222", negotiateInfo.getCheckCode(), negotiateInfo.getFlag());

                                                byte[] cipher = qtf.Encrypt(keyHandle, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                                                byte[] plain = qtf.Decrypt(keyHandle, cipher);
                                                LogUtils.d("明文：" + new String(plain, StandardCharsets.UTF_8));

                                                byte[] softKey = qtf.ExportKey(keyHandle, 16);
                                                LogUtils.d("客户端软密钥：" + ConvertUtils.bytes2HexString(softKey));

                                                cipher = SM4Util.encrypt_CBC_Padding(softKey, zeroIV, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                                                plain = SM4Util.decrypt_CBC_Padding(softKey, zeroIV, cipher);
                                                LogUtils.d("明文：" + new String(plain, StandardCharsets.UTF_8));

                                                qtf.KeyFinal(keyHandle);

                                                // step 4: 服务端销毁在线业务密钥 (业务结束后调用)
                                                CleanOLBizKeyReq cleanRequest = new CleanOLBizKeyReq();
                                                cleanRequest.setSecretId(secretId);
                                                cleanRequest.setSystemId(systemId);
                                                cleanRequest.setServerId("WT-QKMS100_001");
                                                cleanRequest.setTimestamp(String.valueOf(System.currentTimeMillis()));
                                                String authMsg_clean = cleanRequest.getSecretId() + "," + cleanRequest.getSystemId() + "," + cleanRequest.getServerId() + "," + cleanRequest.getTimestamp();
                                                cleanRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_clean.getBytes(StandardCharsets.UTF_8))));
                                                Response response_clean = okHttpClient.newCall(new Request.Builder()
                                                        .url("https://112.27.97.202:8890/onlinebizkey/cleanNegotiateOnlineBizKey")
                                                        .post(RequestBody.create(GsonUtils.toJson(cleanRequest), MediaType.parse("application/json; charset=utf-8"))).build()).execute();
                                                if (response_clean.isSuccessful()) {
                                                    CleanOLBizKeyResp cleanResponse = GsonUtils.fromJson(response_clean.body().string(), CleanOLBizKeyResp.class);
                                                    if (cleanResponse.getCode() == 0) {
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                qtf.UpdateResource();
                                qtf.DestroyResource();
                            }
                            qtf.Logout();
                        }
                        qtf.FreeStoreHandle();
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public void CTCNego(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                if (qtf.EnumStoreHandle(getPackageName())) {
                    if (qtf.Login()) {
                        if (qtf.InitResource()) {
                            String storeId = qtf.GetStoreId();
                            String systemId = qtf.GetSystemId("QTFCTC", "QTFCTC");
                            qtf.QueryKey("343048353201355DFFFFFFFF", "QTFCTC", "QTFCTC");


                            String authSynFlag = qtf.ReadAuthSynFlag("343048353201355DFFFFFFFF", "QTFCTC", "QTFCTC", "12222222");

//                            if (qtf.AuthSynFlag("343048353201454EFFFFFFFF", "QTFCTC", "QTFCTC", "12222222", authSynFlag)) {


                            long keyHandle = qtf.AuthSynFlagKeyInit("343048353201355DFFFFFFFF", "QTFCTC", "QTFCTC", "12222222", authSynFlag);

                            byte[] cipher = qtf.Encrypt(keyHandle, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                            byte[] plain = qtf.Decrypt(keyHandle, cipher);
                            LogUtils.d("明文：" + new String(plain, StandardCharsets.UTF_8));

                            byte[] softKey = qtf.ExportKey(keyHandle, 16);
                            LogUtils.d("软密钥：" + ConvertUtils.bytes2HexString(softKey));
                            try {
                                cipher = SM4Util.encrypt_CBC_Padding(softKey, zeroIV, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                                plain = SM4Util.decrypt_CBC_Padding(softKey, zeroIV, cipher);
                            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
                                throw new RuntimeException(e);
                            }

                            LogUtils.d("明文：" + new String(plain, StandardCharsets.UTF_8));

                            qtf.KeyFinal(keyHandle);
//                            }
                            qtf.UpdateResource();
                            qtf.DestroyResource();
                        }
                        qtf.Logout();
                    }
                    qtf.FreeStoreHandle();
                }
            }
        }).start();
    }

    public void TEST(View view) {
        qtf.LogSetCallBack();
        qtf.test();
    }
//    public void TEST(View view) {
//        new Thread(new Runnable() {
//            @Override
//            public void run() {
//                if (qtf.EnumStoreHandle(getPackageName())) {
//                    if (qtf.Login()) {
//                        if (qtf.InitResource()) {
//                            byte[] key = "1234567890123456".getBytes();
//                            long keyHandle = qtf.ExternalKeyInit(key);
//
////                            String plain = new String(new char[1024 * 1024 * 100]).replace("\0", "Q");
////                            char[] data = new char[1024 * 1024 * 79];
////                            Arrays.fill(data, (char) 0x51);
//
//                            byte[] plain = new byte[1024 * 1024 * 64];
//                            Arrays.fill(plain, (byte) 0x51);
//
//                            long time = System.currentTimeMillis();
//                            byte[] encrypt = qtf.Encrypt(keyHandle, plain);
//                            long time_encrypt = System.currentTimeMillis();
//                            LogUtils.d("加密耗时：" + (time_encrypt - time) / 1000 + "s");
//                            byte[] decrypt = qtf.Decrypt(keyHandle, encrypt);
//                            long time_decrypt = System.currentTimeMillis();
//                            LogUtils.d("解密耗时：" + (time_decrypt - time_encrypt) / 1000 + "s");
//                            LogUtils.d("总耗时：" + (time_decrypt - time) / 1000 + "s");
//
////                            LogUtils.d("结果：" + new String(decrypt, StandardCharsets.UTF_8));
//
//                            qtf.KeyFinal(keyHandle);
//
//                            qtf.UpdateResource();
//                            qtf.DestroyResource();
//                        }
//                        qtf.Login();
//                    }
//                    qtf.FreeStoreHandle();
//                }
//            }
//        }).start();
//    }

//    public void TEST(View view) {
////        qtf.EnumStoreHandle(getPackageName());
////        qtf.Login();
////        qtf.InitResource();
////        long keyHandle = qtf.ExternalKeyInit("1234567890123456".getBytes());
////
////
////
////
////        new Thread(new Runnable() {
////            @SuppressLint("DefaultLocale")
////            @Override
////            public void run() {
////                long id = Thread.currentThread().getId();
////                LogUtils.e("启动新线程进行测试: " + id);
////
////                byte[] plain = new byte[1024 * 1024 * 1];
////                Arrays.fill(plain, (byte) 0x31);
////                for (int i = 0; i < 100; i++) {
////                    long start = System.currentTimeMillis();
////                    byte[] cipher = qtf.Encrypt(keyHandle, plain);
////                    long endEncrypt = System.currentTimeMillis();
////                    byte[] result = qtf.Decrypt(keyHandle, cipher);
////                    long endDecrypt = System.currentTimeMillis();
////                    LogUtils.e(id  + "==>" + String.format("耗时测试[%d]结果: 数据长度 %d， 编码耗时 %dms， 解码耗时 %dms\n", i, plain.length, endEncrypt - start, endDecrypt - endEncrypt));
////                }
////            }
////        }).start();
////
////        new Thread(new Runnable() {
////            @SuppressLint("DefaultLocale")
////            @Override
////            public void run() {
////                long id = Thread.currentThread().getId();
////                LogUtils.e("启动新线程进行测试: " + id);
////                byte[] cipher = new byte[]{
////                        -29, -67, 102, -2, 68, -104, -102, 48, 9, -48, 88, 62, -98, 16, 27, -51, 32, -21, -45, -80, -14, -98, 80, 124, 17, -46, -33, -73, 21, -123, -97, 96, 126, 109, 104, -9, -24, 88, -48, 34, 80, -102, -57, -114, -64, -124, -120, 71, 127, 41, 53, -71, -99, 99, -14, 102, -15, 93, 66, 20, 12, 53, 84, -65, 23, 39, -57, 31, 61, -89, 13, -126, 5, -104, 101, -64, -90, -72, -89, -8, -14, 74, 48, 61, -49, 90, 89, 118, -109, -90, -49, -75, -47, -81, -23, 98, -25, -76, 31, -106, -48, 65, -104, 4, -21, -55, -17, -69, -37, 118, -71, -81, -127, -82, -107, 125, -46, 33, 50, 10, -6, 126, -124, 53, 14, 83, 19, 110, 23, 125, -116, 16, -81, -94, -112, -109, -79, 22, 8, 68, -19, -23, -93, -128
////                };
////
////                for (int i = 0; i < 100; i++) {
////                    long start = System.currentTimeMillis();
////                    byte[] result = qtf.Decrypt(keyHandle, cipher);
//////                    LogUtils.e("解密后数据:" + Arrays.toString(result));
////                    long endEncrypt = System.currentTimeMillis();
////                    byte[] plain = qtf.Encrypt(keyHandle, result);
////                    long endDecrypt = System.currentTimeMillis();
////                    LogUtils.e(id + "==>" + String.format("耗时测试[%d]结果: 数据长度 %d， 编码耗时 %dms， 解码耗时 %dms\n", i, cipher.length, endEncrypt - start, endDecrypt - endEncrypt));
////                }
////            }
////        }).start();
////
////
////        new Thread(new Runnable() {
////            @SuppressLint("DefaultLocale")
////            @Override
////            public void run() {
////                long id = Thread.currentThread().getId();
////                LogUtils.e("启动新线程进行测试: " + id);
////
////                byte[] plain = new byte[1024 * 1024 * 1];
////                Arrays.fill(plain, (byte) 0x51);
////                for (int i = 0; i < 100; i++) {
////                    long start = System.currentTimeMillis();
////                    byte[] cipher = qtf.Encrypt(keyHandle, plain);
////                    long endEncrypt = System.currentTimeMillis();
////                    byte[] result = qtf.Decrypt(keyHandle, cipher);
////                    long endDecrypt = System.currentTimeMillis();
////                    LogUtils.e(id  + "==>" + String.format("耗时测试[%d]结果: 数据长度 %d， 编码耗时 %dms， 解码耗时 %dms\n", i, plain.length, endEncrypt - start, endDecrypt - endEncrypt));
////                }
////            }
////        }).start();
//    }
}
