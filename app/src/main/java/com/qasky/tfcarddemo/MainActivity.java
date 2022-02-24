package com.qasky.tfcarddemo;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.LinearLayoutCompat;

import com.blankj.utilcode.util.ConvertUtils;
import com.blankj.utilcode.util.GsonUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.TimeUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.google.android.material.textfield.TextInputLayout;
import com.google.gson.reflect.TypeToken;
import com.qasky.tfcard.NegotiateInfo;
import com.qasky.tfcard.QTF;
import com.qasky.tfcarddemo.dto.CleanOLBizKeyReq;
import com.qasky.tfcarddemo.dto.CleanOLBizKeyResp;
import com.qasky.tfcarddemo.dto.CreateOLBizKeyReq;
import com.qasky.tfcarddemo.dto.CreateOLBizKeyResp;
import com.qasky.tfcarddemo.dto.ExtServerConsultInfo;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

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
    QTF QTF = new QTF();

    HashMap<String, String> params = new HashMap<>();
    String host;
    String appName;
    String conName;
    String userPIN;
    String softKeyLen;
    String keyAppSvrId;
    String secAuthKey;
    String protectKey;
    String plain;

    byte[] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte[] encryptKey;
    byte[] decryptKey;
    byte[] hmacKey;

    OkHttpClient client;
    AlertDialog waitingDialog;
    AlertDialog paramsDialog;
    View customView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        client = OkHttpUtil.getClient();
        waitingDialog = new AlertDialog.Builder(MainActivity.this).setMessage("loading").create();
        customView = getLayoutInflater().inflate(R.layout.dialog_reset_params, null);
        paramsDialog = new AlertDialog.Builder(this)
                .setTitle("参数设置")
                .setView(customView)
                .setPositiveButton("确定", (dialog, which) -> resetParams())
                .setNegativeButton("取消", null)
                .create();

        resetParams();
    }

    private void resetParams() {
        params.clear();
        LinearLayoutCompat paramsView = customView.findViewById(R.id.params);
        for (int i = 0; i < paramsView.getChildCount(); i++) {
            EditText et = ((TextInputLayout) paramsView.getChildAt(i)).getEditText();
            params.put(et.getResources().getResourceEntryName(et.getId()), et.getEditableText().toString());
        }

        host = params.get("host");
        appName = params.get("appName");
        conName = params.get("conName");
        userPIN = params.get("userPIN");
        softKeyLen = params.get("softKeyLen");
        keyAppSvrId = params.get("keyAppSvrId");
        secAuthKey = params.get("secAuthKey");
        protectKey = params.get("protectKey");
        plain = params.get("plain");

        String protectKey = params.get("protectKey");
        String secAuthKey = params.get("secAuthKey");
        byte[] cutProtectKey = Arrays.copyOfRange(SM3Util.hash(protectKey.getBytes(StandardCharsets.UTF_8)), 0, 16);
        byte[] keys = new byte[0];
        try {
            keys = SM4Util.decrypt_CBC_Padding(cutProtectKey, iv, Base64.decode(secAuthKey.getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        encryptKey = Arrays.copyOfRange(keys, 0, 16);
        decryptKey = Arrays.copyOfRange(keys, 16, 32);
        hmacKey = Arrays.copyOfRange(keys, 32, 48);
    }

    public void resetParams(View view) {
        paramsDialog.show();
    }

    long handles;
    long devHandle;

    public void enumDev(View view) {
        long[] handleInfo = QTF.enumDev(getPackageName());
        if (handleInfo != null && handleInfo.length > 1) {
            handles = handleInfo[0];
            LogUtils.d("handles = 0x" + Long.toHexString(handles));

            String[] devHandles = Arrays.stream(handleInfo).skip(1).mapToObj(Long::toHexString).toArray(String[]::new);

            new AlertDialog.Builder(this)
                    .setTitle("选择设备")
                    .setCancelable(false)
                    .setItems(devHandles, (dialog, which) -> devHandle = Long.valueOf(devHandles[which], 16))
                    .create().show();
        }
    }

    public void freeDev(View view) {
        QTF.freeDev(handles);
        ToastUtils.showLong("释放设备");
    }

    public void loginDev(View view) {
        boolean success = QTF.loginDev(devHandle);
        ToastUtils.showLong("登录设备" + (success ? "成功" : "失败"));
    }

    public void logoutDev(View view) {
        boolean success = QTF.logoutDev(devHandle);
        ToastUtils.showLong("登录设备" + (success ? "成功" : "失败"));
    }

    public void initResource(View view) {
        boolean success = QTF.initResource(devHandle);
        ToastUtils.showLong("初始化资源" + (success ? "成功" : "失败"));
    }

    public void updateResource(View view) {
        boolean success = QTF.updateResource(devHandle);
        ToastUtils.showLong("更新资源" + (success ? "成功" : "失败"));
    }

    public void destroyResource(View view) {
        QTF.destroyResource(devHandle);
        ToastUtils.showLong("销毁资源");
    }

    String deviceId;

    public void getDevId(View view) {
        deviceId = QTF.getDeviceId(devHandle);
        ToastUtils.showLong("设备ID: " + deviceId);
    }

    String systemId;

    public void getSysId(View view) {
        systemId = QTF.getSystemId(devHandle, appName, conName);
        ToastUtils.showLong("系统ID: " + systemId);
    }

    public void queryKeyLength(View view) {
        long[] keyLenInfo = QTF.queryKeyLength(devHandle, appName, conName);
        ToastUtils.showLong("密钥总量: " + keyLenInfo[0] + "字节\n" + " 密钥已使用: " + keyLenInfo[1] + "字节");
    }

    public void chargeKey(View view) {
        new Thread(() -> {
            runOnUiThread(() -> waitingDialog.show());
            boolean success = QTF.chargeKey(devHandle, host, appName, conName, userPIN);
            ToastUtils.showLong("密钥充注" + (success ? "成功" : "失败"));
            runOnUiThread(() -> waitingDialog.dismiss());
        }).start();
    }

    List<NegotiateInfo> negoInfos = new ArrayList<>();

    public void CTSNegotiate(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                runOnUiThread(() -> waitingDialog.show());
                String timestamp = String.valueOf(System.currentTimeMillis());
                String authMsg = deviceId + "," + appName + "," + conName + "," + softKeyLen + "," + keyAppSvrId + "," + timestamp;
                String hmac = Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg.getBytes(StandardCharsets.UTF_8)));
                Request request = new Request.Builder()
                        .url("https://" + host + "/qkeyapply/serverConsultInfosByApp")
                        .post(new FormBody.Builder()
                                .add("storeId", deviceId)
                                .add("appName", appName)
                                .add("containerName", conName)
                                .add("keyLen", softKeyLen)
                                .add("serverId", keyAppSvrId)
                                .add("timestamp", timestamp)
                                .add("hmac", hmac)
                                .build())
                        .build();
                try {
                    Response response = client.newCall(request).execute();
                    if (response.isSuccessful()) {
                        RestResult<ExtServerConsultInfo> restResult = GsonUtils.fromJson(response.body().string(), new TypeToken<RestResult<ExtServerConsultInfo>>() {
                        }.getType());
                        if (restResult.getCode() == 0) {
                            ExtServerConsultInfo data = restResult.getData();
                            String hmac_expect = Base64.toBase64String(SM3Util.hmac(hmacKey, String.join(",", data.toAuthMsgParams()).getBytes(StandardCharsets.UTF_8)));
                            if (timestamp.equals(data.getTimestamp()) && hmac_expect.equals(data.getHmac())) { // 校验时间戳与hmac
                                ToastUtils.showLong("CTS密钥协商成功");
                                String softQkey_encrypted_encoded = data.getSoftQkey();
                                byte[] softQkey_encrypted = Base64.decode(softQkey_encrypted_encoded);
                                byte[] softQkey = SM4Util.decrypt_CBC_Padding(decryptKey, iv, softQkey_encrypted);
                                LogUtils.d("服务端软密钥：0x" + ConvertUtils.bytes2HexString(softQkey)); // 客户端导出软密钥对比是否与服务端一致
                                negoInfos.add(new NegotiateInfo(data.getFlag().toOriginalOrderJson(), data.getCheckCode()));
                            }
                        } else {
                            ToastUtils.showLong(restResult.getMessage());
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                runOnUiThread(() -> waitingDialog.dismiss());
            }
        }).start();
    }

    public void negoOLBizKey(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                runOnUiThread(waitingDialog::show);
                // step 1: 服务端创建在线业务密钥
                Calendar calendar = Calendar.getInstance();
                calendar.add(Calendar.YEAR, 1);
                CreateOLBizKeyReq createRequest = new CreateOLBizKeyReq();
                createRequest.setSecretSize(softKeyLen);
                createRequest.setValidityDate(TimeUtils.date2String(calendar.getTime()));
                createRequest.setSystemId(systemId);
                createRequest.setServerId(keyAppSvrId);
                createRequest.setTimestamp(System.currentTimeMillis());
                String authMsg_create = createRequest.getSecretSize() + "," + createRequest.getValidityDate() + "," + createRequest.getSystemId() + "," + createRequest.getServerId() + "," + createRequest.getTimestamp();
                createRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_create.getBytes(StandardCharsets.UTF_8))));
                try {
                    Response response_create = client.newCall(new Request.Builder()
                            .url("https://" + host + "/onlinebizkey/createOnlineBizKey")
                            .post(RequestBody.create(GsonUtils.toJson(createRequest), MediaType.parse("application/json; charset=utf-8")))
                            .build()).execute();
                    if (response_create.isSuccessful()) {
                        CreateOLBizKeyResp createResponse = GsonUtils.fromJson(response_create.body().string(), CreateOLBizKeyResp.class);
                        if (createResponse.getCode() == 0) {
                            String secretId = createResponse.getData().getSecretId();

                            // step 2: 服务端协商在线业务密钥
                            SvrNegoOLBizKeyReq svrNegoReq = new SvrNegoOLBizKeyReq();
                            svrNegoReq.setSecretId(secretId);
                            svrNegoReq.setSystemId(systemId);
                            svrNegoReq.setServerId(keyAppSvrId);
                            svrNegoReq.setTimestamp(String.valueOf(System.currentTimeMillis()));
                            String authMsg_svrNego = svrNegoReq.getSecretId() + "," + svrNegoReq.getSystemId() + "," + svrNegoReq.getServerId() + "," + svrNegoReq.getTimestamp();
                            svrNegoReq.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_svrNego.getBytes(StandardCharsets.UTF_8))));
                            Response response_svrNego = client.newCall(new Request.Builder()
                                    .url("https://" + host + "/onlinebizkey/serverNegotiateOnlineBizKey")
                                    .post(RequestBody.create(GsonUtils.toJson(svrNegoReq), MediaType.parse("application/json; charset=utf-8")))
                                    .build()).execute();
                            if (response_svrNego.isSuccessful()) {
                                SvrNegoOLBizKeyResp srvNegoResponse = GsonUtils.fromJson(response_svrNego.body().string(), SvrNegoOLBizKeyResp.class);
                                if (srvNegoResponse.getCode() == 0) {
                                    String secretKey_encrypted_encoded = srvNegoResponse.getData().getSecretKey();
                                    byte[] secretKey_encrypted = Base64.decode(secretKey_encrypted_encoded);
                                    byte[] secretKey = SM4Util.decrypt_CBC_Padding(decryptKey, iv, secretKey_encrypted);
                                    LogUtils.d("服务端在线业务密钥：0x" + ConvertUtils.bytes2HexString(secretKey));

                                    // step 3: 客户端协商在线业务密钥
                                    Thread.sleep(1000L); // 客户端协商时间应比服务端协商时间晚，模拟延时操作。
                                    NegotiateInfo negotiateInfo = QTF.negoOLBizKey(host, deviceId, systemId, secretId, keyAppSvrId, secAuthKey, protectKey);
                                    if (negotiateInfo != null) {
                                        ToastUtils.showLong("在线业务密钥协商成功");
                                        negoInfos.add(negotiateInfo);
                                    } else {
                                        ToastUtils.showLong("在线业务密钥协商失败");
                                    }

                                    // step 3.1: 获取密钥句柄
                                    // step 3.2: 导出软密钥
                                    // step 3.3: 对比客户端软密钥与服务端业务密钥是否一致
                                    // step 4: 服务端销毁在线业务密钥 (业务结束后调用)
                                    CleanOLBizKeyReq cleanRequest = new CleanOLBizKeyReq();
                                    cleanRequest.setSecretId(secretId);
                                    cleanRequest.setSystemId(systemId);
                                    cleanRequest.setServerId(keyAppSvrId);
                                    cleanRequest.setTimestamp(String.valueOf(System.currentTimeMillis()));
                                    String authMsg_clean = cleanRequest.getSecretId() + "," + cleanRequest.getSystemId() + "," + cleanRequest.getServerId() + "," + cleanRequest.getTimestamp();
                                    cleanRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_clean.getBytes(StandardCharsets.UTF_8))));
                                    Response response_clean = client.newCall(new Request.Builder()
                                            .url("https://" + host + "/onlinebizkey/cleanNegotiateOnlineBizKey")
                                            .post(RequestBody.create(GsonUtils.toJson(cleanRequest), MediaType.parse("application/json; charset=utf-8"))).build()).execute();
                                    if (response_clean.isSuccessful()) {
                                        CleanOLBizKeyResp cleanResponse = GsonUtils.fromJson(response_clean.body().string(), CleanOLBizKeyResp.class);
                                        if (cleanResponse.getCode() == 0) {
                                            LogUtils.d("清除在线业务密钥成功");
                                        } else {
                                            ToastUtils.showLong(cleanResponse.getMessage());
                                        }
                                    }
                                } else {
                                    ToastUtils.showLong(srvNegoResponse.getMessage());
                                }
                            }
                        } else {
                            ToastUtils.showLong(createResponse.getMessage());
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                runOnUiThread(waitingDialog::dismiss);
            }
        }).start();
    }

    long keyHandle;

    public void getKeyHandle(View view) {
        new AlertDialog.Builder(this)
                .setTitle("选择密钥协商信息检验码")
                .setItems(negoInfos.stream().map(NegotiateInfo -> NegotiateInfo.checkCode).toArray(String[]::new), (dialog, which) -> {
                    NegotiateInfo negotiateInfo = negoInfos.get(which);
                    keyHandle = QTF.getKeyHandle(devHandle, appName, conName, userPIN, negotiateInfo.checkCode, negotiateInfo.flag);
                    ToastUtils.showLong("获取密钥句柄成功");
                })
                .setCancelable(false)
                .create().show();
    }

    public void freeKeyHandle(View view) {
        QTF.freeKeyHandle(devHandle, keyHandle);
        ToastUtils.showLong("释放密钥句柄");
    }

    byte[] cipher;

    public void encrypt(View view) {
        cipher = QTF.encrypt(devHandle, keyHandle, plain.getBytes(StandardCharsets.UTF_8));
        ToastUtils.showLong("加密成功");
    }

    public void decrypt(View view) {
        byte[] plain = QTF.decrypt(devHandle, keyHandle, cipher);
        ToastUtils.showLong(new String(plain, StandardCharsets.UTF_8));
    }

    public void getSoftKey(View view) {
        byte[] softKey = QTF.getSoftKey(devHandle, keyHandle, Integer.parseInt(softKeyLen));
        ToastUtils.showLong(ConvertUtils.bytes2HexString(softKey));
    }

    public void test(View view) {

    }
}
