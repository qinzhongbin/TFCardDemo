package com.qasky.tfcarddemo;

import static com.qasky.tfcarddemo.App.LOG_TAG;

import android.content.DialogInterface;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.LinearLayoutCompat;

import com.blankj.utilcode.util.ConvertUtils;
import com.blankj.utilcode.util.GsonUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.StringUtils;
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
    String appName = "QTFCTS";
    String conName = "QTFCTS";
    String pin = "12222222";
    String host = "112.27.97.202:8890";
    int softKeyLen = 16;

    String keyAppSvrId = "WT-QKMS100_001";
    String protectKey = "123456";
    String secAuthKey = "JLz3wNv1g8cTbiOBMaE+xl+lEzvqeqYKghYk+rJZxAa8c+Aq8VCeMxi7u0a7vaHVWOjuePeXoM7JFEeAZy64xA==";
    byte[] zeroIV = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte[] encryptKey;
    byte[] decryptKey;
    byte[] hmacKey;

    private QTF qtf = new QTF();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        init();
    }

    private void init() {
        byte[] cutProtectKey = Arrays.copyOfRange(SM3Util.hash(protectKey.getBytes(StandardCharsets.UTF_8)), 0, 16);
        byte[] keys = new byte[0];
        try {
            keys = SM4Util.decrypt_CBC_Padding(cutProtectKey, zeroIV, Base64.decode(secAuthKey.getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        encryptKey = Arrays.copyOfRange(keys, 0, 16);
        decryptKey = Arrays.copyOfRange(keys, 16, 32);
        hmacKey = Arrays.copyOfRange(keys, 32, 48);
    }

    public void expDevInfo(View view) {
        String deviceId = qtf.getDeviceId();
        LogUtils.d("设备id：" + deviceId);

        byte[] encCert = qtf.exportCert(0, appName, conName);
        String encCertPem = new String(encCert, StandardCharsets.UTF_8);
        Log.d(LOG_TAG, "加密证书：\n" + encCertPem);

        byte[] signCert = qtf.exportCert(1, appName, conName);
        String signCertPem = new String(signCert, StandardCharsets.UTF_8);
        Log.d(LOG_TAG, "签名证书：\n" + signCertPem);

        byte[] encPubKey = qtf.exportPubKey(0, appName, conName);
        String encPubKeyPem = new String(encPubKey, StandardCharsets.UTF_8);
        Log.d(LOG_TAG, "加密公钥：\n" + encPubKeyPem);

        byte[] signPubKey = qtf.exportPubKey(1, appName, conName);
        String signPubKeyPem = new String(signPubKey, StandardCharsets.UTF_8);
        Log.d(LOG_TAG, "签名公钥：\n" + signPubKeyPem);
    }

    public void CTSNegoFillQKey(View view) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (qtf.enumDevice(getPackageName())) {
                        if (qtf.loginDevice()) {
                            if (qtf.initResource()) {
                                String deviceId = qtf.getDeviceId();
                                int keyLength = qtf.queryKeyLength(deviceId, appName, conName);
                                qtf.chargeKey(host, appName, conName, pin, 16);

                                // 协商
                                String timestamp = String.valueOf(System.currentTimeMillis());
                                String authMsg = deviceId + "," + appName + "," + conName + "," + softKeyLen + "," + keyAppSvrId + "," + timestamp;
                                String hmac = Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg.getBytes(StandardCharsets.UTF_8)));
                                Request request = new Request.Builder()
                                        .url("https://" + host + "/qkeyapply/serverConsultInfosByApp")
                                        .post(new FormBody.Builder()
                                                .add("storeId", deviceId)
                                                .add("appName", appName)
                                                .add("containerName", conName)
                                                .add("keyLen", String.valueOf(softKeyLen))
                                                .add("serverId", keyAppSvrId)
                                                .add("timestamp", timestamp)
                                                .add("hmac", hmac)
                                                .build())
                                        .build();

                                Response response = OkHttpUtil.getClient().newCall(request).execute();
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
                                        LogUtils.d("服务端软密钥：0x" + ConvertUtils.bytes2HexString(softQkey)); // 客户端导出软密钥对比是否与服务端一致
                                        LogUtils.d("CTS密钥协商成功");

                                        long keyHandle = qtf.getKeyHandle(appName, conName, pin, data.getCheckCode(), data.getFlag().toOriginalOrderJson());
                                        byte[] cipher = qtf.encrypt(keyHandle, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                                        byte[] plain = qtf.decrypt(keyHandle, cipher);
                                        LogUtils.d(new String(plain, StandardCharsets.UTF_8));

                                        byte[] softKey = qtf.getSoftKey(keyHandle, softKeyLen);
                                        LogUtils.d("客户端软密钥：" + ConvertUtils.bytes2HexString(softKey));
                                        cipher = SM4Util.encrypt_CBC_Padding(softKey, zeroIV, "君不见，黄河之水天上来。".getBytes(StandardCharsets.UTF_8));
                                        plain = SM4Util.decrypt_CBC_Padding(softKey, zeroIV, cipher);
                                        LogUtils.d(new String(plain, StandardCharsets.UTF_8));

                                        qtf.freeKeyHandle(keyHandle);
                                    } else {
                                        LogUtils.d(restResult.getMessage());
                                    }
                                } else {
                                    LogUtils.d(response.message());
                                }

                                qtf.updateResource();
                                qtf.destroyResource();
                            }
                            qtf.logoutDevice();
                        }
                        qtf.freeDevices();
                    }
                } catch (Throwable e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public void CTSNegoOLQKey(View view) {
    }

    public void CTSNegoOLBizQKey(View view) {
    }
}
