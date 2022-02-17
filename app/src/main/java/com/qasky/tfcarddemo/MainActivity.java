package com.qasky.tfcarddemo;

import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.EditText;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import com.blankj.utilcode.util.AppUtils;
import com.blankj.utilcode.util.ArrayUtils;
import com.blankj.utilcode.util.ConvertUtils;
import com.blankj.utilcode.util.DeviceUtils;
import com.blankj.utilcode.util.GsonUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.SDCardUtils;
import com.blankj.utilcode.util.StringUtils;
import com.blankj.utilcode.util.ThreadUtils;
import com.blankj.utilcode.util.TimeUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.qasky.tfcard.ConsultInfo;
import com.qasky.tfcard.QTF;
import com.qasky.tfcarddemo.dto.CleanOnlineBizKeyRequest;
import com.qasky.tfcarddemo.dto.CleanOnlineBizKeyResponse;
import com.qasky.tfcarddemo.dto.CreateOnlineBizKeyRequest;
import com.qasky.tfcarddemo.dto.CreateOnlineBizKeyResponse;
import com.qasky.tfcarddemo.dto.ExtServerConsultInfo;
import com.qasky.tfcarddemo.dto.ExtSyncQKeykInfoDto;
import com.qasky.tfcarddemo.dto.RestResult;
import com.qasky.tfcarddemo.dto.ServerConsultOnlineBizKeyRequest;
import com.qasky.tfcarddemo.dto.ServerConsultOnlineBizKeyResponse;
import com.qasky.tfcarddemo.gm.SM3Util;
import com.qasky.tfcarddemo.gm.SM4Util;
import com.qasky.tfcarddemo.okhttp.OkHttpUtil;

import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.InputStream;
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
    QTF mQTF = new QTF();

    //    armeabi-v7a不兼容HTTPS，使用18890端口
    String cts_pcAddr = "112.27.97.202:8890";

    String cts_pcAppName = "SCWJCTSSYM";
    String cts_pcConName = "SCWJCTSSYM";
    String cts_pcUserPin = "12222222";
    String ctc_pcAppName = "SCBCTC";
    String ctc_pcConName = "SCBCTC";
    String ctc_pcUserPin = "12222222";

    String keyAppSvrId = "WT-QKMS100_001";
    String secAuthKey = "JLz3wNv1g8cTbiOBMaE+xl+lEzvqeqYKghYk+rJZxAa8c+Aq8VCeMxi7u0a7vaHVWOjuePeXoM7JFEeAZy64xA==";
    String protectKey = "123456";
    byte[] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte[] encryptKey;
    byte[] decryptKey;
    byte[] hmacKey;

    String mCipherHexString;
    private String pcSoreId;
    private ConsultInfo consultInfo = new ConsultInfo();
    byte[] softKey;
    private String systemID;
    int consultKeyLen = 16;

    OkHttpClient client;
    AlertDialog waitingDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        LogUtils.d("设备信息：\n" +
                "制造商：" + DeviceUtils.getManufacturer() + "\n" +
                "型号：" + DeviceUtils.getModel() + "\n" +
                "Android版本：" + DeviceUtils.getSDKVersionName() + "\t" + DeviceUtils.getSDKVersionCode() + "\n" +
                "App版本：" + AppUtils.getAppVersionName() + "\t" + AppUtils.getAppVersionCode() + "\n" +
                "CPU架构：" + Arrays.toString(DeviceUtils.getABIs()) + "\n" +
                "Root：" + DeviceUtils.isDeviceRooted()
        );


        if (!SDCardUtils.isSDCardEnableByEnvironment()) {
            ToastUtils.showShort("TF卡不可用");
            return;
        }

       waitingDialog  = new AlertDialog.Builder(MainActivity.this).setMessage("loading").create();

        client = OkHttpUtil.getClient();
        getKeys();


        ((SwitchCompat) findViewById(R.id.modeSwitch)).setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    buttonView.setText("C2C");
                    findViewById(R.id.container_c2s).setVisibility(View.GONE);
                    findViewById(R.id.container_c2c).setVisibility(View.VISIBLE);
                } else {
                    buttonView.setText("C2S");
                    findViewById(R.id.container_c2s).setVisibility(View.VISIBLE);
                    findViewById(R.id.container_c2c).setVisibility(View.GONE);
                }
            }
        });

        findViewById(R.id.initRes).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        return mQTF.initRes(getPackageName());
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        ToastUtils.showShort("资源初始化" + (result ? "成功" : "失败"));
                    }
                });
            }
        });

        findViewById(R.id.destroyRes).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Void>() {
                    @Override
                    public Void doInBackground() throws Throwable {
                        mQTF.destroyRes();
                        return null;
                    }

                    @Override
                    public void onSuccess(Void result) {
                        ToastUtils.showShort("销毁资源成功");
                    }
                });
            }
        });

        findViewById(R.id.exportStoreId).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        return mQTF.exportStoreId();
                    }

                    @Override
                    public void onSuccess(String pcStoreId) {
                        pcSoreId = pcStoreId;
                        ToastUtils.showShort("pcStoreId = " + pcStoreId);
                    }
                });
            }
        });

        findViewById(R.id.exportSystemId).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        return mQTF.exportSystemId(cts_pcAppName, cts_pcConName);
                    }

                    @Override
                    public void onSuccess(String systemID) {
                        MainActivity.this.systemID = systemID;
                        ToastUtils.showShort("systemID = " + systemID);
                    }
                });
            }
        });

        findViewById(R.id.c2sNegotiateKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    @RequiresApi(api = Build.VERSION_CODES.O)
                    @Override
                    public void run() {

                        runOnUiThread(waitingDialog::show);

                        try {
                            String timestamp = String.valueOf(System.currentTimeMillis());
                            String authMsg_ctsConsult = pcSoreId + "," + cts_pcAppName + "," + cts_pcConName + "," + "16" + "," + keyAppSvrId + "," + timestamp;
                            String hmac = Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_ctsConsult.getBytes(StandardCharsets.UTF_8)));

                            Response response_ctsConsult = client.newCall(new Request.Builder()
                                    .url("https://" + cts_pcAddr + "/qkeyapply/serverConsultInfosByApp")
                                    .post(new FormBody.Builder()
                                            .add("storeId", pcSoreId)
                                            .add("appName", cts_pcAppName)
                                            .add("containerName", cts_pcConName)
                                            .add("keyLen", "16")
                                            .add("serverId", keyAppSvrId)
                                            .add("timestamp", timestamp)
                                            .add("hmac", hmac)
                                            .build())
                                    .build()).execute();

                            if (response_ctsConsult.isSuccessful()) {
                                RestResult<ExtServerConsultInfo> extServerConsultInfoRestResult = GsonUtils.fromJson(response_ctsConsult.body().string(), new TypeToken<RestResult<ExtServerConsultInfo>>() {}.getType());
                                if (extServerConsultInfoRestResult.getCode() == 0) {
                                    ToastUtils.showLong("CTS协商成功");

                                    ExtServerConsultInfo extServerConsultInfo = extServerConsultInfoRestResult.getData();

                                    String authMsg_extServerConsultInfo = String.join(",", extServerConsultInfo.toAuthMsgParams());
                                    String hmac_expect = Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_extServerConsultInfo.getBytes(StandardCharsets.UTF_8)));
                                    if (hmac_expect.equals(extServerConsultInfo.getHmac())) { // 校验HMAC
                                        String softQkey_encrypted_encoded = extServerConsultInfo.getSoftQkey();
                                        byte[] softQkey_encrypted = Base64.decode(softQkey_encrypted_encoded);
                                        byte[] softQkey = SM4Util.decrypt_CBC_Padding(decryptKey, iv, softQkey_encrypted);
                                        LogUtils.d("CTS协商软密钥：" + ConvertUtils.bytes2HexString(softQkey));

                                        // 客户端导出软密钥 与其对比 应一致
                                        consultInfo.checkCode = extServerConsultInfo.getCheckCode();
                                        consultInfo.flag = GsonUtils.toJson(new GsonBuilder().registerTypeAdapter(ExtSyncQKeykInfoDto.class, new TypeAdapter<ExtSyncQKeykInfoDto>() {
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
                                        }).create(), extServerConsultInfo.getFlag());
                                    }
                                }
                            }
                        } catch (IOException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchProviderException | IllegalBlockSizeException e) {
                            e.printStackTrace();
                        }
                        runOnUiThread(waitingDialog::dismiss);
                    }
                }).start();
            }
        });

        findViewById(R.id.getKeyHandleByC2S).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        return mQTF.getKeyHandleByC2S(cts_pcAppName, cts_pcConName, cts_pcUserPin, consultInfo.checkCode, consultInfo.flag);
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        ToastUtils.showShort("获取密钥句柄" + (result ? "成功" : "失败"));
                    }
                });
            }
        });

        findViewById(R.id.getAuthSyncFlag).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        String otherStoreId = ((EditText) findViewById(R.id.et_otherStoreId)).getText().toString();
                        return mQTF.getAuthSynFlag(otherStoreId, ctc_pcAppName, ctc_pcConName, ctc_pcUserPin);
                    }

                    @Override
                    public void onSuccess(String flag) {
                        LogUtils.d("C2C同步认证码：\n" + flag);
                        ToastUtils.showShort("C2C同步认证码获取成功");
                    }
                });
            }
        });

        findViewById(R.id.c2cSyncAuth).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        String otherStoreId = ((EditText) findViewById(R.id.et_otherStoreId)).getText().toString();
                        String authSynFlag = ((EditText) findViewById(R.id.et_authSynFlag)).getText().toString();
                        return mQTF.authSynFlag(otherStoreId, ctc_pcAppName, ctc_pcConName, ctc_pcUserPin, authSynFlag);
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        ToastUtils.showShort("C2C同步认证" + (result ? "成功" : "失败"));
                    }
                });
            }
        });

        findViewById(R.id.getKeyHandleByC2C).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        String otherStoreId = ((EditText) findViewById(R.id.et_otherStoreId)).getText().toString();
                        String authSynFlag = ((EditText) findViewById(R.id.et_authSynFlag)).getText().toString();
                        return mQTF.getKeyHandleByC2C(otherStoreId, authSynFlag, ctc_pcAppName, ctc_pcConName, ctc_pcUserPin);
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        ToastUtils.showShort("获取密钥句柄" + (result ? "成功" : "失败"));
                    }
                });
            }
        });

        findViewById(R.id.hardEncrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
                    @Override
                    public byte[] doInBackground() throws Throwable {
                        byte[] plainBytes = ((EditText) findViewById(R.id.plain)).getText().toString().getBytes();

                        int padLength = 16 - plainBytes.length % 16;
                        byte[] paddedBytes = new byte[plainBytes.length + padLength];
                        System.arraycopy(plainBytes, 0, paddedBytes, 0, plainBytes.length);

                        String paddedHexString = ConvertUtils.bytes2HexString(paddedBytes);
                        LogUtils.d("硬加密明文：" + paddedHexString + "（已填充）");
                        return mQTF.hardEncrypt(paddedBytes);
                    }

                    @Override
                    public void onSuccess(byte[] result) {
                        mCipherHexString = ConvertUtils.bytes2HexString(result);
                        LogUtils.d("硬加密密文：" + mCipherHexString);
                    }
                });
            }
        });

        findViewById(R.id.hardDecrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
                    @Override
                    public byte[] doInBackground() throws Throwable {
                        LogUtils.d("硬解密密文：" + mCipherHexString);
                        byte[] cipherBytes = ConvertUtils.hexString2Bytes(mCipherHexString);
                        return mQTF.hardDecrypt(cipherBytes);
                    }

                    @Override
                    public void onSuccess(byte[] result) {
                        int plainLength = 0;

                        for (int i = result.length - 1; i >= 0; i--) {
                            if (result[i] != 0) {
                                plainLength = i + 1;
                                break;
                            }
                        }

                        LogUtils.d("硬解密明文：" + new String(result, 0, plainLength));
                    }
                });
            }
        });

        findViewById(R.id.exportSoftKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        softKey = mQTF.getSoftKey();

                        StringBuilder key = new StringBuilder();
                        for (byte b : softKey) {
                            key.append(String.format("%02X", b));
                        }

                        return ConvertUtils.bytes2HexString(softKey);
                    }

                    @Override
                    public void onSuccess(String result) {
                        ToastUtils.showShort("软密钥：\n" + result);
                    }
                });
            }
        });

        findViewById(R.id.softEncrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
                    @Override
                    public byte[] doInBackground() throws Throwable {
                        byte[] plainBytes = ((EditText) findViewById(R.id.plain)).getText().toString().getBytes();

                        int padLength = 16 - plainBytes.length % 16;
                        byte[] paddedBytes = new byte[plainBytes.length + padLength];
                        System.arraycopy(plainBytes, 0, paddedBytes, 0, plainBytes.length);

                        String paddedHexString = ConvertUtils.bytes2HexString(paddedBytes);
                        LogUtils.d("软加密明文：" + paddedHexString + "（已填充）");
                        return mQTF.sm4SoftEncrypt(paddedBytes, softKey);
                    }

                    @Override
                    public void onSuccess(byte[] result) {
                        mCipherHexString = ConvertUtils.bytes2HexString(result);
                        LogUtils.d("软加密密文：" + mCipherHexString);
                    }
                });
            }
        });

        findViewById(R.id.softDecrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
                    @Override
                    public byte[] doInBackground() throws Throwable {
                        LogUtils.d("软解密密文：" + mCipherHexString);
                        byte[] cipherBytes = ConvertUtils.hexString2Bytes(mCipherHexString);
                        return mQTF.sm4SoftDecrypt(cipherBytes, softKey);
                    }

                    @Override
                    public void onSuccess(byte[] result) {
                        LogUtils.d("软解密明文：" + ConvertUtils.bytes2HexString(result) + "已填充");

                        int plainLength = 0;

                        for (int i = result.length - 1; i >= 0; i--) {
                            if (result[i] != 0) {
                                plainLength = i + 1;
                                break;
                            }
                        }

                        LogUtils.d("软解密明文：" + new String(result, 0, plainLength));
                    }
                });
            }
        });

        findViewById(R.id.queryKeyLength).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<int[]>() {
                    @Override
                    public int[] doInBackground() throws Throwable {
                        return mQTF.queryKeyLength(cts_pcAppName, cts_pcConName, pcSoreId);
                    }

                    @Override
                    public void onSuccess(int[] result) {
                        if (result != null) {
                            ToastUtils.showShort("总长度：" + result[0]
                                    + "\n已使用：" + result[1]
                                    + "\n剩余量：" + result[2]);
                        } else {
                            ToastUtils.showShort("查询密钥失败");
                        }
                    }
                });
            }
        });

        findViewById(R.id.onlineChargingKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        return mQTF.onlineChargingKey(cts_pcAddr, cts_pcAppName, cts_pcConName, cts_pcUserPin);
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        ToastUtils.showShort("密钥充注" + (result ? "成功\n密钥长度不少于2048" : "失败"));
                    }
                });
            }
        });

        findViewById(R.id.exportEncCert).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
//                    @Override
//                    public String doInBackground() throws Throwable {
//                        byte[] encCert = mQTF.exportCert(cts_pcAppName, cts_pcConName, 0);
//                        return ConvertUtils.bytes2HexString(encCert);
//                    }
//
//                    @Override
//                    public void onSuccess(String result) {
//                        LogUtils.d("加密证书：\n" + result);
//                        ToastUtils.showShort("成功");
//                    }
//                });

                byte[] encCert = mQTF.exportCert(cts_pcAppName, cts_pcConName, 0);
                LogUtils.d(ConvertUtils.bytes2HexString(encCert));

            }
        });

        findViewById(R.id.exportSignCert).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        byte[] encCert = mQTF.exportCert(cts_pcAppName, cts_pcConName, 1);
                        return ConvertUtils.bytes2HexString(encCert);
                    }

                    @Override
                    public void onSuccess(String result) {
                        LogUtils.d("签名证书：\n" + result);
                        ToastUtils.showShort("成功");
                    }
                });
            }
        });

        findViewById(R.id.exportEncPubKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        byte[] encCert = mQTF.exportPubKey(cts_pcAppName, cts_pcConName, 0);
                        return ConvertUtils.bytes2HexString(encCert);
                    }

                    @Override
                    public void onSuccess(String result) {
                        LogUtils.d("加密公钥：\n" + result);
                        ToastUtils.showShort("成功");
                    }
                });
            }
        });

        findViewById(R.id.exportSignPubKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        byte[] encCert = mQTF.exportPubKey(cts_pcAppName, cts_pcConName, 1);
                        return ConvertUtils.bytes2HexString(encCert);
                    }

                    @Override
                    public void onSuccess(String result) {
                        LogUtils.d("签名公钥：\n" + result);
                        ToastUtils.showShort("成功");
                    }
                });
            }
        });

        findViewById(R.id.sm3Digest).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        InputStream inputStream = getResources().getAssets().open("量子安全移动存储介质密钥协商充注协议详细设计.docx");
                        byte[] bytes = ConvertUtils.inputStream2Bytes(inputStream);
                        byte[] digest = mQTF.sm3Digest(cts_pcAppName, cts_pcConName, cts_pcUserPin, bytes);
                        return ConvertUtils.bytes2HexString(digest);
                    }

                    @Override
                    public void onSuccess(String result) {
                        LogUtils.d("SM3计算摘要：\n" + result);
                        ToastUtils.showShort("成功");
                    }
                });
            }
        });

        findViewById(R.id.rsaSignDigest).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        byte[] digest = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
                        byte[] encCert = mQTF.RSASignDigest(cts_pcAppName, cts_pcConName, cts_pcUserPin, digest);
                        return ConvertUtils.bytes2HexString(encCert);
                    }

                    @Override
                    public void onSuccess(String result) {
                        LogUtils.d("RSA签名：\n" + result);
                        ToastUtils.showShort("成功");
                    }
                });
            }
        });

        findViewById(R.id.eccSignDigest).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
                    @Override
                    public String doInBackground() throws Throwable {
                        byte[] digest = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
                        byte[] encCert = mQTF.ECCSignDigest(cts_pcAppName, cts_pcConName, cts_pcUserPin, digest);
                        return ConvertUtils.bytes2HexString(encCert);
                    }

                    @Override
                    public void onSuccess(String result) {
                        LogUtils.d("ECC签名：\n" + result);
                        ToastUtils.showShort("成功");
                    }
                });
            }
        });

        findViewById(R.id.verifyPin).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        return mQTF.verifyAppPIN(cts_pcAppName, cts_pcUserPin, 0);
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        ToastUtils.showShort(result ? "成功" : "失败");
                    }
                });
            }
        });


        findViewById(R.id.clientRequestOnlineBizKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new Thread(new Runnable() {
                            @Override
                            public void run() {
                                runOnUiThread(waitingDialog::show);

                                // step 1: 服务端创建在线业务密钥
                                Calendar calendar = Calendar.getInstance();
                                calendar.add(Calendar.YEAR, 1);
                                CreateOnlineBizKeyRequest createRequest = new CreateOnlineBizKeyRequest();
                                createRequest.setSecretSize(consultKeyLen);
                                createRequest.setValidityDate(TimeUtils.date2String(calendar.getTime()));
                                createRequest.setSystemId(systemID);
                                createRequest.setServerId(keyAppSvrId);
                                createRequest.setTimestamp(System.currentTimeMillis());
                                String authMsg_create = createRequest.getSecretSize() + "," + createRequest.getValidityDate() + "," + createRequest.getSystemId() + "," + createRequest.getServerId() + "," + createRequest.getTimestamp();
                                createRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_create.getBytes(StandardCharsets.UTF_8))));
                                try {
                                    Response response_create = client.newCall(new Request.Builder()
                                            .url("https://" + cts_pcAddr + "/onlinebizkey/createOnlineBizKey")
                                            .post(RequestBody.create(GsonUtils.toJson(createRequest), MediaType.parse("application/json; charset=utf-8")))
                                            .build()).execute();
                                    if (response_create.isSuccessful()) {
                                        CreateOnlineBizKeyResponse createResponse = GsonUtils.fromJson(response_create.body().string(), CreateOnlineBizKeyResponse.class);
                                        if (createResponse.getCode() == 0) {
                                            String secretId = createResponse.getData().getSecretId();

                                            // step 2: 服务端协商在线业务密钥
                                            ServerConsultOnlineBizKeyRequest consultRequest = new ServerConsultOnlineBizKeyRequest();
                                            consultRequest.setSecretId(secretId);
                                            consultRequest.setSystemId(systemID);
                                            consultRequest.setServerId(keyAppSvrId);
                                            consultRequest.setTimestamp(String.valueOf(System.currentTimeMillis()));
                                            String authMsg_consult = consultRequest.getSecretId() + "," + consultRequest.getSystemId() + "," + consultRequest.getServerId() + "," + consultRequest.getTimestamp();
                                            consultRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_consult.getBytes(StandardCharsets.UTF_8))));
                                            Response response_consult = client.newCall(new Request.Builder()
                                                    .url("https://" + cts_pcAddr + "/onlinebizkey/serverNegotiateOnlineBizKey")
                                                    .post(RequestBody.create(GsonUtils.toJson(consultRequest), MediaType.parse("application/json; charset=utf-8")))
                                                    .build()).execute();
                                            if (response_consult.isSuccessful()) {
                                                ServerConsultOnlineBizKeyResponse consultResponse = GsonUtils.fromJson(response_consult.body().string(), ServerConsultOnlineBizKeyResponse.class);
                                                if (consultResponse.getCode() == 0) {
                                                    String secretKey_encrypted_base64 = consultResponse.getData().getSecretKey();
                                                    byte[] secretKey_encrypted = Base64.decode(secretKey_encrypted_base64);
                                                    byte[] bizKey = SM4Util.decrypt_CBC_Padding(decryptKey, iv, secretKey_encrypted);
                                                    LogUtils.d("业务密钥：" + ConvertUtils.bytes2HexString(bizKey));

                                                    // step 3: 客户端协商在线业务密钥
                                                    Thread.sleep(1000L); // 在服务端协商时间基础上短暂延迟客户端协商时间，否则会概率出现协商失败。
                                                    consultInfo = mQTF.clientRequestOnlineBizKey(cts_pcAddr, pcSoreId, systemID, secretId, keyAppSvrId, secAuthKey, protectKey);
                                                    // step 4: 获取密钥句柄
                                                    // step 5: 导出软密钥
                                                    // step 6: 对比客户端软密钥与服务端业务密钥是否一致
                                                    // step 7: 服务端销毁在线业务密钥
                                                    CleanOnlineBizKeyRequest cleanRequest = new CleanOnlineBizKeyRequest();
                                                    cleanRequest.setSecretId(secretId);
                                                    cleanRequest.setSystemId(systemID);
                                                    cleanRequest.setServerId(keyAppSvrId);
                                                    cleanRequest.setTimestamp(String.valueOf(System.currentTimeMillis()));
                                                    String authMsg_clean = cleanRequest.getSecretId() + "," + cleanRequest.getSystemId() + "," + cleanRequest.getServerId() + "," + cleanRequest.getTimestamp();
                                                    cleanRequest.setHmac(Base64.toBase64String(SM3Util.hmac(hmacKey, authMsg_clean.getBytes(StandardCharsets.UTF_8))));

                                                    Response response_clean = client.newCall(new Request.Builder()
                                                            .url("https://" + cts_pcAddr + "/onlinebizkey/cleanNegotiateOnlineBizKey")
                                                            .post(RequestBody.create(GsonUtils.toJson(cleanRequest), MediaType.parse("application/json; charset=utf-8"))).build()).execute();
                                                    if (response_clean.isSuccessful()) {
                                                        CleanOnlineBizKeyResponse cleanResponse = GsonUtils.fromJson(response_clean.body().string(), CleanOnlineBizKeyResponse.class);
                                                        if (cleanResponse.getCode() == 0) {
                                                            LogUtils.d("清除在线业务密钥成功");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } catch (IOException | InterruptedException | IllegalBlockSizeException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException e) {
                                    e.printStackTrace();
                                }
                                runOnUiThread(waitingDialog::dismiss);
                            }
                        }).start();
                    }
                }).start();
            }
        });

        findViewById(R.id.test).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
            }
        });
    }


    private void getKeys() {
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
}
