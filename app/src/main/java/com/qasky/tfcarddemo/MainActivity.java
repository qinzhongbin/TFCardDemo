package com.qasky.tfcarddemo;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;

import android.os.Bundle;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.EditText;

import com.blankj.utilcode.util.ConvertUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.SDCardUtils;
import com.blankj.utilcode.util.ThreadUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.qasky.tfcard.C2SNegotiateInfo;
import com.qasky.tfcard.QTF;

public class MainActivity extends AppCompatActivity {
    QTF mQTF = new QTF();

//    armeabi-v7a不兼容HTTPS，使用18890端口
//    String cts_pcAddr = "112.27.97.202:8890";
    String cts_pcAddr = "112.27.97.202:18890";

    String cts_pcAppName = "SCBCTS";
    String cts_pcConName = "SCBCTS";
    String cts_pcUserPin = "12222222";
    String ctc_pcAppName = "SCBCTC";
    String ctc_pcConName = "SCBCTC";
    String ctc_pcUserPin = "12222222";

    String mCipherHexString;
    private String pcSoreId;
    private final C2SNegotiateInfo c2SNegotiateInfo = new C2SNegotiateInfo();
    byte[] softKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        if (!SDCardUtils.isSDCardEnableByEnvironment()) {
            ToastUtils.showShort("TF卡不可用");
            return;
        }

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

        findViewById(R.id.c2sNegotiateKey).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        return mQTF.mockC2SNegotiateKey(cts_pcAddr, cts_pcAppName, cts_pcConName, pcSoreId, c2SNegotiateInfo);
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        LogUtils.d(c2SNegotiateInfo);
                        ToastUtils.showShort("C2S密钥协商" + (result ? "成功" : "失败"));
                    }
                });
            }
        });

        findViewById(R.id.getKeyHandleByC2S).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        return mQTF.getKeyHandleByC2S(cts_pcAppName, cts_pcConName, cts_pcUserPin, c2SNegotiateInfo.getCheckCode(), c2SNegotiateInfo.getFlag());
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
    }
}
