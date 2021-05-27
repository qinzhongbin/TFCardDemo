package com.qasky.tfcarddemo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;

import com.blankj.utilcode.util.ConvertUtils;
import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.SDCardUtils;
import com.blankj.utilcode.util.ThreadUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.qasky.tfcard.C2SNegotiateInfo;
import com.qasky.tfcard.TFCard;

import java.util.Arrays;

public class MainActivity extends AppCompatActivity {
    TFCard mTFCard = new TFCard();

    String pcAddr = "112.27.97.202:18890";
    String pcAppName = "SIMECC1";
    String pcConName = "SIMECC1";
    String pcUserPin = "12222222";

    private byte[] mCipherBytes;
    String mCipherHexString;
    private String mStoreId;
    private final C2SNegotiateInfo c2SNegotiateInfo = new C2SNegotiateInfo();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (!SDCardUtils.isSDCardEnableByEnvironment()) {
            ToastUtils.showShort("TF卡不可用");
            return;
        }

        findViewById(R.id.initRes).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
                    @Override
                    public Boolean doInBackground() throws Throwable {
                        return mTFCard.initRes(getPackageName());
                    }

                    @Override
                    public void onSuccess(Boolean result) {
                        ToastUtils.showShort("资源初始化" + (result ? "成功" : "失败"));
                    }
                });
            }
        });

//        findViewById(R.id.exportStoreId).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
//                    @Override
//                    public String doInBackground() throws Throwable {
//                        return mTFCard.getStoreId();
//                    }
//
//                    @Override
//                    public void onSuccess(String result) {
//                        mStoreId = result;
//                        ToastUtils.showShort("设备序列号：\n" + result);
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.mockC2SNegotiateKey).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
//                    @Override
//                    public Boolean doInBackground() throws Throwable {
//                        return mTFCard.mockC2SNegotiateKey(pcAddr, pcAppName, pcConName, mStoreId, c2SNegotiateInfo);
//                    }
//
//                    @Override
//                    public void onSuccess(Boolean result) {
//                        ToastUtils.showShort("C2S密钥协商" + (result ? "成功" : "失败"));
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.mockGetKeyHandle).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
//                    @Override
//                    public Boolean doInBackground() throws Throwable {
//                        return mTFCard.getKeyHandle(pcAppName, pcConName, pcUserPin, c2SNegotiateInfo.getCheckCode(), c2SNegotiateInfo.getFlag());
//                    }
//
//                    @Override
//                    public void onSuccess(Boolean result) {
//                        ToastUtils.showShort("获取密钥句柄" + (result ? "成功" : "失败"));
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.getSoftKey).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<String>() {
//                    @Override
//                    public String doInBackground() throws Throwable {
//                        byte[] bytes_softKey = mTFCard.getSoftKey();
//
//                        LogUtils.d(Arrays.toString(bytes_softKey));
//
//                        return ConvertUtils.bytes2HexString(bytes_softKey);
//                    }
//
//                    @Override
//                    public void onSuccess(String result) {
//                        ToastUtils.showShort("软密钥：\n" + result);
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.queryKeyLength).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<int[]>() {
//                    @Override
//                    public int[] doInBackground() throws Throwable {
//                        return mTFCard.queryKeyLength(pcAppName, pcConName, mStoreId);
//                    }
//
//                    @Override
//                    public void onSuccess(int[] result) {
//                        if (result != null) {
//                            ToastUtils.showShort("总长度：" + result[0]
//                                    + "\n已使用：" + result[1]
//                                    + "\n剩余量：" + result[2]);
//                        } else {
//                            ToastUtils.showShort("查询密钥失败");
//                        }
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.onlineChargingKey).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Boolean>() {
//                    @Override
//                    public Boolean doInBackground() throws Throwable {
//                        return mTFCard.onlineChargingKey(pcAddr, pcAppName, pcConName, pcUserPin);
//                    }
//
//                    @Override
//                    public void onSuccess(Boolean result) {
//                        ToastUtils.showShort("密钥充注" + (result ? "成功\n密钥长度不少于2048" : "失败"));
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.destroyRes).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<Void>() {
//                    @Override
//                    public Void doInBackground() throws Throwable {
//                        mTFCard.destroyRes();
//                        return null;
//                    }
//
//                    @Override
//                    public void onSuccess(Void result) {
//                        ToastUtils.showShort("销毁资源成功");
//                    }
//                });
//            }
//        });

//        findViewById(R.id.hardEncrypt).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
//                    @Override
//                    public byte[] doInBackground() throws Throwable {
//                        byte[] plainBytes = ((EditText) findViewById(R.id.plain)).getText().toString().getBytes();
//
////                        String plainHexString = ConvertUtils.bytes2HexString(plainBytes);
////                        LogUtils.d("硬加密明文：" + plainHexString);
//
//                        int padLength = 16 - plainBytes.length % 16;
//                        byte[] paddedBytes = new byte[plainBytes.length + padLength];
//                        System.arraycopy(plainBytes, 0, paddedBytes, 0, plainBytes.length);
//
//                        String paddedHexString = ConvertUtils.bytes2HexString(plainBytes);
//                        LogUtils.d("硬加密明文：" + paddedHexString);
//                        return mTFCard.hardEncrypt(paddedBytes);
//                    }
//
//                    @Override
//                    public void onSuccess(byte[] result) {
//                        mCipherBytes = result;
//                        mCipherHexString = ConvertUtils.bytes2HexString(result);
//                        LogUtils.d("硬加密密文：" + mCipherHexString);
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.hardDecrypt).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
//                    @Override
//                    public byte[] doInBackground() throws Throwable {
////                        String cipherHexString = ConvertUtils.bytes2HexString(cipherBytes);
////                        LogUtils.d("硬解密密文：" + cipherHexString);
////                        return mSuperSIM.hardDecrypt(MainActivity.this.cipherBytes);
//
//                        LogUtils.d("硬解密密文：" + mCipherHexString);
//                        byte[] cipherBytes = ConvertUtils.hexString2Bytes(mCipherHexString);
//                        return mTFCard.hardDecrypt(cipherBytes);
//                    }
//
//                    @Override
//                    public void onSuccess(byte[] result) {
//                        int plainLength = 0;
//
//                        for (int i = result.length - 1; i >= 0; i--) {
//                            if (result[i] != 0) {
//                                plainLength = i + 1;
//                                break;
//                            }
//                        }
//
////                        String plainHexString = ConvertUtils.bytes2HexString(result);
////                        LogUtils.d("硬解密明文：" + plainHexString);
////                        LogUtils.d("硬解密明文：" + ConvertUtils.bytes2String(result));
//                        LogUtils.d("硬解密明文：" + new String(result, 0, plainLength));
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.softEncrypt).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
//                    @Override
//                    public byte[] doInBackground() throws Throwable {
//                        byte[] plainBytes = ((EditText) findViewById(R.id.plain)).getText().toString().getBytes();
//                        String plainHexString = ConvertUtils.bytes2HexString(plainBytes);
//                        LogUtils.d("软加密明文：" + plainHexString);
//                        return mTFCard.sm4SoftEncrypt(plainBytes, c2SNegotiateInfo.getKey());
//                    }
//
//                    @Override
//                    public void onSuccess(byte[] result) {
//                        mCipherBytes = result;
//                        String cipherHexString = ConvertUtils.bytes2HexString(result);
//                        LogUtils.d("软加密密文：" + cipherHexString);
//                    }
//                });
//            }
//        });
//
//        findViewById(R.id.softDecrypt).setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View v) {
//                ThreadUtils.executeByIo(new ThreadUtils.SimpleTask<byte[]>() {
//                    @Override
//                    public byte[] doInBackground() throws Throwable {
//                        String cipherHexString = ConvertUtils.bytes2HexString(mCipherBytes);
//                        LogUtils.d("软解密密文：" + cipherHexString);
//                        return mTFCard.sm4SoftDecrypt(mCipherBytes, c2SNegotiateInfo.getKey());
//                    }
//
//                    @Override
//                    public void onSuccess(byte[] result) {
//                        String plainHexString = ConvertUtils.bytes2HexString(result);
//                        LogUtils.d("软解密明文：" + plainHexString);
//                    }
//                });
//            }
//        });
    }
}