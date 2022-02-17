package com.qasky.tfcarddemo;

import android.app.Application;
import android.view.Gravity;

import androidx.multidex.MultiDexApplication;

import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.blankj.utilcode.util.Utils;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jcajce.provider.digest.SM3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class App extends MultiDexApplication {


    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            System.out.println("security provider BC not found");
        }else {
            double version = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME).getVersion();
            System.out.println("old security provider BC's version is " + version);
            Security.removeProvider("BC");
        }
        Security.addProvider(new BouncyCastleProvider());
    }


    @Override
    public void onCreate() {
        super.onCreate();

        Utils.init(App.this);
        ToastUtils.getDefaultMaker().setGravity(Gravity.CENTER, 0, 0);
        LogUtils.getConfig()
                .setGlobalTag("QaSky")
                .setBorderSwitch(false);
    }
}
