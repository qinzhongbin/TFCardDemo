package com.qasky.tfcarddemo;

import android.app.Application;
import android.view.Gravity;

import com.blankj.utilcode.util.LogUtils;
import com.blankj.utilcode.util.ToastUtils;
import com.blankj.utilcode.util.Utils;

public class App extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        Utils.init(App.this);
        ToastUtils.getDefaultMaker().setGravity(Gravity.CENTER, 0, 0);
        LogUtils.getConfig()
                .setGlobalTag("Qasky")
                .setBorderSwitch(false);
    }
}
