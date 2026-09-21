package com.example.syshook;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.util.TypedValue;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final String TAG = "SysHookTest";

    static {
        System.loadLibrary("native_test");
    }

    private static native String nativeRunSelfTest();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String result;
        try {
            result = nativeRunSelfTest();
        } catch (Throwable t) {
            result = "native self-test threw: " + t;
        }
        Log.i(TAG, result);

        TextView tv = new TextView(this);
        tv.setPadding(32, 32, 32, 32);
        tv.setTextIsSelectable(true);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        tv.setText(result);

        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);
    }
}
