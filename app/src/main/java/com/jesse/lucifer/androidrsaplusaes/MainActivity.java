package com.jesse.lucifer.androidrsaplusaes;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.jesse.lucifer.androidrsaplusaes.encrypt.AES;
import com.jesse.lucifer.androidrsaplusaes.encrypt.RSA;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        encrypt("123456");
        decrypt();
    }

    private void encrypt(String content) {
        try {
            RSAPublicKey rsaPublicKey = RSA.loadPublicKey(getAssets().open("rsa_public_key.pem"));
            String aesKey=AES.generateKeyString();
            String encryptAesKey = RSA.encryptByPublicKey(aesKey, rsaPublicKey);
            String encryptContent = AES.encrypt(content, aesKey);
            TestData.data = encryptContent;
            TestData.sign = encryptAesKey;
            Log.e("Panda", "data after decrypt: " + TestData.data);
            Log.e("Panda", "sign after decrypt: " + TestData.sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void decrypt() {
        try {
            RSAPrivateKey rsaPrivateKey = RSA.loadPrivateKey(getAssets().open("rsa_private_key.pem"));
            //解密AES-KEY
            String decryptAesKey = RSA.decryptByPrivateKey(TestData.sign, rsaPrivateKey);
            //AES解密数据
            String decrypt = AES.decrypt(TestData.data, decryptAesKey);
            Log.e("Panda", "data after encrypt: " + decrypt);
            Log.e("Panda", "sign after encrypt: " + decryptAesKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static class TestData {
        public static String data;
        public static String sign;
    }
}
