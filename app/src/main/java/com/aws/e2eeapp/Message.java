package com.aws.e2eeapp;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

/**
 * Created by Rahul Gaur on 16, December, 2019
 * Email: rahul.gaur152@gmail.com
 * Github: github.com/iRahulGaur
 */
public class Message extends AppCompatActivity {

    @BindView(R.id.userNameTV)
    TextView userNameTV;
    @BindView(R.id.messageEt)
    EditText messageEt;
    @BindView(R.id.sendBtn)
    Button sendBtn;
    @BindView(R.id.encryptedTextView)
    TextView encryptedTextView;
    @BindView(R.id.getTextBtn)
    Button getTextBtn;
    @BindView(R.id.decryptedTextView)
    TextView decryptedTextView;

    private PrivateKey privateKey;
    byte[] encryptedBytes = null;
    byte[] decryptedBytes = null;
    private static final String TAG = "Message";

    public PublicKey publicKey;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_message);
        ButterKnife.bind(this);

        initKeys();
    }

    private void initKeys() {
        try {
            KeyPair keyPair = Utils.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.e(TAG, "initKeys: exception " + e.getMessage());
        }
    }

    @OnClick({R.id.sendBtn, R.id.getTextBtn})
    public void onViewClicked(View view) {
        switch (view.getId()) {
            case R.id.sendBtn:
                sendMessage();
                break;
            case R.id.getTextBtn:
                getMessage();
                break;
        }
    }

    @SuppressLint("SetTextI18n")
    private void getMessage() {
        try {
            decryptedBytes = Utils.decrypt(privateKey.getEncoded(), encryptedBytes);
            String decryptedString = new String(decryptedBytes);

            Log.e(TAG, "getMessage: data decrypted " + decryptedString);
            decryptedTextView.setText(decryptedString + "");
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, "getMessage: exception in decryption ");
        }
    }

    @SuppressLint("SetTextI18n")
    private void sendMessage() {
        String message = messageEt.getText().toString();

        if (!message.isEmpty()) {
            try {
                encryptedBytes = Utils.encrypt(publicKey.getEncoded(), message.getBytes(StandardCharsets.UTF_8));
                encryptedTextView.setText(Arrays.toString(encryptedBytes));
                String ecryptedString = Arrays.toString(encryptedBytes);

                Toast.makeText(this, "Message Encrypted ", Toast.LENGTH_SHORT).show();
                encryptedTextView.setText(ecryptedString);
            } catch (Exception e) {
                e.printStackTrace();
                Log.e(TAG, "sendMessage: exception in encryption " + e.getMessage());
            }
        } else {
            Toast.makeText(this, "Please write a message", Toast.LENGTH_SHORT).show();
        }
    }

}
