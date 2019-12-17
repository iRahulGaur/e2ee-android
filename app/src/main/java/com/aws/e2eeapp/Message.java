package com.aws.e2eeapp;

import android.annotation.SuppressLint;
import android.media.MediaScannerConnection;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

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
    private static final String TAG = "Message";
    private String secretKey = "this is a secret key";
    private String encryptedMessage;

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

            // Creates a file in the primary external storage space of the
            // current application.
            // If the file does not exists, it is created.
            File testFile = new File(this.getExternalFilesDir(null), "key.pub");

            // Adds a line to the file
            FileOutputStream writer = new FileOutputStream(testFile);
            writer.write(publicKey.getEncoded());
            writer.close();
            // Refresh the data so it can seen when the device is plugged in a
            // computer. You may have to unplug and replug the device to see the
            // latest changes. This is not necessary if the user should not modify
            // the files.
            MediaScannerConnection.scanFile(this,
                    new String[]{testFile.toString()},
                    null,
                    null);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.e(TAG, "initKeys: exception " + e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
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
            //get secretMessage using public key
            String decryptedSecretKey = Utils.decrypt(encryptedBytes, privateKey);

            Log.e(TAG, "getMessage: this is secret key used to encrypt the data : " + decryptedSecretKey);

            Log.e(TAG, "sendMessage: AES encrypted message in get Message : " + encryptedMessage);

            // decrypt the real message using the secretMessage
            String decryptedMessage = Utils.AESDecryptionString(encryptedMessage, decryptedSecretKey);
            decryptedTextView.setText(decryptedMessage + "");
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, "getMessage: exception in decryption ");
        }
    }

    @SuppressLint("SetTextI18n")
    private void sendMessage() {
        String message = messageEt.getText().toString();
        Log.e(TAG, "sendMessage: data size " + message.length());

        if (!message.isEmpty()) {
            try {

                // encrypting the real data with secretMessage
                encryptedMessage = Utils.AESEncryptionString(message, secretKey);
                Log.e(TAG, "sendMessage: AES encrypted message " + encryptedMessage);
                String dec = Utils.AESDecryptionString(encryptedMessage, secretKey);
                Log.e(TAG, "sendMessage: this is string decrypted in sendMessage " + dec);

                // Gets the file from the primary external storage space of the
                // current application.
                File testFile = new File(this.getExternalFilesDir(null), "key.pub");

                // Reads the data from the file
                FileInputStream reader;
                reader = new FileInputStream(testFile);

                byte[] b = new byte[1024];
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                int c;
                while ((c = reader.read(b)) != -1) {
                    os.write(b, 0, c);
                }

                // get the public key encoded from the file
                byte[] pubKeyEncoded = os.toByteArray();
                reader.close();

                // encrypt the secretKey message using public key
                encryptedBytes = Utils.encrypt(secretKey, pubKeyEncoded);
                String encryptedString = new String(encryptedBytes);
                Toast.makeText(this, "Message Encrypted ", Toast.LENGTH_SHORT).show();
                encryptedTextView.setText(encryptedString);
            } catch (Exception e) {
                e.printStackTrace();
                Log.e(TAG, "sendMessage: exception in encryption " + e.getMessage());
            }
        } else {
            Toast.makeText(this, "Please write a message", Toast.LENGTH_SHORT).show();
        }
    }

}
