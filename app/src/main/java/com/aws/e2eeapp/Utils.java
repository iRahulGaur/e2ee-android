package com.aws.e2eeapp;

import android.annotation.SuppressLint;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import static android.content.ContentValues.TAG;

/**
 * Created by Rahul Gaur on 16, December, 2019
 * Email: rahul.gaur152@gmail.com
 * Github: github.com/iRahulGaur
 */
class Utils {

    private static final String ALGORITHM = "RSA";
    private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final String AES_PADDING = "AES/ECB/PKCS5PADDING";
    private static final String RSA__PADDING = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";

    /*
    * Padding sizes
        RSA/ECB/PKCS1Padding, 11
        RSA/ECB/NoPadding, 0
        RSA/ECB/OAEPPadding, 42 // Actually it's OAEPWithSHA1AndMGF1Padding
        RSA/ECB/OAEPWithMD5AndMGF1Padding, 34
        RSA/ECB/OAEPWithSHA1AndMGF1Padding, 42
        RSA/ECB/OAEPWithSHA224AndMGF1Padding, 58
        RSA/ECB/OAEPWithSHA256AndMGF1Padding, 66
        RSA/ECB/OAEPWithSHA384AndMGF1Padding, 98
        RSA/ECB/OAEPWithSHA512AndMGF1Padding, 130
        RSA/ECB/OAEPWithSHA3-224AndMGF1Padding, 58
        RSA/ECB/OAEPWithSHA3-256AndMGF1Padding, 66
        RSA/ECB/OAEPWithSHA3-384AndMGF1Padding, 98
        RSA/ECB/OAEPWithSHA3-512AndMGF1Padding, 130
    *
    * real data size will be = (block size / 8) - paddingSize
    * in our case = (2048 / 8) - 66  = 190 (char)
    *
    * AES padding = AES/ECB/PKCS5PADDING
    * */

    static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);

        keyGen.initialize(2048);

        KeyPair generateKeyPair = keyGen.generateKeyPair();

        //Log.e(TAG, "generateKeyPair: this is public key encoding " + Arrays.toString(generateKeyPair.getPrivate().getEncoded()));

        return generateKeyPair;
    }

    static byte[] encrypt(String plainText, byte[] publicKeyEncoded) throws Exception {
        //Get Cipher Instance RSA With ECB Mode and OAEPWithSHA3-256AndMGF1Padding Padding
        Cipher cipher = Cipher.getInstance(RSA__PADDING);

        PublicKey publicKey =
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyEncoded));

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Perform Encryption

        return cipher.doFinal(plainText.getBytes());
    }

    static String decrypt(byte[] cipherTextArray, PrivateKey privateKey) throws Exception {
        //Get Cipher Instance RSA With ECB Mode and OAEPWithSHA3-256AndMGF1Padding Padding
        Cipher cipher = Cipher.getInstance(RSA__PADDING);

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }

    private static void setKey(String myKey) {
        MessageDigest sha;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
            Log.e(TAG, "setKey: this is AES secretKey = " + Arrays.toString(secretKey.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

/*
    static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return new String(cipher.doFinal(strToEncrypt.getBytes()));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] text = cipher.doFinal(strToDecrypt.getBytes());
            return new String(text);
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    */

    //for encryption
    @SuppressLint("GetInstance")
    static String AESEncryptionString(String stringData, String secret) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(AES_PADDING);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        setKey(secret);
        byte[] stringToByte = stringData.getBytes();
        byte[] encryptionByte = new byte[stringToByte.length];

        try {
            assert cipher != null;
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptionByte = cipher.doFinal(stringToByte);

        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        String returnData;
        returnData = new String(encryptionByte, StandardCharsets.ISO_8859_1);
        return returnData;
    }

    //DecryptString
    @SuppressLint("GetInstance")
    static String AESDecryptionString(String stringData, String secret) {
        Cipher decipher = null;
        byte[] encryptedString = stringData.getBytes(StandardCharsets.ISO_8859_1);
        String returnData = stringData;
        setKey(secret);
        try {
            decipher = Cipher.getInstance(AES_PADDING);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        byte[] decryption;
        try {
            assert decipher != null;
            decipher.init(Cipher.DECRYPT_MODE, secretKey);
            decryption = decipher.doFinal(encryptedString);
            returnData = new String(decryption);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return returnData;
    }

}
