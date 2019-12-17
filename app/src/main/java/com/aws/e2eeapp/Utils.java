package com.aws.e2eeapp;

import android.util.Log;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

import static android.content.ContentValues.TAG;

/**
 * Created by Rahul Gaur on 16, December, 2019
 * Email: rahul.gaur152@gmail.com
 * Github: github.com/iRahulGaur
 */
class Utils {

    private static final String ALGORITHM = "RSA";

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
    * in our case = (2048 / 8) - 42 = 214 (char)
    * */

    static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);

        keyGen.initialize(2048);

        KeyPair generateKeyPair = keyGen.generateKeyPair();

        Log.e(TAG, "generateKeyPair: this is public key encoding " + Arrays.toString(generateKeyPair.getPrivate().getEncoded()));

        return generateKeyPair;
    }

    static byte[] encrypt(String plainText, byte[] publicKeyEncoded) throws Exception {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-1ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");

        PublicKey publicKey =
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyEncoded));

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Perform Encryption

        return cipher.doFinal(plainText.getBytes());
    }

    static String decrypt(byte[] cipherTextArray, PrivateKey privateKey) throws Exception {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-1ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Perform Decryption
        byte[] decryptedTextArray = cipher.doFinal(cipherTextArray);

        return new String(decryptedTextArray);
    }
}
