package com.aws.e2eeapp;

import android.util.Log;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
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

    static byte[] encrypt(byte[] publicKey, byte[] inputData)
            throws Exception {

        PublicKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePublic(new X509EncodedKeySpec(publicKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(inputData);
    }

    static byte[] decrypt(byte[] privateKey, byte[] inputData)
            throws Exception {

        PrivateKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(inputData);
    }

    static KeyPair generateKeyPair()
            throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);

        keyGen.initialize(512);

        KeyPair generateKeyPair = keyGen.generateKeyPair();

        Log.e(TAG, "generateKeyPair: this is public key encoding " + Arrays.toString(generateKeyPair.getPrivate().getEncoded()));

        return generateKeyPair;
    }
}
