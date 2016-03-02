package com.fingerprint.sampsonjoliver.fingerprintcryptospike;

import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoUtils {
    public static final String KEY_STORE_TYPE = "AndroidKeyStore";

    private static KeyStore getKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null);
            return keyStore;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean hasKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null);
            return keyStore.containsAlias(alias) && keyStore.isKeyEntry(alias);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean deleteKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null);
            keyStore.deleteEntry(alias);
            return true;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Creates a symmetric key in the Android Key Store.
     * This key can only be used once the user has authenticated with fingerprint.
     */
    public static SecretKey createKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null);

            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_STORE_TYPE);
            keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | KeyStoreException | CertificateException | IOException e) {
            throw new RuntimeException("Failed to create a symmetric key", e);
        }
    }

    /**
     * Get a new cryptographic cipher instance. This instance must be initialised using
     * {@link #initCipher(Cipher, String, int, byte[])} and then signed using a {@link FingerprintManager}
     * @return the new cipher instance
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static Cipher getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }

    /**
     * Initialize the {@link Cipher} instance with the created key in the {@link #createKey(String)}
     * method. Note: This REQUIRES that the key specified by {@param alias} exists
     *
     * @param cipher the cipher created by {@link #getCipher()}
     * @param alias the alias of the key in the KeyStore to encrypt/decrypt
     * @param mode one of {@link Cipher#DECRYPT_MODE} {@link Cipher#ENCRYPT_MODE}
     * @return {@code true} if initialization is successful, {@code false} if the lock screen has
     * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
     * the key was generated
     * @throws RuntimeException if the key alias does not exist
     */

    public static boolean initCipher(Cipher cipher, String alias, int mode, byte[] iv) throws RuntimeException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(null);

            SecretKey key = (SecretKey) keyStore.getKey(alias, null);
            if (mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, key);
            } else {
                IvParameterSpec ivParams = new IvParameterSpec(iv);
                cipher.init(mode, key, ivParams);
            }
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to init Cipher. This may be because the key's alias does not exist in the keystore.", e);
        }
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    public static byte[] tryEncrypt(String data, Cipher cipher) throws BadPaddingException, IllegalBlockSizeException {
        return cipher.doFinal(data.getBytes());
    }

    /**
     * Tries to decrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    public static byte[] tryDecrypt(byte[] data, Cipher cipher) throws BadPaddingException, IllegalBlockSizeException {
        return cipher.doFinal(data);
    }
}
