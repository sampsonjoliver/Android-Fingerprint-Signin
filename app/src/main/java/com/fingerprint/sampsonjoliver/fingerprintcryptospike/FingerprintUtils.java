package com.fingerprint.sampsonjoliver.fingerprintcryptospike;

import android.app.FragmentManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.support.annotation.RequiresPermission;
import android.support.annotation.VisibleForTesting;
import android.util.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static android.Manifest.permission.USE_FINGERPRINT;

public class FingerprintUtils {
    private static final String STORAGE_FILE_NAME = "fingerprint_crypto_service_credentials";

    private final Context context;
    private final SharedPreferences preferences;
    private static FingerprintUtils instance;

    private FingerprintUtils(Context context) {
        this.context = context;
        preferences = context.getSharedPreferences(STORAGE_FILE_NAME, Context.MODE_PRIVATE);
    }

    public static FingerprintUtils getInstance(Context context) {
        if (instance == null) {
            instance = new FingerprintUtils(context);
        }
        return instance;
    }

    public boolean hasFingerprintHardwareSupport() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT);
        }
        return false;
    }

    public void encrypt(FragmentManager fragmentManager, final String alias, final String data, final CryptoCallbacks callbacks) {
        try {
            final Cipher cipher = CryptoUtils.getCipher();
            CryptoUtils.createKey(alias);

            if (CryptoUtils.initCipher(cipher, alias, Cipher.ENCRYPT_MODE, null)) {
                byte[] iv = cipher.getIV();
                writeIv(alias, iv);

                // Show the dialog
                signCryptoWithFingerprint(fragmentManager, cipher, new SimpleCallbacks() {
                    @Override
                    public void onSuccess() {
                        try {
                            byte[] bytes = CryptoUtils.tryEncrypt(data, cipher);
                            writeEncryptedPassword(alias, bytes);
                            callbacks.onEncrypted(Base64.encodeToString(bytes, 0));
                        } catch (BadPaddingException | IllegalBlockSizeException | IOException e) {
                            e.printStackTrace();
                            callbacks.onFailure();
                        }
                    }
                });
            } else {
                // This happens if the lock screen has been disabled or a new fingerprint got enrolled.
                callbacks.onKeystoreInvalidated();
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            callbacks.onFailure();
        }
    }

    public void decrypt(FragmentManager fragmentManager, String alias, final CryptoCallbacks callbacks) {
        try {
            final Cipher cipher = CryptoUtils.getCipher();
            final byte[] iv = readIv(alias);

            if (CryptoUtils.initCipher(cipher, alias, Cipher.DECRYPT_MODE, iv)) {
                final byte[] encryptedPassword = readEncryptedPassword(alias);

                signCryptoWithFingerprint(fragmentManager, cipher, new FingerprintUtils.SimpleCallbacks() {
                    @Override
                    public void onSuccess() {
                        try {
                            byte[] bytes = CryptoUtils.tryDecrypt(encryptedPassword, cipher);
                            callbacks.onDecrypted(new String(bytes, 0, bytes.length, "UTF-8"));
                        } catch (BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
                            e.printStackTrace();
                            callbacks.onFailure();
                        }
                    }
                });

            } else {
                // This happens if the lock screen has been disabled or a new fingerprint got enrolled.
                callbacks.onKeystoreInvalidated();
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            callbacks.onFailure();
        }
    }

    private void signCryptoWithFingerprint(FragmentManager manager, Cipher cipher, FingerprintUtils.SimpleCallbacks callback) {
        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
        FingerprintAuthenticationDialogFragment fragment = new FingerprintAuthenticationDialogFragment();
        fragment.setCryptoObject(cryptoObject);
        fragment.setListener(callback);
        fragment.show(manager, FingerprintAuthenticationDialogFragment.TAG);
    }

    private void writeIv(String alias, byte[] iv) throws IOException {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(alias + "encryptionIv", Base64.encodeToString(iv, Base64.DEFAULT));
        editor.apply();
    }

    private byte[] readIv(String alias) throws IOException {
        String base64EncryptionIv = preferences.getString(alias + "encryptionIv", null);
        return Base64.decode(base64EncryptionIv, Base64.DEFAULT);
    }

    private void writeEncryptedPassword(String alias, byte[] passwordBytes) throws IOException {
        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(alias + "password", Base64.encodeToString(passwordBytes, Base64.DEFAULT));
        editor.apply();
    }

    private byte[] readEncryptedPassword(String alias) throws IOException {
        String base64EncryptedPassword = preferences.getString(alias + "password", null);
        return Base64.decode(base64EncryptedPassword, Base64.DEFAULT);
    }

    public interface CryptoCallbacks {
        void onEncrypted(String cryptoResult);
        void onDecrypted(String cryptoResult);
        void onFailure();
        void onKeystoreInvalidated();
    }

    public interface SimpleCallbacks {
        void onSuccess();
    }

    public interface Callbacks {
        void onStartedScan();
        void onAuthenticated();
        void onUnrecognised();
        void onUnrecoverableError(String message);
        void onRecoverableError(String message);
    }

    public static class FingerprintHelper extends FingerprintManager.AuthenticationCallback {
        private final Callbacks callback;
        private final FingerprintManager fingerprintManager;
        private CancellationSignal cancellationSignal;

        @VisibleForTesting
        boolean mSelfCancelled;

        public FingerprintHelper(Callbacks callback, Context context) {
            this.callback = callback;
            this.fingerprintManager = context.getSystemService(FingerprintManager.class);
        }

        @RequiresPermission(USE_FINGERPRINT)
        @SuppressWarnings("all")
        public void startListening(FingerprintManager.CryptoObject cryptoObject) {
            cancellationSignal = new CancellationSignal();
            mSelfCancelled = false;
            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
            callback.onStartedScan();
        }

        public void stopListening() {
            if (cancellationSignal != null) {
                mSelfCancelled = true;
                cancellationSignal.cancel();
                cancellationSignal = null;
            }
        }

        @Override
        public void onAuthenticationError(int errMsgId, CharSequence errString) {
            if (!mSelfCancelled) {
                callback.onUnrecoverableError(errString.toString());
            }
        }

        @Override
        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            callback.onRecoverableError(helpString.toString());
        }

        @Override
        public void onAuthenticationFailed() {
            callback.onUnrecognised();
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            callback.onAuthenticated();
        }

    }
}
