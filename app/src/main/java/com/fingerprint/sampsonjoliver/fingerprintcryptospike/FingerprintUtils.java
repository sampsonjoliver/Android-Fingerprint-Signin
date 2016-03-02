package com.fingerprint.sampsonjoliver.fingerprintcryptospike;

import android.Manifest;
import android.app.FragmentManager;
import android.app.KeyguardManager;
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

    public boolean hasHardwareSupport() {
        if (hasApiSupport()) {
            if (BuildConfig.DEBUG)
                return true;
            return context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_FINGERPRINT);
        }
        return false;
    }

    public boolean hasSecureKeyguard() {
        return context.getSystemService(KeyguardManager.class).isKeyguardSecure();
    }

    public boolean hasApiSupport() {
        return (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M);
    }

    public boolean hasPermissionsGranted() {
        return context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED;
    }

    @SuppressWarnings("all")
    public boolean isFingerprintAuthAvailable() {
        FingerprintManager fingerprintManager = context.getSystemService(FingerprintManager.class);
        return fingerprintManager.isHardwareDetected()
                && fingerprintManager.hasEnrolledFingerprints();
    }

    public void encrypt(FragmentManager fragmentManager, final String alias, final String data, final ICryptoAuthListener callbacks) {
        try {
            final Cipher cipher = CryptoUtils.getCipher();
            CryptoUtils.createKey(alias);

            if (CryptoUtils.initCipher(cipher, alias, Cipher.ENCRYPT_MODE, null)) {
                byte[] iv = cipher.getIV();
                writeIv(alias, iv);

                // Show the dialog
                signCryptoWithFingerprint(fragmentManager, cipher, new IFingerprintResultListener() {
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

    public void decrypt(FragmentManager fragmentManager, String alias, final ICryptoAuthListener callbacks) {
        try {
            final Cipher cipher = CryptoUtils.getCipher();
            final byte[] iv = readIv(alias);

            if (CryptoUtils.initCipher(cipher, alias, Cipher.DECRYPT_MODE, iv)) {
                final byte[] encryptedPassword = readEncryptedPassword(alias);

                signCryptoWithFingerprint(fragmentManager, cipher, new IFingerprintResultListener() {
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

    private void signCryptoWithFingerprint(FragmentManager manager, Cipher cipher, IFingerprintResultListener callback) {
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

    public interface ICryptoAuthListener {
        void onEncrypted(String cryptoResult);
        void onDecrypted(String cryptoResult);
        void onFailure();
        void onKeystoreInvalidated();
    }

    public interface IFingerprintResultListener {
        void onSuccess();
    }

    public interface IFingerprintListener {
        void onScanStarted();
        void onScanFinished(boolean isRecognised);
        void onError(boolean isRecoverable, String message);
    }

    public static class FingerprintHelper extends FingerprintManager.AuthenticationCallback {
        private final IFingerprintListener callback;
        private final FingerprintManager fingerprintManager;
        private CancellationSignal cancellationSignal;

        @VisibleForTesting
        boolean mSelfCancelled;

        public FingerprintHelper(IFingerprintListener callback, Context context) {
            this.callback = callback;
            this.fingerprintManager = context.getSystemService(FingerprintManager.class);
        }

        @RequiresPermission(USE_FINGERPRINT)
        @SuppressWarnings("all")
        public void startListening(FingerprintManager.CryptoObject cryptoObject) {
            cancellationSignal = new CancellationSignal();
            mSelfCancelled = false;
            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
            callback.onScanStarted();
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
                callback.onError(false, errString.toString());
            }
        }

        @Override
        public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
            callback.onError(true, helpString.toString());
        }

        @Override
        public void onAuthenticationFailed() {
            callback.onScanFinished(false);
        }

        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            callback.onScanFinished(true);
        }
    }
}
