package com.fingerprint.sampsonjoliver.fingerprintcryptospike;

import android.annotation.TargetApi;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;

import static android.Manifest.permission.USE_FINGERPRINT;

/**
 * A login screen that offers login via email/password.
 */
public class CryptoActivity extends AppCompatActivity implements FingerprintUtils.ICryptoAuthListener {
    private AutoCompleteTextView mEmailView;
    private EditText mPasswordView;
    private Button encryptBtn;
    private Button decryptButton;
    private ListView keystoreList;
    private TextView info;

    private FingerprintUtils fingerprintUtils;

    /**
     * Id to identity READ_CONTACTS permission request.
     */
    private static final int REQUEST_USE_FINGERPRINT = 123;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_crypto);
        // Set up the login form.
        mEmailView = (AutoCompleteTextView) findViewById(R.id.email);

        mPasswordView = (EditText) findViewById(R.id.password);

        encryptBtn = (Button) findViewById(R.id.encrypt);
        decryptButton = (Button) findViewById(R.id.decrypt);

        keystoreList = (ListView) findViewById(R.id.keys);
        info = (TextView) findViewById(R.id.info);

        encryptBtn.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                if (isFingerprintAuthAvailable()) {
                    String email = mEmailView.getText().toString();
                    String password = mPasswordView.getText().toString();
                    fingerprintUtils.encrypt(getFragmentManager(), email, password, CryptoActivity.this);
                }
            }
        });

        decryptButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                if (isFingerprintAuthAvailable()) {
                    String email = mEmailView.getText().toString();
                    if (!CryptoUtils.hasKey(email))
                        Toast.makeText(CryptoActivity.this, "Key does not exist", Toast.LENGTH_SHORT).show();
                    fingerprintUtils.decrypt(getFragmentManager(), email, CryptoActivity.this);
                }
            }
        });

        initCryptoServices();
        invalidateKeystoreList();

        if (!fingerprintUtils.hasHardwareSupport()) {
            info.setText("No hardware support for fingerprinting, so no point going on.\n");
        } else if (!fingerprintUtils.hasSecureKeyguard()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            info.setText("Secure lock screen hasn't set up.\n");
        } else if (!fingerprintUtils.isFingerprintAuthAvailable()) {
            info.setText("Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint");
        } else {
            info.setText("Enrolled fingerprints and secure lockscreen detected. All good.");
        }
    }

    @Override
    public void onEncrypted(String encryptedData) {
        info.setText(encryptedData);
        invalidateKeystoreList();
    }

    @Override
    public void onDecrypted(String decryptedData) {
        info.setText(decryptedData);
        invalidateKeystoreList();
    }

    @Override
    public void onFailure() {
        Toast.makeText(this, "Something went wrong. Try again.", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onKeystoreInvalidated() {
        Toast.makeText(this, "Need to perform the enrollment process again", Toast.LENGTH_SHORT).show();
    }

    private void invalidateKeystoreList() {
        try {
            KeyStore keyStore = KeyStore.getInstance(CryptoUtils.KEY_STORE_TYPE);
            keyStore.load(null);
            ArrayList<String> keyAliases = new ArrayList<>();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                keyAliases.add(aliases.nextElement());
            }
            keystoreList.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, keyAliases));

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            Toast.makeText(this, "Couldn't build keystore list", Toast.LENGTH_SHORT).show();
        }
    }

    private void initCryptoServices() {
        fingerprintUtils = FingerprintUtils.getInstance(this);
    }

    @SuppressWarnings("all")
    public boolean isFingerprintAuthAvailable() {
        if (!mayUseFingerprintReader()) {
            return false;
        } else {
            return fingerprintUtils.isFingerprintAuthAvailable();
        }
    }

    private boolean mayUseFingerprintReader() {
        if (!fingerprintUtils.hasHardwareSupport() || !fingerprintUtils.hasApiSupport()) {
            return false;
        }

        if (fingerprintUtils.hasPermissionsGranted()) {
            return true;
        }

        if (shouldShowRequestPermissionRationale(USE_FINGERPRINT)) {
            Snackbar.make(mEmailView, "Need dem FP permissions bruh", Snackbar.LENGTH_INDEFINITE)
                    .setAction(android.R.string.ok, new View.OnClickListener() {
                        @Override
                        @TargetApi(Build.VERSION_CODES.M)
                        public void onClick(View v) {
                            requestPermissions(new String[]{USE_FINGERPRINT}, REQUEST_USE_FINGERPRINT);
                        }
                    });
        } else {
            requestPermissions(new String[]{USE_FINGERPRINT}, REQUEST_USE_FINGERPRINT);
        }
        return false;
    }

    /**
     * Callback received when a permissions request has been completed.
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        if (requestCode == REQUEST_USE_FINGERPRINT) {
            if (grantResults.length == 1 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // todo nothing?
            }
        }
    }
}

