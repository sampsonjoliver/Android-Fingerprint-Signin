package com.fingerprint.sampsonjoliver.fingerprintcryptospike;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.app.LoaderManager.LoaderCallbacks;
import android.content.CursorLoader;
import android.content.Loader;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.hardware.fingerprint.FingerprintManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
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
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import static android.Manifest.permission.READ_CONTACTS;

/**
 * A login screen that offers login via email/password.
 */
public class CryptoActivity extends AppCompatActivity implements LoaderCallbacks<Cursor>, FingerprintUtils.CryptoCallbacks {
    private static final String TAG = "CryptoActivity";
    private static final String IV_EXT = ".iv";
    private static final String PASS_EXT = ".pass";
    private static final String STORAGE_FILE_NAME = "credentials";

    private SharedPreferences sharedPreferences;

    private AutoCompleteTextView mEmailView;
    private EditText mPasswordView;
    private Button encryptBtn;
    private Button decryptButton;
    private Button delete;
    private ListView keystoreList;
    private TextView info;

    private FingerprintUtils fingerprintUtils;
    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;

    /**
     * Id to identity READ_CONTACTS permission request.
     */
    private static final int REQUEST_READ_CONTACTS = 0;
    private static final int REQUEST_USE_FINGERPRINT = 123;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_crypto);
        sharedPreferences = getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE);
        // Set up the login form.
        mEmailView = (AutoCompleteTextView) findViewById(R.id.email);
        populateAutoComplete();

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
                    FingerprintUtils.getInstance(CryptoActivity.this)
                            .encrypt(getFragmentManager(), email, password, CryptoActivity.this);
                }
            }
        });

        decryptButton.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                if (isFingerprintAuthAvailable()) {
                    String email = mEmailView.getText().toString();
                    FingerprintUtils.getInstance(CryptoActivity.this)
                            .decrypt(getFragmentManager(), email, CryptoActivity.this);
                }
            }
        });

        initCryptoServices();
        invalidateKeystoreList();

        if (!keyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            info.setText("Secure lock screen hasn't set up.\n");
        } else if (!fingerprintManager.hasEnrolledFingerprints()) {
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

    }

    @Override
    public void onKeystoreInvalidated() {

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
        fingerprintManager = getSystemService(FingerprintManager.class);
        keyguardManager = getSystemService(KeyguardManager.class);
        fingerprintUtils = FingerprintUtils.getInstance(this);
    }

    @SuppressWarnings("all")
    public boolean isFingerprintAuthAvailable() {
        if (!mayUseFingerprintReader()) {
            return false;
        } else {
            return fingerprintManager.isHardwareDetected()
                    && fingerprintManager.hasEnrolledFingerprints();
        }
    }

    private boolean mayUseFingerprintReader() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false;
        }

        if (checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED) {
            return true;
        }

        if (shouldShowRequestPermissionRationale(Manifest.permission.USE_FINGERPRINT)) {
            Snackbar.make(mEmailView, "Need dem FP permissions bruh", Snackbar.LENGTH_INDEFINITE)
                    .setAction(android.R.string.ok, new View.OnClickListener() {
                        @Override
                        @TargetApi(Build.VERSION_CODES.M)
                        public void onClick(View v) {
                            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_USE_FINGERPRINT);
                        }
                    });
        } else {
            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_USE_FINGERPRINT);
        }
        return false;
    }

    /**
     * Callback received when a permissions request has been completed.
     */
    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        if (requestCode == REQUEST_READ_CONTACTS) {
            if (grantResults.length == 1 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                populateAutoComplete();
            }
        } else if (requestCode == REQUEST_USE_FINGERPRINT) {
            if (grantResults.length == 1 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // todo nothing?
            }
        }
    }



    private void signCryptoWithFingerprint(Cipher cipher, FingerprintUtils.SimpleCallbacks callback) {
        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
        FingerprintAuthenticationDialogFragment fragment = new FingerprintAuthenticationDialogFragment();
        fragment.setCryptoObject(cryptoObject);
        fragment.setListener(callback);
        fragment.show(getFragmentManager(), "tag");
    }

    private void populateAutoComplete() {
        if (!mayRequestContacts()) {
            return;
        }

        getLoaderManager().initLoader(0, null, this);
    }

    private boolean mayRequestContacts() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        if (checkSelfPermission(READ_CONTACTS) == PackageManager.PERMISSION_GRANTED) {
            return true;
        }
        if (shouldShowRequestPermissionRationale(READ_CONTACTS)) {
            Snackbar.make(mEmailView, R.string.permission_rationale, Snackbar.LENGTH_INDEFINITE)
                    .setAction(android.R.string.ok, new View.OnClickListener() {
                        @Override
                        @TargetApi(Build.VERSION_CODES.M)
                        public void onClick(View v) {
                            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_READ_CONTACTS);
                        }
                    });
        } else {
            requestPermissions(new String[]{READ_CONTACTS}, REQUEST_READ_CONTACTS);
        }
        return false;
    }

    @Override
    public Loader<Cursor> onCreateLoader(int i, Bundle bundle) {
        return new CursorLoader(this,
                // Retrieve data rows for the device user's 'profile' contact.
                Uri.withAppendedPath(ContactsContract.Profile.CONTENT_URI,
                        ContactsContract.Contacts.Data.CONTENT_DIRECTORY), ProfileQuery.PROJECTION,

                // Select only email addresses.
                ContactsContract.Contacts.Data.MIMETYPE +
                        " = ?", new String[]{ContactsContract.CommonDataKinds.Email
                .CONTENT_ITEM_TYPE},

                // Show primary email addresses first. Note that there won't be
                // a primary email address if the user hasn't specified one.
                ContactsContract.Contacts.Data.IS_PRIMARY + " DESC");
    }

    @Override
    public void onLoadFinished(Loader<Cursor> cursorLoader, Cursor cursor) {
        List<String> emails = new ArrayList<>();
        cursor.moveToFirst();
        while (!cursor.isAfterLast()) {
            emails.add(cursor.getString(ProfileQuery.ADDRESS));
            cursor.moveToNext();
        }

        addEmailsToAutoComplete(emails);
    }

    @Override
    public void onLoaderReset(Loader<Cursor> cursorLoader) {

    }

    private void addEmailsToAutoComplete(List<String> emailAddressCollection) {
        //Create adapter to tell the AutoCompleteTextView what to show in its dropdown list.
        ArrayAdapter<String> adapter =
                new ArrayAdapter<>(CryptoActivity.this,
                        android.R.layout.simple_dropdown_item_1line, emailAddressCollection);

        mEmailView.setAdapter(adapter);
    }

    private interface ProfileQuery {
        String[] PROJECTION = {
                ContactsContract.CommonDataKinds.Email.ADDRESS,
                ContactsContract.CommonDataKinds.Email.IS_PRIMARY,
        };

        int ADDRESS = 0;
        int IS_PRIMARY = 1;
    }
}

