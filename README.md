# Android-Fingerprint-Signin

##Intro

Sample implementation of Android Fingerprint API introduced with Marshmallow 6.0.

The sample app attempts to provide a limited but highly functional set of utils specifically designed for encrypting and decrypting simple data blocks, such as passwords. On a call to encrypt or decrypt a datum, a fingerprint listening dialog is spawned that awaits a succesful scan, and then perfroms the registered callbacks.

Usage in an activity then becomes very simple, requiring implementation of only the relevant callbacks as well as permission and hardware feature checks. The activity takes an email and password as a keyvalue pair and encrypts the password with the user's fingerprint, and stores the encrypted datum under the user's email as a reference key.

## Usage

The main utility functions exist in the `FingerprintUtils` class. You can start an encrypt or decrypt task by getting a `FingerprintUtils` instance and calling the appropriate function with the approriate data and callbacks.

### How to Encrypt a key/value pair

This example shows how to encrypt a password and store the encrypted data under the corresponding email.

```
class MyActivity extends Activity {
  ...
  
  FingerprintUtils utils = FingerprintUtils.getInstance(this);
  if (isFingerprintAuthAvailable()) { 
    String email = ... ;
    String password = ... ;
    ICryptoAuthListener callback = ... ;
    fingerprintUtils.encrypt(getFragmentManager(), email, password, callback);
  }
  ...
}
```

The activity then displays a dialog that indicates to the user to scan their fingerprint, and shows relevant success or error messages upon a scan. 

### How to Decrypt a value for a given key

This example shows how to decrypt a password stored under a given email address.

```
class MyActivity extends Activity {
  ...
  
  FingerprintUtils utils = FingerprintUtils.getInstance(this);
  if (isFingerprintAuthAvailable()) { 
    String email = ... ;
    ICryptoAuthListener callback = ... ;
    if (!CryptoUtils.hasKey(email))  {
      Toast.makeText(CryptoActivity.this, "Key does not exist", Toast.LENGTH_SHORT).show(); 
    } else {
      fingerprintUtils.decrypt(getFragmentManager(), email, callback);
    }
  }
  ...
}
```

Note the use of `CryptoUtils` to determine if the provided key exists within the Cryptographic key store. `CryptoUtils` is provided as a generic access-layer to a `SharedPreferences` keystore for saving encrypted data, and provides helper methods for generating ciphers and other Cryptographic functions independent of Fingerprinting.

### Use of ICryptoAuthListener

The callback class is used to drive your own view and handle successful or unsuccessful efforts to store or retrieve an encrypted key/value pair.

```
    @Override
    public void onEncrypted(String encryptedData) {
        // Key has been encrypted. In our example, this may be from a first-time login, so after 
        // successful encryption we now proceed from login to the main app
    }

    @Override
    public void onDecrypted(String decryptedData) {
        // The value was decrypted for a given email. In our example, this means a user has entered
        // an email, then signed in using their fingerprint to retrieve their password, so we 
        // now authenticate the email and password (decryptedData) and proceed with login
    }

    @Override
    public void onFailure() {
        // Some unknown error occurred with reading the fingerprint or encrypting/decrypting the data. 
        // In our example, we can try again or force the user to login by manually entering the password
    }

    @Override
    public void onKeystoreInvalidated() {
        // If a user changes their fingerprint keystore by unenrolling their fingerprints from the device,
        // then this invalidates our generated ciphers for their stored keys.
        // We need to prompt the user to perform their enrollment again by starting a new encrypt task
    }
```

**Note** Classes other than an `Activity` can also start an encryption/decryption process, so long as they can provide a `Context` to retrieve an instance of the `FingerprintUtils` and a `FragmentManager` to show the resulting dialog.
