# Android-Fingerprint-Signin

Sample implementation of Android Fingerprint API introduced with Marshmallow 6.0.

The sample app attempts to provide a limited but highly functional set of utils specifically designed for encrypting and decrypting simple data blocks, such as passwords. On a call to encrypt or decrypt a datum, a fingerprint listening dialog is spawned that awaits a succesful scan, and then perfroms the registered callbacks.

Usage in an activity then becomes very simple, requiring implementation of only the relevant callbacks as well as permission and hardware feature checks.
