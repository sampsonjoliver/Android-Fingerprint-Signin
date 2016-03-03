/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.fingerprint.sampsonjoliver.fingerprintcryptospike;

import android.Manifest;
import android.app.DialogFragment;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 */
public class FingerprintScanDialog extends DialogFragment implements FingerprintUtils.IFingerprintListener {
    public static final String TAG = "FPAuthDialog";

    protected static final long ERROR_TIMEOUT_MILLIS = 1600;
    protected static final long SUCCESS_DELAY_MILLIS = 1300;

    protected String titleText;
    protected String descriptionText;
    protected String scanText;
    protected String scanSuccessText;
    protected String scanFailedText;

    private FingerprintManager.CryptoObject cryptoObject;

    private IFingerprintScanListener listener;
    private FingerprintUtils.FingerprintHelper fingerprintHelper;

    private ImageView icon;
    private TextView status;
    private TextView desc;

    public static FingerprintScanDialog newInstance(String title, String descriptionText, String scanText, String scanSuccessText, String scanFailedText, IFingerprintScanListener listener) {
        FingerprintScanDialog dialog = new FingerprintScanDialog();

        dialog.setTitleText(title);
        dialog.setDescriptionText(descriptionText);
        dialog.setScanText(scanText);
        dialog.setScanSuccessText(scanSuccessText);
        dialog.setScanFailedText(scanFailedText);
        dialog.listener = listener;

        return dialog;
    }

    public void setTitleText(String titleText) {
        this.titleText = titleText;
    }

    public void setDescriptionText(String descText) {
        this.descriptionText = descText;
    }

    public void setScanText(String scanText) {
        this.scanText = scanText;
    }

    public void setScanSuccessText(String scanSuccessText) {
        this.scanSuccessText = scanSuccessText;
    }

    public void setScanFailedText(String scanFailedText) {
        this.scanFailedText = scanFailedText;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);
        fingerprintHelper = new FingerprintUtils.FingerprintHelper(this, getContext());
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        getDialog().setTitle(titleText);

        View view = inflater.inflate(R.layout.dialog_fingerprint_scan, container, false);

        icon = (ImageView) view.findViewById(R.id.fingerprint_icon);
        status = (TextView) view.findViewById(R.id.fingerprint_status);
        desc = (TextView) view.findViewById(R.id.fingerprint_description);
        desc.setText(descriptionText);

        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        startListening(cryptoObject);
    }

    @Override
    public void onPause() {
        super.onPause();
        stopListening();
    }

    public void startListening(FingerprintManager.CryptoObject cryptoObject) {
        if (ActivityCompat.checkSelfPermission(getContext(), Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED) {
            fingerprintHelper.startListening(cryptoObject);
        }
    }

    public void stopListening() {
        fingerprintHelper.stopListening();
    }

     public void setCryptoObject(FingerprintManager.CryptoObject mCryptoObject) {
         this.cryptoObject = mCryptoObject;
     }

    public void setListener(IFingerprintScanListener listener) {
        this.listener = listener;
    }

    @Override
    public void onScanStarted() {
        icon.setImageResource(R.drawable.ic_fp_40px);
        status.setText(scanText);
    }

    @Override
    public void onScanFinished(boolean isRecognised) {
        icon.setImageResource(isRecognised ? R.drawable.ic_fingerprint_success : R.drawable.ic_fingerprint_error);
        status.setText(isRecognised ? scanSuccessText : scanFailedText);
        if (getView() != null) {
            if (isRecognised) {
                getView().postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        listener.onSuccess();
                        dismiss();
                    }
                }, SUCCESS_DELAY_MILLIS);
            } else {
                getView().postDelayed(mResetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
            }
        }
    }

    @Override
    public void onError(boolean isRecoverable, String message) {
        icon.setImageResource(R.drawable.ic_fingerprint_error);
        status.setText(message);
        if (getView() != null) {
            getView().postDelayed(mResetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
        }
    }

    Runnable mResetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            status.setText(scanText);
            icon.setImageResource(R.drawable.ic_fp_40px);
        }
    };

    public interface IFingerprintScanListener {
        void onSuccess();
    }
}
