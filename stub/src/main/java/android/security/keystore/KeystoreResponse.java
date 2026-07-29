/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.keystore;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class KeystoreResponse implements Parcelable {
    public final int error_code_;
    public final String error_msg_;

    protected KeystoreResponse(int error_code, String error_msg) {
        this.error_code_ = error_code;
        this.error_msg_ = error_msg;
    }

    @Override
    public void writeToParcel(@NonNull Parcel dest, int flags) {
        throw new RuntimeException("");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    public static final Creator<KeystoreResponse> CREATOR = new Creator<KeystoreResponse>() {
        @Override
        public KeystoreResponse createFromParcel(Parcel in) {
            throw new RuntimeException("");
        }

        @Override
        public KeystoreResponse[] newArray(int size) {
            throw new RuntimeException("");
        }
    };
}
