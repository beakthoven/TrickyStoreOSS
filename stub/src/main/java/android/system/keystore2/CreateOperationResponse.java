/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

public class CreateOperationResponse implements Parcelable {
    public IKeystoreOperation iOperation;
    public KeyParameters parameters;

    public static final Creator<CreateOperationResponse> CREATOR = new Creator<CreateOperationResponse>() {
        @Override
        public CreateOperationResponse createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public CreateOperationResponse[] newArray(int size) {
            throw new UnsupportedOperationException("STUB!");
        }
    };

    public CreateOperationResponse() {
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(@NonNull Parcel parcel, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
