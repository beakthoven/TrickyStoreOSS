/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.os;

public class ServiceSpecificException extends RuntimeException {
    public final int errorCode;

    public ServiceSpecificException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ServiceSpecificException(int errorCode) {
        this.errorCode = errorCode;
    }
}
