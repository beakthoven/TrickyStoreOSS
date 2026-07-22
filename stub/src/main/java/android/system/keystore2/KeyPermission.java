/*
 * Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.system.keystore2;

public class KeyPermission {
    public static final int NONE = 0;
    public static final int DELETE = 1;
    public static final int GEN_UNIQUE_ID = 2;
    public static final int GET_INFO = 4;
    public static final int GRANT = 8;
    public static final int MANAGE_BLOB = 16;
    public static final int REBIND = 32;
    public static final int REQ_FORCED_OP = 64;
    public static final int UPDATE = 128;
    public static final int USE = 256;
    public static final int USE_DEV_ID = 512;
    public static final int USE_NO_LSKF_BINDING = 1024;
    public static final int CONVERT_STORAGE_KEY_TO_EPHEMERAL = 2048;
}
