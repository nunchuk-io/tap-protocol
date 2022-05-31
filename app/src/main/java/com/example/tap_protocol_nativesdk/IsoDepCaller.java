package com.example.tap_protocol_nativesdk;

import android.nfc.tech.IsoDep;

import java.io.IOException;

public class IsoDepCaller {
    public static byte[] transceive(IsoDep isoDep, byte[] data) {
        try {
            byte[] resp = isoDep.transceive(data);
            return resp;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
