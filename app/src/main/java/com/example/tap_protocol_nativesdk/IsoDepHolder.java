package com.example.tap_protocol_nativesdk;

import android.nfc.tech.IsoDep;
import java.io.IOException;

public class IsoDepHolder {
    volatile static private IsoDep isoDep;

    static public boolean isConnected() {
        synchronized (IsoDepHolder.class) {
            return isCreated() && isoDep.isConnected();
        }
    }

    static public boolean isCreated() {
        synchronized (IsoDepHolder.class) {
            return isoDep != null;
        }
    }

    static public String getID() {
        synchronized (IsoDepHolder.class) {
            return new String(isoDep.getTag().getId());
        }
    }

    static public void init(IsoDep isoDep) throws IOException {
        synchronized (IsoDepHolder.class) {
            if (!isoDep.equals(IsoDepHolder.isoDep)) {
                close();
                IsoDepHolder.isoDep = isoDep;
            }
            IsoDepHolder.isoDep.connect();
        }
    }

    static public byte[] transceive(byte[] data) throws IOException, InterruptedException {
        synchronized (IsoDepHolder.class) {
            if (!isConnected()) {
                throw new RuntimeException("transceive - nfc is not connected");
                // TODO: show popup connect NFC card and wait till card is connected
                // TapSigner maybe need to perform ISO app select here
            }
            return IsoDepHolder.isoDep.transceive(data);
        }
    }

    static public void close() throws IOException {
        synchronized (IsoDepHolder.class) {
            if (isoDep != null) {
                isoDep.close();
                isoDep = null;
            }
        }
    }

    static public native void reInit();
}
