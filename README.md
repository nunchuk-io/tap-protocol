# tap-protocol
Coinkite Tap Protocol

# Build

## Build secp256k1
[https://github.com/bitcoin-core/secp256k1#build-steps](https://github.com/bitcoin-core/secp256k1#build-steps)

## Build tap-protocol

```
mkdir build
cd build
cmake -DBUILD_TESTING=ON -DBUILD_TEST_WITH_EMULATOR=ON ..
make
make test #run tests
```

# JNI

```
    protected void onNewIntent(Intent intent) {
    // ...
        byte[] id = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
        Tag tag = (Tag) intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        NfcA nfca = NfcA.get(tag);
        try {
            nfca.connect();
            if (nfca.isConnected()) {
                addCard(nfca);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static {
        System.loadLibrary("tap_protocol_nativesdk");
    }

    public native void addCard(NfcA nfcA);


```

```
cd <android project location>
git clone https://github.com/nunchuk-io/tap-protocol src/main/cpp/tap-protocol
# build tap-protocol
```

```
# src/main/cpp/CMakeLists.txt
add_subdirectory(tap-protocol)
target_link_libraries(
        tap_protocol_nativesdk
        tap-protocol
        )
```

```

#include <tap_protocol/tap_protocol.h>
#include <tap_protocol/cktapcard.h>

extern "C"
JNIEXPORT void JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_addCard(JNIEnv *env, jobject thiz,
                                                               jobject nfca) {
    jclass nfcaClass = env->FindClass("android/nfc/tech/NfcA");
    jmethodID tranceiveMethodID = env->GetMethodID(nfcaClass, "transceive", "([B)[B");

    auto tp = tap_protocol::MakeDefaultTransport([&](const tap_protocol::Bytes &in) {
        auto bytesToSend = env->NewByteArray(in.size());
        env->SetByteArrayRegion(bytesToSend, 0, in.size(), (jbyte *) in.data());
        auto bytesReceive = (jbyteArray) env->CallObjectMethod(nfca, tranceiveMethodID,
                                                               bytesToSend);
        auto firstByte = env->GetByteArrayElements(bytesReceive, 0);
        tap_protocol::Bytes result((char *) firstByte,
                                   (char *) firstByte + env->GetArrayLength(bytesReceive));
        env->ReleaseByteArrayElements(bytesToSend, firstByte, JNI_ABORT);
        return result;
    });
    tap_protocol::TapSigner tapSigner(std::move(tp));
    // Call status
    tapSigner.Status();
}
```
