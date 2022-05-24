# tap-protocol
Coinkite Tap Protocol implement
[https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md)

# Setup

```
$ cd your_project/
$ git submodule add https://github.com/nunchuk-io/tap-protocol
$ git submodule update --init --recursive
```

Add the following to your CMakeLists.txt

```
add_subdirectory(tap-protocol)
target_link_libraries("${PROJECT_NAME}" PUBLIC tap-protocol)
```

## Build libwally-core ([detail](https://github.com/ElementsProject/libwally-core#building))
```
# For android
# you may wanna export ANDROID_NDK=/path/to/android-ndk
$ ./tools/build_android_libraries.sh

# For linux
$ ./tools/build_unix_libraries.sh
```

# Use with JNI


Android Intent that handle NFC event

```
    protected void onNewIntent(Intent intent) {
    // ...
        byte[] id = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
        Tag tag = (Tag) intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        IsoDep card = IsoDep.get(tag);
        try {
            card.connect();
            if (card.isConnected()) {
                addCard(card);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static {
        System.loadLibrary("tap_protocol_nativesdk");
    }

    public native void addCard(IsoDep card);


```

Native library code

```
#include <tap_protocol/tap_protocol.h>
#include <tap_protocol/cktapcard.h>

extern "C"
JNIEXPORT void JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_addCard(JNIEnv *env, jobject thiz,
                                                               jobject card) {
    jclass isoDepClass = env->FindClass("android/nfc/tech/IsoDep");
    jmethodID tranceiveMethodID = env->GetMethodID(isoDepClass, "transceive", "([B)[B");

    auto tp = tap_protocol::MakeDefaultTransport([=](const tap_protocol::Bytes &in) {
    // Dual to NFC only available when a card tap phone
    // Client must make sure this function only call when this happend

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
    auto resp = tapSigner.Status();
    
}
```

# Development

## Testing
```
mkdir build
cd build
cmake -DBUILD_TESTING=ON -DBUILD_TEST_WITH_EMULATOR=ON ..
make all test
```


