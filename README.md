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

## Build secp256k1
```
# Android
$ ./tool/build_android.sh

# iOS
$ PLATFORM_NAME=iphoneos CONFIGURATION=debug ARCHS=arm64 ./tools/build_ios.sh
## Add these libs into XCode project Build Phases
## build/libtap-protocol.a
## build/contrib/bitcoin-core/libbitcoin-core.a
## build/contrib/bitcoin-core/src/secp256k1/build/iphoneos/libsecp256k1.a

# Linux
$ ./tool/build_linux.sh
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

    auto tp = tap_protocol::MakeDefaultTransport([=](const tap_protocol::Bytes &in) {
    // Dual to NFC only available when a card tap phone,
    // client must make sure this function only get called when card is connected 
    // 1. Put a popup here and only continue when card is connected 
    // 2. Implement a queue?
    // 3. Another way...

        jclass isoDepClass = env->FindClass("android/nfc/tech/IsoDep");
        jmethodID tranceiveMethodID = env->GetMethodID(isoDepClass, "transceive", "([B)[B");
        auto bytesToSend = env->NewByteArray(in.size());
        env->SetByteArrayRegion(bytesToSend, 0, in.size(), (jbyte *) in.data());
        
        auto bytesReceive = (jbyteArray) env->CallObjectMethod(card, tranceiveMethodID,
                                                               bytesToSend);
        auto firstByte = env->GetByteArrayElements(bytesReceive, 0);
        tap_protocol::Bytes result((char *) firstByte,
                                   (char *) firstByte + env->GetArrayLength(bytesReceive));
        env->ReleaseByteArrayElements(bytesToSend, firstByte, JNI_ABORT);
        return result;
    });
    tap_protocol::Tapsigner tapsigner(std::move(tp));
    // Call status
    json resp = tapsigner.Status();

    __android_log_print(ANDROID_LOG_VERBOSE, "CoolApp", "Status response %s", resp.dump(4).c_str());
}
```

# Development

## Testing
```
mkdir build
cd build
cmake -DBUILD_TESTING=ON ..
make all test
```


