# tap-protocol

[Coinkite Tap Protocol](https://github.com/coinkite/coinkite-tap-proto/blob/master/docs/protocol.md) implemented in C++.

## Setup

``` bash
$ cd your_project/
$ git submodule add https://github.com/nunchuk-io/tap-protocol
$ git submodule update --init --recursive
```

Add the following to your `CMakeLists.txt`.

``` cmake
add_subdirectory(tap-protocol)
target_link_libraries("${PROJECT_NAME}" PUBLIC tap-protocol)
```

Build secp256k1.

``` bash
# Android
$ ./tools/build_android.sh

# iOS
$ PLATFORM_NAME=iphoneos CONFIGURATION=debug ARCHS=arm64 ./tools/build_ios.sh
# Add these libs into XCode project Build Phases
# build/contrib/bitcoin-core/libbitcoin-core.a
# build/contrib/bitcoin-core/src/secp256k1/build/iphoneos/libsecp256k1.a

# Linux
$ ./tools/build_linux.sh
```

## Usage

TAPSIGNER

``` c++

using namespace tap_protocol;

// First create a transport that sends bytes to the device
auto transport = MakeDefaultTransport([](const Bytes& bytes) {
    // see how to send bytes to NFC card on Android or iOS below 
});

// Create a Tapsigner using transport
auto tapsigner = std::make_unique<Tapsigner>(std::move(transport));
// or simply: 
// Tapsigner tapsigner(std::move(transport));

// Get card status
auto status = tapsigner->Status();

if (tapsigner->NeedSetup()) {
  // Set up a new card
  Bytes chain_code = RandomChainCode(); // generate random chain code
  std::string cvc = "123456";
  auto setup = tapsigner->New(chain_code, cvc);
}

// See more commands in include/tap_protocol/cktapcard.h
```

Alternatively, we can use Tapsigner HWI interface

``` c++
// Create HWI-like interface
auto hwi = MakeHWITapsigner(tapsigner.get(), "123456");

// Set up a new card
hwi->SetupDevice();

// Card fingerprint
std::string fingerprint = hwi->GetMasterFingerprint();

// Sign message
std::string signed_message = hwi->SignMessage("nunchuk", "m/84h/0h/0h");

// Sign transaction
std::string base64_psbt = "...";
std::string signed_tx = hwi->SignTx(base64_psbt);

// Backup-restore
auto bytes = hwi->BackupDevice();
std::string decrypt_backup = hwi->DecryptBackup(bytes, "backup key");

```

SATSCARD

``` c++

// First create a transport that sends bytes to the device
auto transport = MakeDefaultTransport([](const Bytes& bytes) {
    // see how to send bytes to NFC card for Android or iOS below 
});

auto satscard = Satscard(std::move(transport));

if (satscard.IsUsedUp()) {
  // Card is used up
  // but let's check just in case some BTC are still in there

  // Get all unsealed slots
  std::vector<Satscard::Slot> slots = satscard.ListSlots();

  for (const auto &slot : slots) {
      // checking each slot address
      auto balance = SOME_CHECKING_BALANCE_API(slot.address);

      // Obtain private key
      auto slot_with_priv = satscard.GetSlot(slot.index, "123456");

      // Get wif of slot
      std::string wif = slot_with_priv.to_wif(satscard.IsTestnet());

      // Import wif then sweep func
  }

  // Or we can get all private key info in one go
  std::vector<Satscard::Slot> slots_with_privkey = satscard.ListSlots("123456");
  for (const auto &slot : slots_with_privkey) {
      std::string wif = slot.to_wif();
  }
  return;
}

// Set up a new slot
if (satscard.NeedSetup()) {
    // Setup for slot # satscard.GetActiveSlotIndex()
    Bytes chain_code = RandomChainCode(); // generate random chain code
    std::string cvc = "123456";
    auto resp = satscard.New(chain_code, cvc);
    
    // slot address to deposit
    std::string address = resp.address;
} else {
    // Current slot is sealed so we can deposit to this address
    std::string address = slot.address;

    // Unseal & sweep the func
    std::string cvc = "123456";
    auto unseal = satscard.Unseal(cvc);
    
    // get private key for this slot
    Bytes privkey = unseal.privkey;
    
    // in WIF format
    std::string wif = unseal.to_wif(satscard.IsTestnet());
}

```

Check if card is TAPSIGNER or SATSCARD

``` c++
CKTapCard card(std::move(tp));

if (card.IsTapsigner()) {
    auto tapsigner = ToTapsigner(std::move(card));
    // Do command with tapsigner
} else {
    auto satscard = ToSatscard(std::move(card));
    // Do command with satscard
}
```

### Android - use with JNI

Android Intent that handles NFC events

``` java
    protected void onNewIntent(Intent intent) {
    // ...
        byte[] id = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
        Tag tag = (Tag) intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        IsoDep card = IsoDep.get(tag);
        try {
            card.connect();
            cardStatus(card);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (card != null) {
              card.close()
            }
        }
    }

    static {
        System.loadLibrary("<your-library-name>");
    }

    public native void cardStatus(IsoDep card);
```

JNI code

``` c++
#include <tap_protocol/tap_protocol.h>
#include <tap_protocol/cktapcard.h>

extern "C"
JNIEXPORT void JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_cardStatus(JNIEnv *env, jobject thiz,
                                                               jobject card) {
    
    auto transport = tap_protocol::MakeDefaultTransport([=](const tap_protocol::Bytes &in) {
        jclass isoDepClass = env->FindClass("android/nfc/tech/IsoDep");
        jmethodID tranceiveMethodID = env->GetMethodID(isoDepClass, "transceive", "([B)[B");
        auto bytesToSend = env->NewByteArray(in.size());
        env->SetByteArrayRegion(bytesToSend, 0, in.size(), (jbyte *) in.data());
        
        auto bytesReceive = (jbyteArray) env->CallObjectMethod(card, tranceiveMethodID, bytesToSend);
        env->DeleteLocalRef(bytesToSend);

        auto firstByte = env->GetByteArrayElements(bytesReceive, JNI_FALSE);
        tap_protocol::Bytes result((char *) firstByte, (char *) firstByte + env->GetArrayLength(bytesReceive));
        env->ReleaseByteArrayElements(bytesReceive, firstByte, JNI_ABORT);
        return result;
    });

    tap_protocol::Tapsigner tapsigner(std::move(transport));
    
    // Run command `status`
    auto status = tapsigner.Status();
}
```

### iOS - Objective-C++

``` objc
#include <tap_protocol/tap_protocol.h>
#include <tap_protocol/cktapcard.h>

using namespace tap_protocol;

@interface YourLibName () <NFCTagReaderSessionDelegate>

dispatch_queue_t nfcQueue = dispatch_queue_create([@"io.nunchuk.nfc" UTF8String], dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_BACKGROUND, -1));
dispatch_semaphore_t semaphore;

- (void) cardStatus {
    NFCTagReaderSession *session = [[NFCTagReaderSession alloc] initWithPollingOption:NFCPollingISO14443 | NFCPollingISO15693 | NFCPollingISO18092 delegate:self queue:nfcQueue];
    [session beginSession];
    semaphore = dispatch_semaphore_create(0);
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    id<NFCTag> tag = session.connectedTag;
    auto transport = MakeDefaultTransportIOS([tag](const APDURequest &req) {
        Bytes bytes = {req.cla, req.ins, req.p1, req.p2};
        NSMutableData *data = [[NSMutableData alloc] initWithBytes:bytes.data() length:bytes.size() * sizeof(unsigned char)];
        [data appendBytes:req.data.data() length:req.data.size() * sizeof(unsigned char)];
        NFCISO7816APDU *apdu = [[NFCISO7816APDU alloc] initWithData:data];
        
        __block auto response = APDUResponse();
        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
        [tag.asNFCISO7816Tag sendCommandAPDU:apdu completionHandler:^(NSData * _Nonnull responseData, uint8_t sw1, uint8_t sw2, NSError * _Nullable error) {
            const unsigned char *dataArray = (unsigned char *)responseData.bytes;
            const size_t count = responseData.length / sizeof(unsigned char);
            response.data = Bytes(dataArray, dataArray + count);;
            response.sw1 = sw1;
            response.sw2 = sw2;
            dispatch_semaphore_signal(semaphore);
        }];
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
        return response;
    });

    Tapsigner tapsigner(std::move(transport));
    
    // Run command `status`
    auto status = tapsigner.Status();
    [session invalidateSession];
}

- (void)tagReaderSession:(NFCTagReaderSession *)session didDetectTags:(NSArray<__kindof id<NFCTag>> *)tags {
    id<NFCTag> tag = [tags firstObject];
    [session connectToTag:tag completionHandler:^(NSError * _Nullable error) {
        if (error != NULL) {
            [session invalidateSessionWithErrorMessage:@"Unable to connect tag"];
            return;
        }
        dispatch_semaphore_signal(semaphore);
    }];
}

```

## Contributing

### Install emulator
See [https://github.com/coinkite/coinkite-tap-proto/tree/master/emulator](https://github.com/coinkite/coinkite-tap-proto/tree/master/emulator)

### Build & run tests
```
mkdir build
cd build
cmake -DBUILD_TESTING=ON ..
make all test -j4
```
