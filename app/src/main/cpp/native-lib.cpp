#include <jni.h>
#include <string>
#include <tap_protocol/tap_protocol.h>
#include <tap_protocol/cktapcard.h>
#include <iostream>
#include <android/log.h>

#define APPNAME "tap_protocol_native_sdk"

std::unique_ptr<tap_protocol::TapSigner> ts;

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";

    return env->NewStringUTF(hello.c_str());
}

std::unique_ptr<tap_protocol::Transport> makeTransport(JNIEnv *env, jobject iso_dep) {
    auto tp = tap_protocol::MakeDefaultTransport([=](const tap_protocol::Bytes &in) {
        jclass isoDepClass = env->FindClass("com/example/tap_protocol_nativesdk/IsoDepCaller");
        jmethodID tranceiveMethodID = env->GetStaticMethodID(isoDepClass, "transceive",
                                                             "(Landroid/nfc/tech/IsoDep;[B)[B");
        auto bytesToSend = env->NewByteArray(in.size());
        env->SetByteArrayRegion(bytesToSend, 0, in.size(), (jbyte *) in.data());

        auto bytesReceive = (jbyteArray) env->CallStaticObjectMethod(isoDepClass, tranceiveMethodID,
                                                                     iso_dep, bytesToSend);
        if (bytesReceive == nullptr) {
            // TODO: handle error
        }
        auto firstByte = env->GetByteArrayElements(bytesReceive, 0);
        tap_protocol::Bytes result((char *) firstByte,
                                   (char *) firstByte + env->GetArrayLength(bytesReceive));
        env->ReleaseByteArrayElements(bytesToSend, firstByte, JNI_ABORT);
        return result;
    });
    return tp;
}


extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_tapSignerStatus(JNIEnv *env, jobject thiz,
                                                                       jobject iso_dep) {
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "status called");
    ts = std::make_unique<tap_protocol::TapSigner>(makeTransport(env, iso_dep));

    nlohmann::json res = ts->Status();
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "res status\n %s", res.dump(4).c_str());
    return env->NewStringUTF(res.dump(2).c_str());
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_tapSignerCerts(JNIEnv *env, jobject thiz,
                                                                      jobject iso_dep) {
    ts = std::make_unique<tap_protocol::TapSigner>(makeTransport(env, iso_dep));
    if (env->ExceptionCheck() == JNI_TRUE) {
        std::string msg = std::string("Exception JNI java");
        return env->NewStringUTF(msg.c_str());
    }
    std::string res = ts->CertificateCheck();
    return env->NewStringUTF(res.c_str());
}