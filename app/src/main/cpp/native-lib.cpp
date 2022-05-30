#include <jni.h>
#include <string>
#include <tap_protocol/tap_protocol.h>
#include <tap_protocol/cktapcard.h>
#include <iostream>
#include <android/log.h>

#define APPNAME "tap_protocol_native_sdk"

std::unique_ptr<tap_protocol::TapSigner> ts;

void initTapsigner(JNIEnv *env) {
    auto tp = tap_protocol::MakeDefaultTransport([=](const tap_protocol::Bytes &in) {
        jclass isoDepHolderClazz = env->FindClass(
                "com/example/tap_protocol_nativesdk/IsoDepHolder");
        jmethodID tranceiveMethodID = env->GetStaticMethodID(isoDepHolderClazz, "transceive",
                                                             "([B)[B");
        auto bytesToSend = env->NewByteArray(in.size());
        env->SetByteArrayRegion(bytesToSend, 0, in.size(), (jbyte *) in.data());

        auto bytesReceive = (jbyteArray) env->CallStaticObjectMethod(isoDepHolderClazz,
                                                                     tranceiveMethodID,
                                                                     bytesToSend);


        auto isCopy = jboolean(0);
        auto firstByte = env->GetByteArrayElements(bytesReceive, &isCopy);
        tap_protocol::Bytes result((char *) firstByte,
                                   (char *) firstByte + env->GetArrayLength(bytesReceive));
        std::string str(result.data(), result.data() + result.size());
        env->ReleaseByteArrayElements(bytesToSend, firstByte, JNI_ABORT);
        return result;
    });
    ts = std::make_unique<tap_protocol::TapSigner>(std::move(tp));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";

    return env->NewStringUTF(hello.c_str());
}


extern "C"
JNIEXPORT void JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_addTapSigner(JNIEnv *env, jobject thiz) {
    try {
        initTapsigner(env);
        nlohmann::json res = ts->Status();
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "status %s", res.dump(4).c_str());
    } catch (std::exception &e) {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "err %s", e.what());
    }
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_tapSignerStatus(JNIEnv *env, jobject thiz) {
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "status called");
    nlohmann::json res = ts->Status();
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "res status\n %s", res.dump(4).c_str());
    return env->NewStringUTF(res.dump(2).c_str());

}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_tap_1protocol_1nativesdk_MainActivity_tapSignerCerts(JNIEnv *env, jobject thiz) {
    if (ts) {
        std::string res = ts->CertificateCheck();
        return env->NewStringUTF(res.c_str());
    }
    return env->NewStringUTF("Un init");
}
extern "C"
JNIEXPORT void JNICALL
Java_com_example_tap_1protocol_1nativesdk_IsoDepHolder_reInit(JNIEnv *env, jclass thiz) {
    initTapsigner(env);
}