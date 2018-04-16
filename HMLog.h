//
// Created by guoguo on 18-3-31.
//

#ifndef ELFHOOK_HMLOG_H
#define ELFHOOK_HMLOG_H

#ifndef LOG_TAG
#define LOG_TAG "ELF_HOOK"
#endif
#ifdef __ANDROID__
#include <android/log.h>
#define logi(fmt, ...) \
        __android_log_print(ANDROID_LOG_INFO,   LOG_TAG, ": [%s:%d]"  fmt "\n", \
                            __func__, __LINE__, ##__VA_ARGS__)

#define logd(fmt, ...) \
        __android_log_print(ANDROID_LOG_DEBUG,  LOG_TAG, ": [%s:%d]"  fmt "\n", \
                            __func__, __LINE__, ##__VA_ARGS__)
#define logv(fmt, ...) \
        __android_log_print(ANDROID_LOG_VERBOSE,LOG_TAG, ": [%s:%d]"  fmt "\n", \
                            __func__, __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...) \
        __android_log_print(ANDROID_LOG_WARN,   LOG_TAG, ": [%s:%d]"  fmt "\n", \
                            __func__, __LINE__, ##__VA_ARGS__)

#define loge(fmt, ...) \
        __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG, ": [%s:%d]"  fmt "\n", \
                            __func__, __LINE__, ##__VA_ARGS__)
#else
#define logi(fmt, ...) \
    printf("I "  LOG_TAG ": [%s:%d]"  fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define logv(fmt, ...) \
    printf("V "  LOG_TAG ": [%s:%d]"  fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define logd(fmt, ...) \
    printf("D "  LOG_TAG ": [%s:%d]"  fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...) \
    printf("W "  LOG_TAG ": [%s:%d]"  fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...) \
     printf("E "  LOG_TAG ": [%s:%d]"  fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#endif


#endif //ELFHOOK_HMLOG_H
