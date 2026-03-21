#pragma once

#ifdef USE_ESPHOME
  #include "esphome/core/log.h"
  #define DLMS_LOGD(TAG, ...) ESP_LOGD(TAG, __VA_ARGS__)
  #define DLMS_LOGI(TAG, ...) ESP_LOGI(TAG, __VA_ARGS__)
  #define DLMS_LOGW(TAG, ...) ESP_LOGW(TAG, __VA_ARGS__)
  #define DLMS_LOGV(TAG, ...) ESP_LOGV(TAG, __VA_ARGS__)
  #define DLMS_LOGVV(TAG, ...) ESP_LOGVV(TAG, __VA_ARGS__)
#else
  #include <cstdio>
  #define DLMS_LOGD(TAG, ...) do { printf("[D][%s]: ", TAG); printf(__VA_ARGS__); printf("\n"); } while(0)
  #define DLMS_LOGI(TAG, ...) do { printf("[I][%s]: ", TAG); printf(__VA_ARGS__); printf("\n"); } while(0)
  #define DLMS_LOGW(TAG, ...) do { printf("[W][%s]: ", TAG); printf(__VA_ARGS__); printf("\n"); } while(0)
  #define DLMS_LOGV(TAG, ...) do { printf("[V][%s]: ", TAG); printf(__VA_ARGS__); printf("\n"); } while(0)
  #define DLMS_LOGVV(TAG, ...) do { printf("[VV][%s]: ", TAG); printf(__VA_ARGS__); printf("\n"); } while(0)
#endif
