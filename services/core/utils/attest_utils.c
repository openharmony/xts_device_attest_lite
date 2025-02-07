/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <ctype.h>
#include <string.h>
#include <securec.h>
#include <time.h>
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include "mbedtls/version.h"
#include "attest_utils_log.h"
#include "attest_utils_memleak.h"
#include "attest_utils.h"

#define PER_BYTE_BITS    8
#define RANDOM_BYTES     4

#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER >= 0x03000000)
#define mbedtls_sha256_starts_ret mbedtls_sha256_starts
#define mbedtls_sha256_update_ret mbedtls_sha256_update
#define mbedtls_sha256_finish_ret mbedtls_sha256_finish
#endif

int32_t GetRandomNum(void)
{
    static mbedtls_ctr_drbg_context randomContext;
    static mbedtls_entropy_context randomEntropy;
    static bool initFlag = false;

    const char* pers = "CTR_DRBG";
    int32_t result = 0;
    unsigned char* random = (unsigned char *)ATTEST_MEM_MALLOC(RANDOM_BYTES);
    if (random == NULL) {
        return 0;
    }
    do {
        int32_t ret = ATTEST_OK;
        if (initFlag == false) {
            mbedtls_ctr_drbg_init(&randomContext);
            mbedtls_entropy_init(&randomEntropy);
            ret = mbedtls_ctr_drbg_seed(&randomContext, mbedtls_entropy_func, &randomEntropy,
                                        (const uint8_t*)pers, strlen(pers));
            if (ret != ATTEST_OK) {
                break;
            }
            initFlag = true;
        }

        ret = mbedtls_ctr_drbg_random(&randomContext, random, RANDOM_BYTES);
        if (ret != ATTEST_OK) {
            break;
        }
        result = random[RANDOM_BYTES - 1];
        for (int i = RANDOM_BYTES - 2; i >= 0; --i) {
            result <<= PER_BYTE_BITS;
            result |= random[i];
        }
    } while (0);
    return ABS(result);
}

char* AttestStrdup(const char* input)
{
    if (input == NULL) {
        return NULL;
    }
    size_t inputLen = strlen(input);
    if (inputLen == 0 || inputLen >= MAX_ATTEST_MALLOC_BUFF_SIZE) {
        return NULL;
    }

    size_t outputLen = inputLen + 1;
    char* out = ATTEST_MEM_MALLOC(outputLen);
    if (out == NULL) {
        return NULL;
    }
    if (memcpy_s(out, outputLen, input, inputLen) != 0) {
        ATTEST_MEM_FREE(out);
        return NULL;
    }
    return out;
}

void URLSafeBase64ToBase64(const char* input, size_t inputLen, uint8_t** output, size_t* outputLen)
{
    const uint8_t tempInputLen = 4;
    if (input == NULL || output == NULL || outputLen == NULL) {
        ATTEST_LOG_ERROR("[URLSafeBase64ToBase64] Invalid parameter");
        return;
    }
    if (inputLen == 0 || inputLen >= MAX_ATTEST_MALLOC_BUFF_SIZE) {
        return;
    }
    *outputLen = inputLen + ((inputLen % tempInputLen == 0) ? 0 : (tempInputLen - inputLen % tempInputLen));
    if (*outputLen == 0 || *outputLen >= MAX_ATTEST_MALLOC_BUFF_SIZE) {
        return;
    }
    *output = (uint8_t *)ATTEST_MEM_MALLOC(*outputLen + 1);
    if (*output == NULL) {
        return;
    }
    size_t i;
    for (i = 0; i < inputLen; ++i) {
        if (input[i] == '-') {
            (*output)[i] = '+';
            continue;
        }
        if (input[i] == '_') {
            (*output)[i] = '/';
            continue;
        }
        (*output)[i] = input[i];
    }
    for (i = inputLen; i < *outputLen; ++i) {
        (*output)[i] = '=';
    }
}

static uint32_t CalUnAnonyStrLen(uint32_t strLen)
{
    uint32_t len = 1;
    uint32_t tempLen = 2;
    while ((tempLen * len) < strLen) {
        len = len * tempLen;
    }
    return len / 2; // len / 2即保留信息的字符串总长度
}

// 匿名化算法：长度小于8, 全部匿名;    长度大于8，保留前后信息，中间匿名化，一半保留一半匿名化。
int32_t AnonymiseStr(char* str)
{
    if (str == NULL || strlen(str) == 0) {
        return ATTEST_ERR;
    }
    uint32_t strLen = strlen(str);
    int32_t ret;
    uint32_t tempLen = 8;
    if (strLen <= tempLen) {
        ret = memset_s((void*)str, strLen, '*', strLen);
    } else {
        const uint32_t halfLen = 2;
        int32_t unAnonyStrLen = CalUnAnonyStrLen(strLen);
        int32_t endpointLen = unAnonyStrLen / halfLen;
        ret = memset_s((void*)(str + endpointLen), (strLen - unAnonyStrLen), '*', (strLen - unAnonyStrLen));
    }
    if (ret != 0) {
        ret = ATTEST_ERR;
    }
    return ret;
}

void PrintCurrentTime(void)
{
    time_t timet;
    (void)time(&timet);
    struct tm* timePacket = gmtime(&timet);
    if (timePacket == NULL) {
        return;
    }
    ATTEST_LOG_INFO("[PrintCurrentTime] Hours: %d, Minutes: %d, Seconds: %d",
        timePacket->tm_hour, timePacket->tm_min, timePacket->tm_sec);
}

// 字符串转化为小写
int32_t ToLowerStr(char* str, int len)
{
    if (str == NULL) {
        ATTEST_LOG_ERROR("[ToLowerStr] Str is NUll");
        return ATTEST_ERR;
    }

    for (int i = 0; i < len; i++) {
        str[i] = tolower(str[i]);
    }
    return ATTEST_OK;
}

int Sha256ValueToAscii(const unsigned char *src, int srcLen, unsigned char *dest, int destLen)
{
    if (src == NULL || srcLen <= 0 || dest == NULL || destLen <= 0) {
        ATTEST_LOG_ERROR("[Sha256ValueToAscii] Invalid parameter");
        return ATTEST_ERR;
    }

    unsigned char hash[HASH_LENGTH] = {0};

    mbedtls_sha256_context context;
    mbedtls_sha256_init(&context);
    mbedtls_sha256_starts_ret(&context, 0);
    mbedtls_sha256_update_ret(&context, src, srcLen);
    mbedtls_sha256_finish_ret(&context, hash);

    int ret = ATTEST_OK;
    if (memcpy_s(dest, destLen, hash, HASH_LENGTH) != 0) {
        ATTEST_LOG_ERROR("[Sha256ValueToAscii] Failed to memcpy");
        ret = ATTEST_ERR;
    }
    (void)memset_s(hash, HASH_LENGTH, 0, HASH_LENGTH);
    return ret;
}

/**
 * @brief Encrypt string with sha256 algorithm, and generate uppercase string.
 *
 */
int Sha256Value(const unsigned char *src, int srcLen, char *dest, int destLen)
{
    if (src == NULL || srcLen <= 0 || dest == NULL || destLen <= 0) {
        ATTEST_LOG_ERROR("[Sha256Value] Invalid parameter");
        return ATTEST_ERR;
    }
    char buf[DEV_BUF_LENGTH] = {0};
    unsigned char hash[HASH_LENGTH] = {0};
    int32_t ret = Sha256ValueToAscii(src, srcLen, hash, HASH_LENGTH);
    if (ret != ATTEST_OK) {
        return ATTEST_ERR;
    }

    for (int i = 0; i < HASH_LENGTH; i++) {
        (void)memset_s(buf, DEV_BUF_LENGTH, 0, DEV_BUF_LENGTH);
        // generate uppercase string
        if (sprintf_s(buf, sizeof(buf), "%02X", hash[i]) < 0) {
            ret = ATTEST_ERR;
            break;
        }
        if (strcat_s(dest, destLen, buf) != 0) {
            ret = ATTEST_ERR;
            break;
        }
    }
    (void)memset_s(buf, DEV_BUF_LENGTH, 0, DEV_BUF_LENGTH);
    (void)memset_s(hash, HASH_LENGTH, 0, HASH_LENGTH);
    return ret;
}

void *AttestMemAlloc(uint32_t size, const char* file, uint32_t line, const char* func)
{
    if (size == 0) {
        return NULL;
    }
    void *addr = malloc(size);
    if (addr == NULL) {
        return NULL;
    }
    int32_t ret = memset_s(addr, size, 0, size);
    if (ret != 0) {
        free(addr);
        return NULL;
    }
    if (ATTEST_DEBUG_MEMORY_LEAK) {
        (void)AddMemInfo(addr, file, line, func);
    }
    return addr;
}

void AttestMemFree(void **point)
{
    if (point == NULL || *point == NULL) {
        return;
    }
    if (ATTEST_DEBUG_MEMORY_LEAK) {
        (void)RemoveMemInfo(*point);
    }
    free(*point);
    *point = NULL;
}

static int32_t HexToNumber(char inputChr)
{
    int retNumber = 0;
    if (inputChr >= '0' && inputChr <= '9') {
        retNumber = inputChr - '0';
    } else if (inputChr >= 'a' && inputChr <= 'f') {
        retNumber = DECIMAL_BASE + inputChr - 'a';
    } else if (inputChr >= 'A' && inputChr <= 'F') {
        retNumber = DECIMAL_BASE + inputChr - 'A';
    } else {
        retNumber = ATTEST_ERR;
    }
    return retNumber;
}

int32_t HEXStringToAscii(const char* input, int32_t inputLen, char* output, int32_t outputLen)
{
    if (input == NULL || inputLen <= 0 || output == NULL || (inputLen % ATTEST_EVEN_NUMBER == 1)) {
        ATTEST_LOG_ERROR("[HEXStringToAscii] Invaild paramter");
        return ATTEST_ERR;
    }

    if (outputLen < (inputLen / ATTEST_EVEN_NUMBER)) {
        ATTEST_LOG_ERROR("[HEXStringToAscii] outputLen is shorter than required");
        return ATTEST_ERR;
    }

    int tempLen = 0;
    int32_t ret = ATTEST_OK;
    for (int i = 0; i < inputLen;) {
        int highNumber = HexToNumber(input[i]);
        int lowNumber = HexToNumber(input[i + 1]);
        if (highNumber == ATTEST_ERR || lowNumber == ATTEST_ERR) {
            ret = ATTEST_ERR;
            break;
        }
        output[tempLen++] = highNumber * HEXADECIMAL_BASE + lowNumber;
        i += ATTEST_EVEN_NUMBER;
    }
    return ret;
}
