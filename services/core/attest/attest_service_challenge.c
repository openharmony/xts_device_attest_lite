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

#include <math.h>
#include <stdio.h>
#include <signal.h>
#include "attest_type.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_utils_json.h"
#include "attest_dfx.h"
#include "attest_network.h"
#include "attest_service_device.h"
#include "attest_adapter_mock.h"
#include "attest_service_challenge.h"

static ChallengeResult* CreateChallengeResult(void)
{
    ChallengeResult* challengeResult = (ChallengeResult *)ATTEST_MEM_MALLOC(sizeof(ChallengeResult));
    if (challengeResult == NULL) {
        ATTEST_LOG_ERROR("[CreateChallengeResult] ChallengeResult malloc memory failed");
        return NULL;
    }
    challengeResult->challenge = NULL;
    challengeResult->currentTime = 0;
    challengeResult->cloudServerInfo.activeSite = NULL;
    challengeResult->cloudServerInfo.standbySite = NULL;
    return challengeResult;
}

static int32_t GenChallengeMsg(const DevicePacket** devPacket)
{
    if (devPacket == NULL) {
        ATTEST_LOG_ERROR("[GenChallengeMsg] Invalid parameter");
        return ATTEST_ERR;
    }

    DevicePacket* devicePacket = CreateDevicePacket();
    if (devicePacket == NULL) {
        ATTEST_LOG_ERROR("[GenChallengeMsg] Create DevicePacket failed");
        return ATTEST_ERR;
    }

    devicePacket->appId = StrdupDevInfo(APP_ID);
    devicePacket->tenantId = StrdupDevInfo(TENANT_ID);
    devicePacket->randomUuid = StrdupDevInfo(RANDOM_UUID);
    devicePacket->udid = StrdupDevInfo(UDID);
    devicePacket->productInfo.versionId = StrdupDevInfo(VERSION_ID);
    *devPacket = devicePacket;
    if (ATTEST_DEBUG_DFX) {
        ATTEST_DFX_DEV_PACKET(devicePacket);
    }
    return ATTEST_OK;
}

static int32_t SendChallMsg(const DevicePacket* devicePacket, char** respMsg, ATTEST_ACTION_TYPE action)
{
    if (ATTEST_MOCK_NETWORK_STUB_FLAG) {
        return SendChallMsgStub(action, respMsg);
    }
    if (devicePacket == NULL || respMsg == NULL) {
        ATTEST_LOG_ERROR("[SendChallMsg] Invalid parameter");
        return ATTEST_ERR;
    }
    char* recvMsg = NULL;
    int32_t ret = SendAttestMsg(devicePacket, ATTEST_ACTION_CHALLENGE, &recvMsg);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[SendChallMsg] Send AttestMsg failed");
        return ret;
    }
    *respMsg = recvMsg;
    return ret;
}

static int32_t ParseChallengeResult(const char* jsonStr, ChallengeResult* challenge)
{
    if (jsonStr == NULL || challenge == NULL) {
        ATTEST_LOG_ERROR("[ParseChallengeResult] Invalid parameter");
        return ATTEST_ERR;
    }
    double errorCode = GetObjectItemValueNumber(jsonStr, "errcode");
    if (isnan(errorCode)) {
        ATTEST_LOG_ERROR("[ParseChallengeResult] GetObjectItem errcode failed.");
        return ATTEST_ERR;
    }
    if ((int32_t)errorCode != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ParseChallengeResult] errorCode = %d.", -(int32_t)(errorCode));
        return -(int32_t)(errorCode);
    }

    challenge->currentTime = (uint64_t)GetObjectItemValueNumber(jsonStr, "currentTime");
    if (isnan((double)challenge->currentTime)) {
        ATTEST_LOG_ERROR("[ParseChallengeResult] GetObjectItem currentTime failed.");
        return ATTEST_ERR;
    }
    int32_t ret = GetObjectItemValueStr(jsonStr, "challenge", &(challenge->challenge));
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[ParseChallengeResult] GetObjectItem challenge failed.");
        return ATTEST_ERR;
    }
#ifndef __ATTEST_DISABLE_SITE__
    char* serverInfo = NULL;
    do {
        ret = GetObjectItemValueObject(jsonStr, "serverInfo", &serverInfo);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseChallengeResult] GetObjectItem serverInfo failed.");
            break;
        }
        ret = GetObjectItemValueStr(serverInfo, "activeSite", &(challenge->cloudServerInfo.activeSite));
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseChallengeResult] GetObjectItem challenge failed.");
            break;
        }
        ret = GetObjectItemValueStr(serverInfo, "standbySite", &(challenge->cloudServerInfo.standbySite));
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[ParseChallengeResult] GetObjectItem challenge failed.");
            break;
        }
    } while (0);
    ATTEST_MEM_FREE(serverInfo);
#endif
    return ret;
}

void DestroyChallengeResult(ChallengeResult** challengeResult)
{
    if (challengeResult == NULL || *challengeResult == NULL) {
        ATTEST_LOG_ERROR("[DestroyChallengeResult] Invalid parameter");
        return;
    }
    ATTEST_MEM_FREE((*challengeResult)->cloudServerInfo.activeSite);
    ATTEST_MEM_FREE((*challengeResult)->cloudServerInfo.standbySite);
    ATTEST_MEM_FREE((*challengeResult)->challenge);
    ATTEST_MEM_FREE(*challengeResult);
}

static int32_t SetChallenge(ChallengeResult* challengeResult, ATTEST_ACTION_TYPE actionType)
{
    ATTEST_LOG_DEBUG("[SetChallenge] Begin.");
    const DevicePacket* reqMsg = NULL;
    int32_t ret = GenChallengeMsg(&reqMsg);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[SetChallenge] Gen Challenge Msg failed");
        return ret;
    }

    char* respMsg = NULL;
    ret = SendChallMsg(reqMsg, &respMsg, actionType);
    FREE_DEVICE_PACKET(reqMsg);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[SetChallenge] Send Challenge Msg failed");
        return ret;
    }

    ret = ParseChallengeResult((const char*)respMsg, challengeResult);
    ATTEST_MEM_FREE(respMsg);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[SetChallenge] Parse Challenge Result failed");
        return ret;
    }
    ATTEST_LOG_DEBUG("[SetChallenge] End.");
    return ret;
}

static ChallengeResult* GetChallengeImpl(ATTEST_ACTION_TYPE actionType)
{
    int32_t ret = ATTEST_ERR;
    ChallengeResult* challengeResult = CreateChallengeResult();
    if (challengeResult == NULL) {
        ATTEST_LOG_ERROR("[GetChallengeImpl] Create ChallengeResult failed.");
        return NULL;
    }
    for (int32_t i = 0; i <= WISE_RETRY_CNT; i++) {
        ret = SetChallenge(challengeResult, actionType);
        if (!IS_WISE_RETRY(-ret)) {
            break;
        }
    }
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[GetChallengeImpl] Set Challenge failed, ret = %d.", ret);
        FREE_CHALLENGE_RESULT(challengeResult);
        return NULL;
    }
    return challengeResult;
}

int32_t GetChallenge(ChallengeResult** challResult, ATTEST_ACTION_TYPE actionType)
{
    ATTEST_LOG_DEBUG("[GetChallenge] Begin.");
    if (challResult == NULL) {
        ATTEST_LOG_ERROR("[GetChallenge] Invalid parameter");
        return ATTEST_ERR;
    }
    ChallengeResult* challengeResult = GetChallengeImpl(actionType);
    if (challengeResult == NULL) {
        ATTEST_LOG_ERROR("[GetChallenge] GetChallengeImpl fail");
        return ATTEST_ERR;
    }
    int32_t updateFlag = UPDATE_NO;
    char* activeSite = challengeResult->cloudServerInfo.activeSite;
    char* standbySite = challengeResult->cloudServerInfo.standbySite;
    int32_t ret = UpdateNetConfig(activeSite, standbySite, &updateFlag);
    if (updateFlag == UPDATE_OK) {
        FREE_CHALLENGE_RESULT(challengeResult);
        if (ret != ATTEST_OK) {
            ATTEST_LOG_ERROR("[GetChallenge] update netconfig failed");
            return ATTEST_ERR;
        }
        challengeResult = GetChallengeImpl(actionType);
        if (challengeResult == NULL) {
            ATTEST_LOG_ERROR("[GetChallenge] GetChallengeImpl fail");
            return ATTEST_ERR;
        }
    }
    if (ATTEST_DEBUG_DFX) {
        ATTEST_DFX_CHALL_RESULT(challengeResult);
    }
    *challResult = challengeResult;
    ATTEST_LOG_DEBUG("[GetChallenge] end");
    return ATTEST_OK;
}