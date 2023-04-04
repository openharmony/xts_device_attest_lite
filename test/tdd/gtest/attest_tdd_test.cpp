/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <securec.h>
#include <gtest/gtest.h>

#include "attest_utils_log.h"
#include "attest_entry.h"
#include "devattest_msg_def.h"
#include "attest_type.h"
#include "attest_network.h"
#include "attest_service_active.h"
#include "attest_service_auth.h"
#include "attest_service_challenge.h"
#include "attest_service_device.h"
#include "attest_service.h"
#include "attest_service_device.h"
#include "attest_security_token.h"
#include "attest_service_reset.h"
#include "attest_tdd_mock_config.h"
#include "attest_tdd_test_data.h"

using namespace testing::ext;
namespace OHOS {
namespace DevAttest {
const int32_t ATTEST_GET_CHANLLEGE = 0;
const int32_t ATTEST_RESET = 1;
const int32_t ATTEST_ACTIVE = 2;
const int32_t ATTEST_AUTH = 3;

int32_t g_netType = ATTEST_GET_CHANLLEGE;
bool g_isFirstToken = true;
const char* ATTEST_TICKET = "vbVYmHYmc5i/jiEVITvDOHzevJgU/Ghe";
const char* ATTEST_STATUS = ".eyJhdXRoUmVzdWx0IjowLCJhdXRoVHlwZSI6IlRPS0VOX0VOQUJMRSIsImV4cGlyZVRpbWUiOjE2ODMyMDQx \
    NTQxNzQsImtpdFBvbGljeSI6W10sInNvZnR3YXJlUmVzdWx0IjozMDAwMiwic29mdHdhcmVSZXN1bHREZXRhaWwiOnsicGF0Y2hMZXZlbFJlc \
    3VsdCI6MzAwMDgsInBjaWRSZXN1bHQiOjMwMDExLCJyb290SGFzaFJlc3VsdCI6MzAwMDksInZlcnNpb25JZFJlc3VsdCI6MzAwMDJ9LCJ1ZG \
    lkIjoiODFDOTQ0NTI3OUEzQTQxN0Q0MTU5RkRGQzYyNjkxQkM4REEwMDJFODQ2M0M3MEQyM0FCNENCRjRERjk4MjYxQyIsInZlcnNpb25JZCI6 \
    ImRlZmF1bHQvaHVhLXdlaS9rZW1pbi9kZWZhdWx0L09wZW5IYXJtb255LTQuMC4zLjIoQ2FuYXJ5MSkvb2hvcy9tYXgvMTAvT3Blbkhhcm1vbn \
    kgMi4zIGJldGEvZGVidWcifQ.";
class AttestTddTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void AttestTddTest::SetUpTestCase(void)
{
}

void AttestTddTest::TearDownTestCase(void)
{
}

void AttestTddTest::SetUp()
{
    int32_t ret = InitSysData(); // 初始化系统参数
    ATTEST_LOG_INFO("[AttestTdd] Init system data ret = %d.", ret);
}

void AttestTddTest::TearDown()
{
}

static AuthResult *GetAuthResult()
{
    AuthResult *authResult = CreateAuthResult();
    EXPECT_TRUE((authResult != nullptr));
    if (authResult == nullptr) {
        return nullptr;
    }
    int32_t ret = ParseAuthResultResp(ATTEST_AUTH_EXPECT_RESULT, authResult);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
    return authResult;
}

static void WriteAuthResult(AuthResult *authResult)
{
    int32_t ret = FlushToken(authResult);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
}

static DevicePacket* ConstructDevicePacket()
{
    DevicePacket* result = (DevicePacket*)malloc(sizeof(DevicePacket));
    if (result == nullptr) {
        return nullptr;
    }
    EXPECT_TRUE(result != NULL);
    return result;
}

static DevicePacket* TddGenActiveMsg()
{
    AuthResult *authResult = GetAuthResult();
    DevicePacket* reqMsg = ConstructDevicePacket();
    if (reqMsg == nullptr) {
        return nullptr;
    }
    char* ATTEST_ACTIVE_CHAP = "7bf570910d3e1fcdf3959e10ffddc5c2777164a4a2f55d9fd65b1896f65b3f97";
    ChallengeResult chap = {.challenge = ATTEST_ACTIVE_CHAP, .currentTime = ATTEST_ACTIVE_CHAP_TIME};
    int32_t ret = GenActiveMsg(authResult, &chap, &reqMsg);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    DestroyAuthResult(&authResult);
    return reqMsg;
}

/*
 * @tc.name: TestGenActiveMsg001
 * @tc.desc: Test gen activeMsg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenActiveMsg001, TestSize.Level1)
{
    DevicePacket* reqMsg = TddGenActiveMsg();
    if (reqMsg == NULL) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == NULL) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(outToken, ATTEST_ACTIVE_EXPECT_TOKEN) == 0);
    FREE_DEVICE_PACKET(reqMsg);
}

/*
 * @tc.name: TestSendActiveMsg001
 * @tc.desc: Test send active msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestSendActiveMsg001, TestSize.Level1)
{
    g_netType = ATTEST_ACTIVE;
    DevicePacket* reqMsg = TddGenActiveMsg();
    if (reqMsg == NULL) {
        return;
    }
    char* respMsg = NULL;
    int32_t ret = SendActiveMsg(reqMsg, &respMsg);
    EXPECT_TRUE((ret == ATTEST_OK) && (respMsg != NULL));
    if (respMsg == NULL) {
        ATTEST_LOG_ERROR("[SendActiveMsgTdd] respMsg is NULL.");
        return;
    }
    if (ret != ATTEST_OK) {
        free(respMsg);
        ATTEST_LOG_ERROR("[SendActiveMsgTdd] Send active message failed, ret = %d.", ret);
        return;
    }
    const char* ATTEST_ACTIVE_EXPECT_RESULT = "{\"errcode\":0}";
    EXPECT_TRUE(strcmp(ATTEST_ACTIVE_EXPECT_RESULT, respMsg) == 0);
    free(respMsg);
}

/*
 * @tc.name: TestParseActiveResult001
 * @tc.desc: Test parse active result，result is ok.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseActiveResult001, TestSize.Level1)
{
    char *input = "{\"errcode\":0}";
    int32_t ret = ParseActiveResult(input);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
}

/*
 * @tc.name: TestParseActiveResult002
 * @tc.desc: Test parse active result，result is error.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseActiveResult002, TestSize.Level1)
{
    char *input = "{\"errcode\":\"-32s\"}";
    int32_t ret = ParseActiveResult(input);
    EXPECT_TRUE((ret != DEVATTEST_SUCCESS));
}

void WriteAuthStatus()
{
    int32_t ret = FlushAuthResult(ATTEST_TICKET, ATTEST_STATUS);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
}

void TestGetAuthStatus(char **status)
{
    int32_t ret = GetAuthStatus(status);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS));
}

/*
 * @tc.name: TestGetAuthStatus001
 * @tc.desc: Test get authStatus.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGetAuthStatus001, TestSize.Level1)
{
    WriteAuthStatus();
    char *status = nullptr;
    TestGetAuthStatus(&status);
    EXPECT_TRUE((status != nullptr));
    if (status == nullptr) {
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_STATUS, status) == 0);
    free(status);
}

static void FreeAuthStatus(AuthStatus* authStatus)
{
    if (authStatus->versionId != NULL) {
        free(authStatus->versionId);
    }
    if (authStatus->authType != NULL) {
        free(authStatus->authType);
    }
    if (authStatus->softwareResultDetail != NULL) {
        free(authStatus->softwareResultDetail);
    }
    free(authStatus);
}

/*
 * @tc.name: TestDecodeAuthStatus001
 * @tc.desc: Test decode auth status.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestDecodeAuthStatus001, TestSize.Level1)
{
    WriteAuthStatus();
    char *status = nullptr;
    TestGetAuthStatus(&status);
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE((outStatus != nullptr));
    if (outStatus == nullptr) {
        return;
    }
    int32_t ret = DecodeAuthStatus(status, outStatus);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    SoftwareResultDetail* detail = outStatus->softwareResultDetail;
    EXPECT_TRUE((outStatus->versionId != nullptr) && (outStatus->authType != nullptr) && (detail != nullptr));
    if ((outStatus->versionId == nullptr) || (outStatus->authType == nullptr) || (detail == nullptr)) {
        FreeAuthStatus(outStatus);
        return;
    }
    const char* ATTEST_VERSIONID = "default/hua-wei/kemin/default/OpenHarmony-4.0.3.2(Canary1)/ohos/max/10 \
        /OpenHarmony 2.3 beta/debug";
    const char* ATTEST_AUTH_TYPE = "TOKEN_ENABLE";
    EXPECT_TRUE(strcmp(outStatus->versionId, ATTEST_VERSIONID) == 0);
    EXPECT_TRUE(strcmp(outStatus->authType, ATTEST_AUTH_TYPE) == 0);
    EXPECT_TRUE((outStatus->hardwareResult == ATTEST_HARDWARERESULT) && (outStatus->expireTime == ATTEST_EXPIRRTIME));
    FreeAuthStatus(outStatus);
}

/*
 * @tc.name: TestCheckAuthResult001
 * @tc.desc: Test check auth result.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestCheckAuthResult001, TestSize.Level1)
{
    AuthStatus* outStatus = CreateAuthStatus();
    EXPECT_TRUE(outStatus != nullptr);
    if (outStatus == nullptr) {
        return;
    }
    outStatus->expireTime = 19673222;
    uint64_t currentTime = 19673223;
    int32_t ret = CheckAuthResult(outStatus, currentTime);
    EXPECT_TRUE(ret != DEVATTEST_SUCCESS);
    outStatus->expireTime = 19673222;
    currentTime = 19673221;
    ret = CheckAuthResult(outStatus, currentTime);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    free(outStatus);
}

static DevicePacket* TddGenAuthMsg()
{
    DevicePacket* reqMsg = ConstructDevicePacket();
    if (reqMsg == NULL) {
        return NULL;
    }
    ChallengeResult challenge = {.challenge = (char*)ATTEST_AUTH_CHAP, .currentTime = ATTEST_AUTH_CHAP_TIME};
    int32_t ret = GenAuthMsg(&challenge, &reqMsg);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    return reqMsg;
}

/*
 * @tc.name: TestGenAuthMsg001
 * @tc.desc: Test gen auth msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenAuthMsg001, TestSize.Level1)
{
    DevicePacket* reqMsg = TddGenAuthMsg();
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == NULL) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == NULL) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(outToken, ATTEST_AUTH_GEN_TOKEN) == 0);
    FREE_DEVICE_PACKET(reqMsg);
}

/*
 * @tc.name: TestSendAuthMsg001
 * @tc.desc: Test send auth msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestSendAuthMsg001, TestSize.Level1)
{
    g_netType = ATTEST_AUTH;
    DevicePacket* reqMsg = TddGenAuthMsg();
    char* respMsg = NULL;
    int32_t ret = SendActiveMsg(reqMsg, &respMsg);
    EXPECT_TRUE((ret == ATTEST_OK) && (respMsg != NULL));
    if (respMsg == NULL) {
        ATTEST_LOG_ERROR("[SendAuthTdd] respMsg is NULL.");
        return;
    }
    if (ret != ATTEST_OK) {
        free(respMsg);
        ATTEST_LOG_ERROR("[SendAuthTdd] Send auth message failed, ret = %d.", ret);
        return;
    }
    EXPECT_TRUE(strcmp(respMsg, ATTEST_AUTH_EXPECT_RESULT) == 0);
    free(respMsg);
}

/*
 * @tc.name: TestParseAuthResultResp001
 * @tc.desc: Test parse auth result resp.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestParseAuthResultResp001, TestSize.Level1)
{
    AuthResult *authResult = GetAuthResult();
    EXPECT_TRUE(authResult != nullptr);
    if (authResult == nullptr) {
        return;
    }
    EXPECT_TRUE((authResult->ticket != nullptr) && (authResult->tokenValue != nullptr) &&
        (authResult->authStatus != nullptr));
    if (authResult->ticket != nullptr) {
        EXPECT_TRUE(strcmp(authResult->ticket, ATTEST_TICKET) == 0);
    }
    DestroyAuthResult(&authResult);
}

/*
 * @tc.name: TestGetChallenge001
 * @tc.desc: Test get reset challenge.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGetChallenge001, TestSize.Level1)
{
    g_netType = ATTEST_GET_CHANLLEGE;
    ChallengeResult* challenge = NULL;
    int32_t ret = GetChallenge(&challenge, ATTEST_ACTION_RESET);
    EXPECT_TRUE((ret == ATTEST_OK) && (challenge != NULL));
    if (ret != ATTEST_OK) {
        FREE_CHALLENGE_RESULT(challenge);
        ATTEST_LOG_ERROR("[AttestTdd] GetChallenge failed, ret = %d.", ret);
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_RESET_EXPECT_CHAP, challenge->challenge) == 0);
    FREE_CHALLENGE_RESULT(challenge);
}

static DevicePacket* TddGenResetMsg()
{
    DevicePacket* reqMsg = ConstructDevicePacket();
    if (reqMsg == NULL) {
        return NULL;
    }
    ChallengeResult chap = {
        .challenge = (char*)ATTEST_RESET_EXPECT_CHAP,
        .currentTime = ATTEST_RESET_EXPECT_CHAP_TIME
    };
    int32_t ret = GenResetMsg(&chap, &reqMsg);
    EXPECT_TRUE(ret == DEVATTEST_SUCCESS);
    return reqMsg;
}

/*
 * @tc.name: TestGenResetMsg001
 * @tc.desc: Test gen reset msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestGenResetMsg001, TestSize.Level1)
{
    DevicePacket* reqMsg = TddGenResetMsg();
    EXPECT_TRUE((reqMsg != nullptr));
    if (reqMsg == nullptr) {
        return;
    }
    char *outToken = reqMsg->tokenInfo.token;
    EXPECT_TRUE(outToken != nullptr);
    if (outToken == NULL) {
        FREE_DEVICE_PACKET(reqMsg);
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_RESET_EXPECT_TOKEN, outToken) == 0);
    FREE_DEVICE_PACKET(reqMsg);
}

/*
 * @tc.name: TestSendResetMsg001
 * @tc.desc: Test send reset msg.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestSendResetMsg001, TestSize.Level1)
{
    g_netType = ATTEST_RESET;
    DevicePacket* reqMsg = TddGenResetMsg();
    if (reqMsg == NULL) {
        return;
    }
    char* respMsg = NULL;
    int32_t ret = SendResetMsg(reqMsg, &respMsg);
    EXPECT_TRUE((ret == ATTEST_OK) && (respMsg != NULL));
    if (respMsg == NULL) {
        FREE_DEVICE_PACKET(reqMsg);
        ATTEST_LOG_ERROR("[SendResetTdd] respMsg is NULL.");
        return;
    }
    if (ret != ATTEST_OK) {
        FREE_DEVICE_PACKET(reqMsg);
        free(respMsg);
        ATTEST_LOG_ERROR("[SendResetMsgTdd] Send reset message failed, ret = %d.", ret);
        return;
    }
    EXPECT_TRUE(strcmp(ATTEST_REST_ERROR_EXPECT_RESULT, respMsg) == 0);
    free(respMsg);
    FREE_DEVICE_PACKET(reqMsg);
}

/*
 * @tc.name: TestQueryAttestStatus001
 * @tc.desc: Test query attest status.
 * @tc.type: FUNC
 */
HWTEST_F(AttestTddTest, TestQueryAttestStatus001, TestSize.Level1)
{
    AuthResult *authResult = GetAuthResult();
    if (authResult == nullptr) {
        return;
    }
    WriteAuthResult(authResult);
    AttestResultInfo attestResultInfo = { .softwareResultDetail = {-2, -2, -2, -2, -2} };
    attestResultInfo.ticket = NULL;
    int32_t ret = EntryGetAttestStatus(&attestResultInfo);
    EXPECT_TRUE((ret == DEVATTEST_SUCCESS) && (attestResultInfo.authResult == DEVATTEST_SUCCESS));
    EXPECT_TRUE((attestResultInfo.ticket != nullptr));
    if (attestResultInfo.ticket == nullptr) {
        return;
    }
    EXPECT_TRUE(strcmp(attestResultInfo.ticket, ATTEST_TICKET) == 0);
}
}
}
