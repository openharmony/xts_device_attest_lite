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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <securec.h>
#include <bundle_manager.h>
#include <bundle_info.h>
#include <ohos_init.h>
#include <iunknown.h>
#include <samgr_lite.h>
#include <iproxy_client.h>
#include <iproxy_server.h>
#include "ipc_skeleton.h"

#include "attest_log.h"
#include "attest_framework_define.h"
#include "attest_entry.h"

typedef struct {
    INHERIT_SERVER_IPROXY;
} AttestFrameworkApi;

typedef struct {
    INHERIT_FEATURE;
    INHERIT_IUNKNOWNENTRY(AttestFrameworkApi);
    Identity identity;
    Service *parent;
} AttestFrameworkFeature;

static const char *FEATURE_GetName(Feature *feature);
static void FEATURE_OnInitialize(Feature *feature, Service *parent, Identity identity);
static void FEATURE_OnStop(Feature *feature, Identity identity);
static BOOL FEATURE_OnMessage(Feature *feature, Request *request);
static int32_t Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply);

// 创建功能对象
static AttestFrameworkFeature g_attestFeature = {
    .GetName = FEATURE_GetName,
    .OnInitialize = FEATURE_OnInitialize,
    .OnStop = FEATURE_OnStop,
    .OnMessage = FEATURE_OnMessage,
    SERVER_IPROXY_IMPL_BEGIN,
    .Invoke = Invoke,
    IPROXY_END,
    .identity = {-1, -1, NULL},
};

// 实现功能的生命周期函数
static const char *FEATURE_GetName(Feature *feature)
{
    (void)feature;
    return ATTEST_FEATURE;
}

static void FEATURE_OnInitialize(Feature *feature, Service *parent, Identity identity)
{
    AttestFrameworkFeature *demoFeature = (AttestFrameworkFeature *)feature;
    demoFeature->identity = identity;
    demoFeature->parent = parent;
}

static void FEATURE_OnStop(Feature *feature, Identity identity)
{
    (void)feature;
    (void)identity;
    g_attestFeature.identity.queueId = NULL;
    g_attestFeature.identity.featureId = -1;
    g_attestFeature.identity.serviceId = -1;
}

static BOOL FEATURE_OnMessage(Feature *feature, Request *request)
{
    (void)feature;
    HILOGI("[FEATURE_OnMessage] request->msgId:%d", request->msgId);
    return FALSE;
}

static int32_t WriteAttestResultInfo(IpcIo *reply, AttestResultInfo *attestResultInfo)
{
    if (reply == NULL) {
        HILOGE("[WriteAttestResultInfo] reply is null!");
        return DEVATTEST_FAIL;
    }

    if (attestResultInfo->ticket == NULL) {
        HILOGE("[WriteAttestResultInfo] ticket is NULL!");
        if (!WriteInt32(reply, DEVATTEST_FAIL)) {
            HILOGE("[WriteAttestResultInfo] Write ret fail!");
        }
        return DEVATTEST_FAIL;
    }

    if (!WriteInt32(reply, DEVATTEST_SUCCESS)) {
        HILOGE("[WriteAttestResultInfo] Write result fail!");
        return DEVATTEST_FAIL;
    }

    if (!WriteInt32(reply, attestResultInfo->authResult) ||
        !WriteInt32(reply, attestResultInfo->softwareResult) ||
        !WriteInt32(reply, attestResultInfo->ticketLength) ||
        !WriteString(reply, attestResultInfo->ticket)) {
        HILOGE("[WriteAttestResultInfo] Write data fail!");
        return DEVATTEST_FAIL;
    }

    int32_t size = sizeof(attestResultInfo->softwareResultDetail);
    if (!WriteInt32Vector(reply, attestResultInfo->softwareResultDetail, size)) {
        HILOGE("[WriteAttestResultInfo] Write softwareResultDetail_ fail!");
        return DEVATTEST_FAIL;
    }

    return DEVATTEST_SUCCESS;
}

static int32_t IpcWriteErrorPermissionInfo(IpcIo *reply)
{
    if (reply == NULL) {
        HILOGE("[IpcWritePermissionError] reply is null!");
        return DEVATTEST_FAIL;
    }
    if (!WriteInt32(reply, DEVATTEST_ERR_JS_IS_NOT_SYSTEM_APP)) {
        HILOGE("[IpcWritePermissionError] Write ret fail!");
        return DEVATTEST_FAIL;
    }
    return DEVATTEST_SUCCESS;
}

static int32_t CopyAttestResult(int32_t *resultArray, AttestResultInfo *attestResultInfo)
{
    if (resultArray == NULL) {
        return DEVATTEST_FAIL;
    }
    int32_t *head = resultArray;
    attestResultInfo->authResult = *head;
    head++;
    attestResultInfo->softwareResult = *head;
    for (int i = 0; i < SOFTWARE_RESULT_DETAIL_SIZE; i++) {
        (attestResultInfo->softwareResultDetail)[i] = *(++head);
    }
    return DEVATTEST_SUCCESS;
}

static int32_t GetQueryAttestResult(AttestResultInfo *attestResultInfo)
{
    int32_t resultArraySize = MAX_ATTEST_RESULT_SIZE * sizeof(int32_t);
    int32_t *resultArray = (int32_t *)malloc(resultArraySize);
    if (resultArray == NULL) {
        HILOGE("malloc resultArray failed");
        return DEVATTEST_FAIL;
    }
    (void)memset_s(resultArray, resultArraySize, 0, resultArraySize);
    int32_t ticketLenght = 0;
    char* ticketStr = NULL;
    int32_t ret = DEVATTEST_SUCCESS;
    do {
        ret = QueryAttest(&resultArray, MAX_ATTEST_RESULT_SIZE, &ticketStr, &ticketLenght);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("QueryAttest failed");
            break;
        }
        if (ticketStr == NULL || ticketLenght == 0) {
            HILOGE("Get ticket failed");
            ret = DEVATTEST_FAIL;
            break;
        }
        attestResultInfo->ticketLength = ticketLenght;
        attestResultInfo->ticket = ticketStr;
        ret = CopyAttestResult(resultArray,  attestResultInfo);
        if (ret != DEVATTEST_SUCCESS) {
            HILOGE("copy attest result failed");
            break;
        }
    } while (0);
    if (ret != DEVATTEST_SUCCESS && ticketStr != NULL) {
        free(ticketStr);
        ticketStr = NULL;
    }
    resultArray = NULL;
    return ret;
}

static int32_t FeatureQueryAttest(IpcIo *reply)
{
    if (reply == NULL) {
        HILOGE("[FeatureQueryAttest] reply is null!");
        return DEVATTEST_FAIL;
    }
    AttestResultInfo  attestResultInfo = { .softwareResultDetail = {-1, -1, -1, -1, -1} };
    int32_t ret = GetQueryAttestResult(&attestResultInfo);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[FeatureQueryAttest] Query status fail!");
        if (!WriteInt32(reply, ret)) {
            HILOGE("[FeatureQueryAttest] Write ret fail!");
        }
        return DEVATTEST_FAIL;
    }

    ret = WriteAttestResultInfo(reply, &attestResultInfo);
    if (attestResultInfo.ticket != NULL) {
        free(attestResultInfo.ticket);
        attestResultInfo.ticket = NULL;
    }
    return ret;
}

static bool CheckPermission(int32_t uid)
{
    char *bundName = NULL;
    GetBundleNameForUid(uid, &bundName);
    if (bundName == NULL) {
        HILOGE("[CheckPermission] Get  bundle name fail!");
        return false;
    }
    BundleInfo bundleInfo = { 0 };
    uint8_t ret = GetBundleInfo(bundName, 0, &bundleInfo);
    if (ret != DEVATTEST_SUCCESS) {
        HILOGE("[CheckPermission] Get  bundle info fail!");
        return false;
    }
    bool isSystem = bundleInfo.isSystemApp;
    ClearBundleInfo(&bundleInfo);
    return isSystem;
}

static int32_t Invoke(IServerProxy *iProxy, int funcId, void *origin, IpcIo *req, IpcIo *reply)
{
    (void)req;
    if (iProxy == NULL || origin == NULL) {
        return DEVATTEST_FAIL;
    }
    int32_t uid = GetCallingUid();
    if (!CheckPermission(uid)) {
        return IpcWriteErrorPermissionInfo(req);
    }
    int32_t ret = DEVATTEST_SUCCESS;
    switch (funcId) {
        case ATTEST_FRAMEWORK_MSG_PROC:
            AttestTask();
            break;
        case ATTEST_FRAMEWORK_MSG_QUERY:
            FeatureQueryAttest(reply);
            break;
        default:
            break;
    }
    return ret;
}

// 向SAMGR注册功能及接口
static void Init(void)
{
    SAMGR_GetInstance()->RegisterFeature(ATTEST_SERVICE, (Feature *)&g_attestFeature);
    SAMGR_GetInstance()->RegisterFeatureApi(ATTEST_SERVICE, ATTEST_FEATURE, GET_IUNKNOWN(g_attestFeature));
}

// 定义功能的初始化入口
SYS_FEATURE_INIT(Init);