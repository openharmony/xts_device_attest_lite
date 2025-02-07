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

#ifndef __ATTEST_SERVICE_CHALLENGE_H__
#define __ATTEST_SERVICE_CHALLENGE_H__

#include "attest_type.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

void DestroyChallengeResult(ChallengeResult** challengeResult);

int32_t GetChallenge(ChallengeResult** challResult, ATTEST_ACTION_TYPE actionType);

#define FREE_CHALLENGE_RESULT(challengeResult) DestroyChallengeResult((ChallengeResult**)&(challengeResult))

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif