#pragma once

#if defined(_WIN32) && defined(SYSLOCKER_BEDROCK_SHARED)
#if defined(SYSLOCKER_BEDROCK_BUILDING)
#define SYSLOCKER_BEDROCK_API __declspec(dllexport)
#else
#define SYSLOCKER_BEDROCK_API __declspec(dllimport)
#endif
#else
#define SYSLOCKER_BEDROCK_API
#endif
