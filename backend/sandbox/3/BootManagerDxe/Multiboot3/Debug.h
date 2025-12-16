//
// FILENAME.
//      Debug.h - SecureCore Technology(TM) MultiBoot3 BOP Debug Instrumentation Macros.
//
// FUNCTIONAL DESCRIPTION.
//      This include file defines the definitions used by debugging
//      instrumentation in this driver.
//
// NOTICE.
//      Copyright (C) 2009-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_DEBUG
#define _SCT_H_DEBUG

#include <SctBdsDebug.h>

//
// Instrumentation macros available to all modules in this component.
//
#define BDS_DEBUG_CODE(code)  DEBUG_CODE(code)

//
// The DPRINTF_MB3, DEBUG_MB3, and ASSERT_MB3 macros instrument the
// MultiBoot3 BootOptionProtocol component.
//

#if OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3
#define DPRINTF_MB3(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_MB3(statement) BDS_DEBUG_CODE(statement)
#define ASSERT_MB3(A) ASSERT(A)
#else
#define DPRINTF_MB3(...)
#define DEBUG_MB3(statement)
#define ASSERT_MB3(A)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3_PCILAN
#define DPRINTF_MB3_LAN(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_MB3_LAN(statement) BDS_DEBUG_CODE(statement)
#define ASSERT_MB3_LAN(A) ASSERT(A)
#else
#define DPRINTF_MB3_LAN(...)
#define DEBUG_MB3_LAN(statement)
#define ASSERT_MB3_LAN(A)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3_INSTRUMENTATION
#define DISPLAY_DEVICE_PATH_ARRAY(a,b,c) BDS_DEBUG_CODE (DisplayDevicePathArray  (a,b,c);)
#define DUMP_BYTES_MB3(a,b) DumpBytes (a, b)
#define DUMP_WORDS_MB3(a,b) DumpWords (a, b)
#else
#define DISPLAY_DEVICE_PATH_ARRAY(a,b,c)
#define DUMP_BYTES_MB3(a,b)
#define DUMP_WORDS_MB3(a,b)
#endif

#endif // not defined, _SCT_H_DEBUG
