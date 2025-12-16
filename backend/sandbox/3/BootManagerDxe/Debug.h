//
// FILENAME.
//      Debug.h - SecureCore Technology(TM) System Boot Manager Debug Instrumentation Macros.
//
// FUNCTIONAL DESCRIPTION.
//      This include file defines the definitions used by debugging
//      instrumentation in this driver.
//
//      This file contains definitions for DPRINTF_class, DEBUG_class,
//      and ASSERT_class macros, in order to standardize instrumentation.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_DEBUG
#define _SCT_H_DEBUG

#include <SctBdsDebug.h>

#define BDS_DEBUG_CODE(code)  DEBUG_CODE(code)

//
// DPRINTF_ERROR. Used when an exceptional error is detected. It is only used
// at the lowest function call that detects the exceptional error. Layers of
// function calls above the lowest level use the other DPRINTF types to report
// the errors.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_ERROR
#else
#undef  DPRINTF_ERROR
#define DPRINTF_ERROR(...)
#endif

//
// Instrumentation macros available to all modules in this component.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION
#define DUMP_BYTES(a,b) DumpBytes (a, b)
#define DUMP_WORDS(a,b) DumpWords (a, b)
#else
#define DUMP_BYTES(a,b)
#define DUMP_WORDS(a,b)
#endif


#if ((OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION) && (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INIT))
#define DUMP_IMAGE_INFO(a) BDS_DEBUG_CODE (DumpImageInfo  (a);)
#else
#define DUMP_IMAGE_INFO(a)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_FUNCTION_ENTRY
  #define DPRINTF_FUNCTION_ENTRY(...) DPRINTF ("%a: Entry\n", __FUNCTION__)
#else
  #define DPRINTF_FUNCTION_ENTRY(...)
#endif

//
// The DPRINTF_BM, DEBUG_BMR, and ASSERT_BM macros instrument the Boot Manager.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BOOTMANAGER
#define DPRINTF_BM(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_BMR(statement)       BDS_DEBUG_CODE(statement)
#define ASSERT_BM(A)               ASSERT(A)
#else
#define DPRINTF_BM(...)
#define DEBUG_BMR(statement)
#define ASSERT_BM(A)
#endif


#if ((OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION) && (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BOOTMANAGER))
#define DEBUG_BM_INST(statement)            BDS_DEBUG_CODE (statement)
#define DUMP_ALL_DEVICE_PATHS               BDS_DEBUG_CODE (DumpAllDevicePaths ();)
#define DUMP_ALL_PROTOCOLS(handle)          BDS_DEBUG_CODE (DumpAllProtocols (handle);)
#define DISPLAY_DEVICE_PATH(handle, indent) BDS_DEBUG_CODE (DisplayDevicePath  (handle, indent);)
#else
#define DEBUG_BM_INST(statement)
#define DUMP_ALL_DEVICE_PATHS
#define DUMP_ALL_PROTOCOLS(handle)
#define DISPLAY_DEVICE_PATH(handle, indent)
#endif


#if ((OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION) && (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BOOTMANAGER))
#define DISPLAY_USB_DEVICE_DESCRIPTOR(a)    BDS_DEBUG_CODE (DisplayUsbDeviceDescriptor (a);)
#define DISPLAY_USB_INTERFACE_DESCRIPTOR(a) BDS_DEBUG_CODE (DisplayUsbInterfaceDescriptor (a);)
#else
#define DISPLAY_USB_DEVICE_DESCRIPTOR(a)
#define DISPLAY_USB_INTERFACE_DESCRIPTOR(a)
#endif


//
// Device Module, Child Detection.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DEVICE
#define DPRINTF_DEV(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_DEV(statement) BDS_DEBUG_CODE(statement)
#else
#define DPRINTF_DEV(...)
#define DEBUG_DEV(statement)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DEVICE_CHECK
#define DPRINTF_DEV_CHECK(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_DEV_CHECK(statement) BDS_DEBUG_CODE(statement)
#else
#define DPRINTF_DEV_CHECK(...)
#define DEBUG_DEV_CHECK(statement)
#endif


#if ((OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION) && (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DEVICE))
#define DISPLAY_DEVICE_PATH_ARRAY(a,b,c) BDS_DEBUG_CODE (DisplayDevicePathArray  (a,b,c);)
#else
#define DISPLAY_DEVICE_PATH_ARRAY(a,b,c)
#endif

//
// Device Module, Child Detection.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DEVICE_CHILD
#define DPRINTF_DEV_CHILD(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_DEV_CHILD(statement) BDS_DEBUG_CODE(statement)
#else
#define DPRINTF_DEV_CHILD(...)
#define DEBUG_DEV_CHILD(statement)
#endif

//
// The DPRINTF_CON, DEBUG_CON, and ASSERT_CON macros instrument the Console Module.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_CONSOLE
#define DPRINTF_CON(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_CON(statement) BDS_DEBUG_CODE(statement)
#define ASSERT_CON(A) ASSERT(A)
#else
#define DPRINTF_CON(...)
#define DEBUG_CON(statement)
#define ASSERT_CON(A)
#endif

//
// The DPRINTF_HK, DEBUG_HK, and ASSERT_HK macros instrument the Hotkey Module.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_HOTKEY
#define DPRINTF_HK(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_HK(statement) BDS_DEBUG_CODE(statement)
#define ASSERT_HK(A) ASSERT(A)
#else
#define DPRINTF_HK(...)
#define DEBUG_HK(statement)
#define ASSERT_HK(A)
#endif


#if ((OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION) && (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_HOTKEY))
#define DISPLAY_HOTKEY_OBJECT(p, s) BDS_DEBUG_CODE (DisplayHotkeyObject (p, s);)
#else
#define DISPLAY_HOTKEY_OBJECT(p, s)
#endif


//
// The DPRINTF_VAR, DEBUG_VAR, and ASSERT_VAR macros instrument the Variable Module.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_VARIABLE
#define DPRINTF_VAR(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_VAR(statement) BDS_DEBUG_CODE(statement)
#define ASSERT_VAR(A) ASSERT(A)
#else
#define DPRINTF_VAR(...)
#define DEBUG_VAR(statement)
#define ASSERT_VAR(A)
#endif

//
// The DPRINTF_LO, DEBUG_LO, and ASSERT_LO macros instrument the Load Option Module.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LOAD_OPTION
#define DPRINTF_LO(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_LO(statement) BDS_DEBUG_CODE(statement)
#define ASSERT_LO(A) ASSERT(A)
#else
#define DPRINTF_LO(...)
#define DEBUG_LO(statement)
#define ASSERT_LO(A)
#endif


#if ((OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION) && (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LOAD_OPTION))
#define DISPLAY_OPTION_INFORMATION(p, s) BDS_DEBUG_CODE (DisplayOptionInformation (p, s);)
#else
#define DISPLAY_OPTION_INFORMATION(p, s)
#endif


#if OPTION_DEBUG_DPRINTF_WITH_LEVEL //&& OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LOAD_OPTION
//#define DPRINTL_LO(...)        DPRINTF_LEVEL (__VA_ARGS__)
#define DPRINTL_LO(Level, Expression)   DPRINTF_LEVEL (Level, Expression)
#else
//#define DPRINTL_LO(...)
#define DPRINTL_LO(Level, Expression)
#endif


#define DPRINTF_LO_V2(...)        DPRINTF (__VA_ARGS__)

#if OPTION_DEBUG_CODE_WITH_LEVEL //&& OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LOAD_OPTION
#define DEBUG_LO_L(Level, SourceCode)  DEBUG_LEVEL_CODE (Level, SourceCode)
#else
#define DEBUG_LO_L(Level, SourceCode)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LOAD_OPTION_ENUM
#define DPRINTF_LO_ENUM(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_LO_ENUM(statement) statement
#else
#define DPRINTF_LO_ENUM(...)
#define DEBUG_LO_ENUM(statement)
#endif

//
// The DPRINTF_LEGACY, DEBUG_LEGACY, and ASSERT_LEGACY macros instrument the Legacy Module.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
#define DPRINTF_LEGACY(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_LEGACY(statement) BDS_DEBUG_CODE(statement)
#define ASSERT_LEGACY(A) ASSERT(A)
#else
#define DPRINTF_LEGACY(...)
#define DEBUG_LEGACY(statement)
#define ASSERT_LEGACY(A)
#endif


#if ((OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION) && (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LEGACY_BOOT))
#define DISPLAY_LEGACY_BIOS_BBS_INFO(HddCount, HddInfo, BbsCount, BbsTable) DisplayLegacyBiosBbsInfo (HddCount, HddInfo, BbsCount, BbsTable)
#define DISPLAY_IBV_BBS_TABLE(a) DisplayIbvBbs (a)
#define DISPLAY_LEGACY_DEV_ORDER(a,b,c) DisplayLegacyDevOrder (a,b,c)
#else
#define DISPLAY_LEGACY_BIOS_BBS_INFO(HddCount, HddInfo, BbsCount, BbsTable)
#define DISPLAY_IBV_BBS_TABLE(a)
#define DISPLAY_LEGACY_DEV_ORDER(a,b,c)
#endif

//
// The DPRINTF_MM macro is used for Memory Management debug.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_MEMORY_MANAGEMENT
#define DPRINTF_MM(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#else
#define DPRINTF_MM(...)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_SERVICES
#define DPRINTF_BDS(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#else
#define DPRINTF_BDS(...)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_SERVICES_MEMORY_MANAGEMENT
#define DPRINTF_BDS_MM(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#else
#define DPRINTF_BDS_MM(...)
#endif

//
// Debug Macros for configuration.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_CONFIG
#define DPRINTF_CONFIG(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#else
#define DPRINTF_CONFIG(...)
#endif

//
// Debug Macros for the functionality of "Sort Drive Number by BootOrder.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION && OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER
#define DPRINTF_DN(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_DN(statement) BDS_DEBUG_CODE(statement)
#else
#define DPRINTF_DN(...)
#define DEBUG_DN(statement)
#endif

//
// Debug Macros for File Explorer module.
//

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_FILE_EXPLORER
#define DPRINTF_FE(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DPRINTF_FE_ERROR(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_FE(statement) BDS_DEBUG_CODE(statement)
#else
#define DPRINTF_FE(...)
#define DPRINTF_FE_ERROR(...)
#define DEBUG_FE(statement)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_FILE_EXPLORER_CA
#define DPRINTF_FE_CA(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_FE_CA(statement) BDS_DEBUG_CODE(statement)
#else
#define DPRINTF_FE_CA(...)
#define DEBUG_FE_CA(statement)
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_MISC
#define DPRINTF_BM_MISC(...) \
  do { \
    DPRINTF ("%a.%a(%d): ", __DRIVER__, __FUNCTION__, __LINE__); \
    DPRINTF (__VA_ARGS__); \
  } while (FALSE)
#define DEBUG_BM_MISC(statement) BDS_DEBUG_CODE(statement)
#else
#define DPRINTF_BM_MISC(...)
#define DEBUG_BM_MISC(statement)
#endif

//
// Add more instrumentation macros here as needed, one per module.
//
#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_TEST
SCT_STATUS
BdsServicesTest (VOID);
#define BDS_SERVICES_TEST() BdsServicesTest ()
#else
#define BDS_SERVICES_TEST()
#endif

#endif // not defined, _SCT_H_DEBUG
