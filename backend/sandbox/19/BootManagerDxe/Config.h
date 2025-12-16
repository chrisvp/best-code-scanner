//
// FILENAME.
//      Config.h - SecureCore Technology(TM) System Boot Manager Build Configuration Parameters.
//
// FUNCTIONAL DESCRIPTION.
//      This include file defines the configuration parameters for the
//      System Boot Manager DXE Driver, allowing its policies to
//      be managed through build-time options.
//
//      In general, all those parameters which could be envisioned to be
//      controllable by the user, should be configured through configuration
//      parameters associated with this driver.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_CONFIG
#define _SCT_H_CONFIG

//
// The following are Debug instrumentation options.
//

#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION        0       // custom instrumentation in Debug.c.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_FUNCTION_ENTRY         0       // Function Entry print out instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INIT                   0       // initialization instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BOOTMANAGER            0       // endpoint instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_CONSOLE                0       // console instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_HOTKEY                 0       // hotkey instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_VARIABLE               0       // variable instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LOAD_OPTION            0       // load option instrumentation.
#define OPTION_DEBUG_DPRINTF_WITH_LEVEL                         0       // DPRINTF_LEVEL Macro enabled/disabled
#define CONFIG_DEBUG_DPRINTF_LEVEL                              0       // DPRINTF_LEVEL instrumentation verbose level.
#define OPTION_DEBUG_CODE_WITH_LEVEL                            0       // DEBUG_LEVEL_CODE Macro enabled/disabled
#define CONFIG_DEBUG_CODE_LEVEL                                 0       // DEBUG_LEVEL_CODE instrumentation execute level.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LOAD_OPTION_ENUM       0       // enumerate all LoadOption.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LEGACY_BOOT            0       // legacy boot instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DEVICE                 0       // device module instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DEVICE_CHILD           0       // device module, child detection instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DEVICE_CHECK           0       // device module, check the type of device.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_MEMORY_MANAGEMENT      0       // memory management instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_SERVICES           0       // BDS Services Protocol instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_SERVICES_TEST      0       // BDS Services Protocol test.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_SERVICES_MEMORY_MANAGEMENT 0 // BDS memory management instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_CONFIG                 0       // configuration instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_TEST               0
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER           0       // drive number sorting instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_FILE_EXPLORER          0       // file explorer instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_FILE_EXPLORER_CA       0       // file explorer ConfigAccess instrumentation.
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_MISC                   0
#define OPTION_DEBUG_SYSTEM_BOOT_MANAGER_ERROR                  1

#define OPTION_SYSTEM_BOOT_MANAGER_EFI_LEGACY_OS_SUPPORT        1       // Support EFI Legacy OS (Ex. Windows 7)

//
// The following are other configuration statements applicable to this driver.
//

#ifndef PROJECT_FIRMWARE_VENDOR
#define PROJECT_FIRMWARE_VENDOR L"Phoenix Technologies"
#endif

//
// PROJECT_FIRMWARE_REVISION Should be overridden by the project settings.
// This value will be programmed SystemTable->FirmwareRevision, a UINT32
// representing the BIOS version.
//

#ifndef PROJECT_FIRMWARE_REVISION
#define PROJECT_FIRMWARE_REVISION 0x12345678
#endif                                  // not defined, PROJECT_FIRMWARE_REVISION

//
// Console Defaults.
// Note the trailing comma. It is done this way so that when there is no value
// in the default macro the array can still have one element. To cover all
// cases the comma needs to be associated with the macro and not in the array
// declaration.
//

#define SCT_BM_CONSOLE_CONIN_DEFAULT    CONFIG_CONSOLE_IN_PS2,
#define SCT_BM_CONSOLE_CONOUT_DEFAULT   CONFIG_CONSOLE_OUT_ONBOARD,
#define SCT_BM_CONSOLE_ERROUT_DEFAULT

//
// Cursor configuration.
//

#define SYSTEM_BOOT_MANAGER_CURSOR_LAST         0x80000000

//
// Boot Manager Capabilities, per the UEFI Specification 2.3, Section 3.1.4.
//

#define CONFIG_SCT_BM_NUMBER_OF_HOTKEYS_SUPPORTED 3
#define SCT_BM_NUMBER_OF_HOTKEYS_SUPPORTED CONFIG_SCT_BM_NUMBER_OF_HOTKEYS_SUPPORTED

#define SCT_BM_BOOT_OPTION_SUPPORT EFI_BOOT_OPTION_SUPPORT_KEY | \
        EFI_BOOT_OPTION_SUPPORT_APP | EFI_BOOT_OPTION_SUPPORT_SYSPREP | \
        (EFI_BOOT_OPTION_SUPPORT_COUNT & (SCT_BM_NUMBER_OF_HOTKEYS_SUPPORTED << EFI_BOOT_OPTION_SUPPORT_COUNT_BITPOS))

#ifndef SCT_BM_PLATFORM_LANG_CODES
#define SCT_BM_PLATFORM_LANG_CODES "en-US;ja-JP;fr-FR;ko-KR"
//#define SCT_BM_PLATFORM_LANG_CODES "en-US;zh-CHS;ja-JP;fr-FR;ko-KR;zh-CHT"
#endif

#ifndef SCT_BM_PLATFORM_LANG
#define SCT_BM_PLATFORM_LANG "en-US"
#endif

#define CONFIG_All_Device_SearchList    {L"PciRoot(0x0)", NULL}

//
// Capsule configuration.
//

#define MAX_CAPSULE_COUNT 16

//
// Below configurations will be overridden by Project.h
//

#define CONFIG_SYSTEM_ACPI_S3_SAVE_SIZE_CSM 0x250

//#define NUMBER_OF_TOGGLE_CASE 8

#define Max_NUMBER_OF_DEFERRED_IMAGE 20

#define OPTION_SUPPORT_MULTI_TERMINAL_DEVICE_PATH     1
#define OPTION_SYSTEM_BOOT_MANAGER_ADD_HOTPLUG_CON_IN 0

#define CONFIG_CSM_MODULE_FV_FILE_GUID_LIST \
  {0x46482D14, 0x7CA1, 0x4977, {0x9D, 0xDB, 0x64, 0xD7, 0x47, 0xE1, 0x3D, 0xE6}}, /* SystemLegacyBiosDxe Module. */ \
  {0x29cf55f8, 0xb675, 0x4f5d, {0x8f, 0x2f, 0xb8, 0x7a, 0x3e, 0xcf, 0xd0, 0x63}}, /* SystemVga Module. */  \
  {0xEF33C296, 0xf64c, 0x4146, {0xad, 0x04, 0x34, 0x78, 0x99, 0x70, 0x2c, 0x84}}  /* USB SMM Driver. */

#define CONFIG_ON_DEMAND_FV_FILE_GUID_LIST \
  {0x37087b94, 0xef41, 0x4977, {0x93, 0xe2, 0x3f, 0x6a, 0xdf, 0xdd, 0x06, 0xe1}}, /* Splash Module. */            \
  {0xcb8c0e4f, 0x14f7, 0x4f5a, {0x8d, 0xad, 0x75, 0x2c, 0xb0, 0xb4, 0x20, 0x45}}, /* StatusBar Module. */         \
  {0x33CDC56C, 0xB1EF, 0x4b21, {0x87, 0xE4, 0x22, 0x5F, 0x42, 0xC6, 0x7F, 0x4A}}, /* ProgressIndicator Module. */ \
  {0xfb8fade6, 0x0931, 0x45cf, {0x8e, 0x8c, 0xb9, 0x7f, 0xda, 0xb4, 0x09, 0x1f}}, /* OSB Module. */               \
  {0x114bc6c1, 0x404b, 0x4232, {0x83, 0x16, 0x7c, 0xfa, 0x66, 0xd0, 0xb6, 0x0a}}  /* OSB Module. */

#define CONFIG_SEAMLESS_BOOT_FV_FILE_GUID_LIST \
  {0x37087b94, 0xef41, 0x4977, {0x93, 0xe2, 0x3f, 0x6a, 0xdf, 0xdd, 0x06, 0xe1}}, /* Splash Module. */    \
  {0xcb8c0e4f, 0x14f7, 0x4f5a, {0x8d, 0xad, 0x75, 0x2c, 0xb0, 0xb4, 0x20, 0x45}}  /* StatusBar Module. */

#define CONFIG_NETWORK_ESSENTIAL_FV_FILE_GUID_LIST \
  {0xA2f436EA, 0xA127, 0x4EF8, {0x95, 0x7c, 0x80, 0x48, 0x60, 0x6f, 0xf6, 0x70}}, /* SnpDxe Module. */     \
  {0x025BBFC7, 0xE6A9, 0x4b8b, {0x82, 0xad, 0x68, 0x15, 0xa1, 0xae, 0xaf, 0x4A}}, /* MNP Module. */        \
  {0x529D3F93, 0xE8E9, 0x4e73, {0xb1, 0xe1, 0xbd, 0xf6, 0xa9, 0xd5, 0x01, 0x13}}, /* ARP Module. */        \
  {0xB95E9FDA, 0x26DE, 0x48d2, {0x88, 0x07, 0x1f, 0x91, 0x07, 0xac, 0x5e, 0x3a}}, /* UefiPxeBc Module. */  \
  {0xecebcb00, 0xd9c8, 0x11e4, {0xaf, 0x3d, 0x8c, 0xdc, 0xd4, 0x26, 0xc9, 0x73}}, /* HttpBoot Module. */   \
  {0xE4F61863, 0xFE2C, 0x4b56, {0xA8, 0xF4, 0x08, 0x51, 0x9b, 0xc4, 0x39, 0xdf}}  /* VlanConfig Module. */

#define CONFIG_NETWORK_IPV4_FV_FILE_GUID_LIST \
  {0x9FB1A1F3, 0x3B71, 0x4324, {0xB3, 0x9A, 0x74, 0x5C, 0xBB, 0x01, 0x5F, 0xFF}}, /* IPv4 Module. */      \
  {0xDC3641B8, 0x2FA8, 0x4ed3, {0xBC, 0x1F, 0xF9, 0x96, 0x2A, 0x03, 0x45, 0x4B}}, /* MTFTP4 Module. */    \
  {0x94734718, 0x0BBC, 0x47fb, {0x96, 0xa5, 0xee, 0x7a, 0x5a, 0xe6, 0xa2, 0xad}}, /* DHCP4 Module. */     \
  {0x6d6963ab, 0x906d, 0x4a65, {0xa7, 0xca, 0xbd, 0x40, 0xe5, 0xd6, 0xaf, 0x2b}}, /* UDP4 Module. */      \
  {0x26841BDE, 0x920A, 0x4e7a, {0x9f, 0xbe, 0x63, 0x7f, 0x47, 0x71, 0x43, 0xa6}}, /* Ip4Config Module. */ \
  {0x6d6963ab, 0x906d, 0x4a65, {0xa7, 0xca, 0xbd, 0x40, 0xe5, 0xd6, 0xaf, 0x4d}}, /* TCP4 Module. */      \
  {0x4579B72D, 0x7EC4, 0x4dd4, {0x84, 0x86, 0x08, 0x3C, 0x86, 0xB1, 0x82, 0xA7}}  /* IScsi Module. */

#define CONFIG_SCSI_MODULE_FV_FILE_GUID_LIST \
  {0xE1AD4352, 0x2610, 0x4dd6, {0xBB, 0xbf, 0x8b, 0xb2, 0xb0, 0x33, 0x83, 0xa3}}  /* SCSI Oprom PassThru Module. */

#define CONFIG_TERMINAL_DRIVER_FV_FILE_GUID_LIST \
  {0x9E863906, 0xA40F, 0x4875, {0x97, 0x7F, 0x5B, 0x93, 0xFF, 0x23, 0x7F, 0xC6}}

#define CONFIG_TEXT_VIEW_FV_FILE_GUID_LIST \
  {0xD687E479, 0xDB37, 0x4BCE, {0x86, 0x4A, 0x02, 0xEE, 0xF6, 0x81, 0x9D, 0xF1}}, /* Text View FILE_GUID. */        \
  {0xAADFA1AC, 0xE923, 0x4673, {0xB1, 0xB8, 0x71, 0x4A, 0xD8, 0x49, 0xF7, 0x90}}, /* Text View Layout FILE_GUID. */ \
  {0x86488440, 0x41BB, 0x42C7, {0x93, 0xAC, 0x45, 0x0F, 0xBF, 0x77, 0x66, 0xBF}}, /* Boot Menu. */                  \
  {0x166CD554, 0x8AAE, 0x4617, {0x8F, 0xDD, 0xA2, 0xE3, 0xA5, 0xAF, 0xD8, 0x9E}}  /* Advance Page. */

#define CONFIG_GRAPHIC_VIEW_FV_FILE_GUID_LIST \
  {0x8E1F8670, 0xA1A3, 0x4C12, {0x86, 0xDF, 0xC8, 0xA5, 0x0A, 0xBB, 0xEB, 0x07}}, /* Graphic View FILE_GUID. */ \
  {0xDD296B31, 0xD867, 0x461C, {0xB9, 0x13, 0x39, 0x7E, 0x7E, 0x18, 0x76, 0x89}}, /* Graphic View Layout. */    \
  {0x86488440, 0x41BB, 0x42C7, {0x93, 0xAC, 0x45, 0x0F, 0xBF, 0x77, 0x66, 0xBF}}, /* Boot Menu. */              \
  {0x166CD554, 0x8AAE, 0x4617, {0x8F, 0xDD, 0xA2, 0xE3, 0xA5, 0xAF, 0xD8, 0x9E}}  /* Advance Page. */

#define CONFIG_GUI_VIEW_FV_FILE_GUID_LIST \
  {0xC7351A96, 0x9215, 0x4026, {0xBC, 0xBD, 0x12, 0xD6, 0xE7, 0xDB, 0x36, 0xE9}}, /* GUI View. */        \
  {0x84C31E7D, 0x3703, 0x42D3, {0xB4, 0x3B, 0x1F, 0xEE, 0x41, 0x66, 0x6D, 0x9A}}, /* GUI View Layout. */ \
  {0x2B475251, 0x13C6, 0x4547, {0xB2, 0xF2, 0x40, 0x76, 0x2F, 0xEF, 0x9B, 0x89}}, /* GUI Boot Menu. */   \
  {0x461A67CF, 0x3D9B, 0x4fc0, {0xBC, 0xD2, 0x7c, 0x60, 0x63, 0x35, 0xDE, 0x0F}}  /* GUI Advance Page.. */

#define CONFIG_SYSTEM_BOOT_MANAGER_GENERIC_DEVICE_READY_WAIT_TIME 0

#define OPTION_SYSTEM_ACPI_TIMER_TO_POSTCODE 0

//
// This Option for SUPPORT DEVICE PATH EXPANSION by gEfiBlockIoProtocolGuid
//
#define OPTION_SUPPORT_BLOCK_IO_DEVICE_PATH_EXPANSION   0

//
// This Option SUPPORT for "Internal Shell" Connect All Handles (Except PCI VGA) at the First of "BootOrder"
//
#define OPTION_SYSTEM_BOOT_MANAGER_CONNECT_ALL_WITH_INTERNAL_SHELL_AT_FIRST_BOOT_ORDER  0

#endif // not defined, _SCT_H_CONFIG
