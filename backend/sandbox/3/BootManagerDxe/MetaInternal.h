//
// FILENAME.
//      MetaInternal.h -
//
// FUNCTIONAL DESCRIPTION.
//
// NOTICE.
//      Copyright (C) 2021-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_META_INTERNAL
#define _SCT_H_META_INTERNAL

//
// Include standard header files.
//

//#include "BopLib.h"                     // Boot Option Protocol Library.
#include "NvmeCmd.h"                    // Create Nvme Model Name.
#include "Legacy.h"                     // Legacy Boot define.

#if OPTION_SUPPORT_SURE_BOOT
#include "SureBoot.h"
#endif

#if OPTION_SUPPORT_SECURE_BIOS
#include "BdsSecureBios.h"
#endif

#if OPTION_SUPPORT_CAPSULE_UPDATE
#include "BdsCapsuleUpdate.h"
#endif

#if OPTION_SUPPORT_BIOS_SELF_HEALING
#include "BdsBiosSelfHealing.h"
#endif

#if OPTION_SUPPORT_BIOS_DATA_SELF_HEALING
#include "BdsBiosDataSelfHealing.h"
#include <FlashMap.h>                 //Build (Output_Dir)
#endif

#if OPTION_SUPPORT_WUFU
#include <EsrtDefinition.h>
#include <TdkError.h>
#endif // OPTION_SUPPORT_WUFU

#include "BdsMisc.h"

#if OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS
#include <TdkService.h>
#include <Guid/SctFlashIdentification.h>
#endif

//
// Transferred from .c files
//

// String ID definition.
#ifdef  MODULE_STR_DEFS_FILE
#include  MODULE_STR_DEFS_FILE
#endif  //MODULE_STR_DEFS_FILE

// Image ID definition.
#ifdef  MODULE_IMG_DEFS_FILE
#include  MODULE_IMG_DEFS_FILE
#endif  //MODULE_IMG_DEFS_FILE

//
// CsmModule defines these OPTION in package.def.
// If project doesn't have CsmModule, set these OPTION to 0 for avoiding the wrong definitions.
//

#ifndef OPTION_CSM_OPTION_OUT
#define OPTION_CSM_OPTION_OUT 0
#endif

#ifndef OPTION_CSM_AUTO_OPTION
#define OPTION_CSM_AUTO_OPTION 0
#endif



//
// Public API functions implemented by this component.
//

extern
SCT_STATUS
EFIAPI
ConInInit (VOID);

extern
SCT_STATUS
EFIAPI
ConOutInit (VOID);

extern
SCT_STATUS
EFIAPI
ErrOutInit (VOID);

extern
SCT_STATUS
EFIAPI
InitializeLoadOptions (VOID);

extern
SCT_STATUS
EFIAPI
InitializeBdsServices (VOID);

extern
EFI_STATUS
EFIAPI
InitializeBootManagerPolicy (
  VOID
  );

extern
SCT_STATUS
EFIAPI
SetEfiGlobalVariable (
  IN PCHAR16 VariableName,
  IN UINT32 Attributes,
  IN UINTN DataSize,
  IN PVOID Data
  );

extern
SCT_STATUS
InitializeDevice (VOID);

SCT_STATUS
EFIAPI
ConnectDevices (IN PBOOT_MANAGER_CONNECTION_DEVICE  DeviceList);

extern
BOOLEAN
EFIAPI
QuickBootEnabled (VOID);

extern
BOOLEAN
EFIAPI
LegacyBootEnabled (OUT PBOOLEAN LegacyBeforeUefi OPTIONAL);

extern
SCT_STATUS
InitializeLegacy (VOID);

extern
SCT_STATUS
EFIAPI
AddAllHotPlugConInDeviceToVariable (VOID);

extern
EFI_STATUS
EFIAPI
SignalConsoleReady (VOID);

extern
SCT_STATUS
InitializeConfiguration (VOID);

// #if OPTION_CSM_OPTION_OUT
extern
SCT_STATUS
EFIAPI
PrepareContextOverrideDriver (VOID);
// #endif // OPTION_CSM_OPTION_OUT

extern
SCT_STATUS
EFIAPI
PrepareContextOverrideDriverForEssential (VOID);

extern
SCT_STATUS
EFIAPI
DiscoverBmEssentialVariable (IN BOOLEAN Force);

extern
EFI_STATUS
EFIAPI
RemoveAllBootManagerVariable (VOID);

extern
SCT_STATUS
EFIAPI
FreeBmEssentialVariable (VOID);

extern
SCT_STATUS
RegisterPauseHotkey (VOID);

extern
SCT_STATUS
UnRegisterPauseHotkey (VOID);

extern
SCT_STATUS
EFIAPI
ConnectAllPciDevices (VOID);

extern
EFI_STATUS
EFIAPI
LaunchFvFile (
  IN EFI_HANDLE ParentHandle,
  IN EFI_DEVICE_PATH_PROTOCOL *FvFile,
  OUT UINTN *ExitDataSize,
  OUT PCHAR16 *ExitData
  );

extern
SCT_STATUS
EFIAPI
LaunchBuiltInApplication (IN CHAR16 *FilePath);

extern
EFI_STATUS
CheckBootManagerVariable (
  IN BOOLEAN Force,
  IN EFI_GUID *Guid
  );

extern
EFI_STATUS
ReportBootManagerError (VOID);

//#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
extern
SCT_STATUS
EFIAPI
EnumerateAllLoadOptions (VOID);
//#endif

extern
BOOLEAN
EFIAPI
IsBootOrderChanged (VOID);

//#if OPTION_SYSTEM_SCT_ACPI_BGRT
EFI_STATUS
EFIAPI
SetBootLogoInvalid (VOID);
//#endif

extern
EFI_STATUS
EFIAPI
ConnectAllHandlesExceptPciVga (VOID);

extern
EFI_STATUS
DecompressOptionalFirmwareVolume (UINTN Type);

extern
EFI_STATUS
BmUnloadImages (IN EFI_GUID FvFileName []);

extern
VOID
EFIAPI
BmRegisterContextMenu (
  IN EFI_EVENT Event,
  IN VOID *Context
  );

extern
BOOLEAN
IsPreDefinedLoadOption (IN UINT16 OptionNumber);

extern
SCT_STATUS
EFIAPI
GetConsoleByVariable (
  IN PCHAR16 VariableName,
  OUT UINTN  *VariableSize
  );

extern
SCT_STATUS
EFIAPI
ConnectConsoleRedirectByVariable (
  IN PCHAR16 VariableName,
  IN UINTN  VariableSize
  );

extern
VOID
EFIAPI
RequestPs2Drivers (VOID);

extern
SCT_STATUS
EFIAPI
LoadDeferredImage (VOID);

extern
EFI_STATUS
PrepareDeferred (VOID);

extern
UINT8
VerifyAllConsoleVariable (VOID);

extern
SCT_STATUS
EFIAPI
ConnectDefaultDevices (VOID);

extern
SCT_STATUS
EFIAPI
ConnectAllUsbHostController (VOID);

extern
VOID
CollectAllConsoles (VOID);

//#if (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)
extern
EFI_STATUS
BdsEnableSmmCodeAccessCheck (VOID);
//#endif

//#if OPTION_SUPPORT_TCG
BOOLEAN
IsMorBitSet (
  VOID
  );
//#endif //if OPTION_SUPPORT_TCG

SCT_STATUS
UpdateProgress (
  IN UINT64 Phase,
  IN UINT64 Completed,
  IN UINT64 Total OPTIONAL,
  IN PCHAR16 String OPTIONAL
  );

SCT_STATUS
RequestDrivers (
  IN EFI_HANDLE FirmwareVolumeHandle,
  IN EFI_GUID FvFileName [],
  IN UINTN FirmwareVolumeType,
  IN BOOLEAN Dispatch
  );

//#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND

EFI_STATUS
EFIAPI
InitializeUsbFullInitOnDemand (VOID);

EFI_STATUS
EFIAPI
ReleaseAllUsbHc (VOID);

EFI_STATUS
EFIAPI
StartAllUsbHc (VOID);

//#endif // OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND

VOID
EFIAPI
BmConnectAll (VOID);

SCT_STATUS
EFIAPI
UefiBoot (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINT16 OptionNumber,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  );


//
// Data defined in this module shared with other modules *within* this component.
//

#ifdef MODULE_STRING_ARRAY
  extern unsigned char MODULE_STRING_ARRAY [];    // generated by uni string package.
#else
  //#error  MODULE_STRING_ARRAY was not defined in INF!!!
#endif // MODULE_STRING_ARRAY

#ifdef MODULE_IMAGE_ARRAY
  extern unsigned char MODULE_IMAGE_ARRAY [];    // generated by uni string package.
#else
  //#error  MODULE_IMAGE_ARRAY was not defined in INF!!!
#endif // MODULE_IMAGE_ARRAY

extern EFI_HANDLE mImageHandle;

extern SCT_SYSTEM_CONFIGURATION mSystemConfiguration;
extern BOOLEAN mDisplayHotkeysDuringPost;
extern SYSTEM_CONSOLE_REDIRECTION mSystemConRedirect;
extern BOOT_MANAGER_CONNECTION_DEVICE LegacyConnectList [];
extern UINTN mDeferredVgaHandle;

extern EFI_HANDLE mFvHandle;
extern BOOT_MANAGER_CONFIGURATION mBootManagerConfigurationTable [];
extern UINTN                      mBootManagerConfigurationTableSize;
extern BOOT_REORDER mBootReorder;
extern BOOLEAN mDxeSmmReadyToLockProtocol;
extern BOOLEAN mCapsuleEspDelivery;
extern EFI_BOOT_MODE mBootMode;
extern SCT_ERROR_SCREEN_TEXT_PROTOCOL *ErrorInfoScreen;


#endif // _SCT_H_META_INTERNAL