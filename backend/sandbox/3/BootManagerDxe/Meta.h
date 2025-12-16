//
// FILENAME.
//      Meta.h - SecureCore Technology(TM) System Boot Manager Top-Level Include File.
//
// FUNCTIONAL DESCRIPTION.
//      This include file includes all of the other include files for
//      the System Boot Manager DXE Driver.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_META
#define _SCT_H_META

#include "Edk2Meta.h"

//
// Standard header files included by modules in this driver.
//

#include <SysMeta.h>                    // SCT System Includes.


//
// The libraries used by this driver.
//

#include <Library/SctBdsLib.h>
#include <Library/SctVariableLib.h>
#include <Library/SctMilestoneTaskLib.h>
#include <Library/SctBdsArchLib.h>


#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL
#include <Library/KeyManagementLib.h>
#endif

#include <Library/SctBootManagerLib.h>
#include <Library/SctBootManagerMiscLib.h>
#include <Library/SctBootOptionProtocolLib.h>
#include <Library/SctGopHelperLib.h>
#include <Library/SctBmDebugLib.h>
#include <Library/SctUnicodeDisplayLib.h>

//
// The following definitions specify the protocols used or published by this driver.
// (alphabetical order).
//

#include <Protocol/SctOemHook.h>
#include <Protocol/SctOemHooksInstalled.h>
#include <Protocol/SctBdsBootFailed.h>
#include <Protocol/SctConfigureConsole.h>
#include <Protocol/SctConsoleReady.h>
#include <Protocol/SctDiagnosticSplash.h>
#include <Protocol/SctErrorScreenText.h>
#include <Protocol/SctSecureBios.h>
#include <Protocol/SctHddPwdProtocol.h>
#include <Protocol/SctHiiImageDisplay.h>
#include <Protocol/SctImagePackage.h>
#include <Protocol/SctKeyDesc.h>
#include <Protocol/SctProgressIndicator.h>
#include <Protocol/SctTextSetupBrowser2.h>
#include <Protocol/SctVirtualKeyboard.h>
#include <Protocol/SctFirmwareDevice.h>
#include <Protocol/SctConsoleResolutionPolicy.h>
#include <Protocol/SctSecureFlashAuthentication.h>
#include <Protocol/SctBiosSelfHealing.h>
#include <Protocol/SctFirmwareVolumeLoader.h>
#include <Protocol/SctSecureVariableStorage.h>

#include <Protocol/SctFileExplorerContextMenu.h>

#include <Protocol/SctBootRestriction.h>

//
// These protocols are needed for their defines only.
// (alphabetical order).
//

#include <Protocol/SctDiagnosticSummary.h>
#include <Protocol/SctLegacyVideoBios.h>
#include <Protocol/SctSdHcIo.h>
#include <Protocol/SctSdHostIoProtocol.h>
#include <Protocol/SctSpeaker.h>
#include <Protocol/SctError.h>
#include <Protocol/SctCapsuleStorage.h>
#include <Protocol/SctCapsulePolicy.h>

//
// These GUIDs are used.
// (alphabetical order).
//

#include <Guid/SctHotkeyVariable.h>
#include <Guid/SctSystemConfiguration.h>
#include <Guid/SctSystemVideoResolution.h>
#include <Guid/SctAhciBus.h>
#include <Guid/SctConsoleRedirection.h>
#include <Guid/SctMiscGuid.h>
#include <Guid/PbaStatusVar.h>
#include <Guid/SctCapsule.h>
#include <Guid/SctDriverOverride.h>
#include <Guid/SctSelectView.h>
#include <Guid/SctBiosSelfHealing.h>
#include <Guid/SctBiosSelfHealingModeHob.h>

#if OPTION_PASSWORD_UNLOCK_ERROR_WARNING_DIALOG_SUPPORT
#include <Guid/SctPwdUnlockErrVariableStore.h>
#endif // OPTION_PASSWORD_UNLOCK_ERROR_WARNING_DIALOG_SUPPORT

//
// These protocols are produced in this driver.
//

#include <Protocol/SctBdsServices.h>
#include <Protocol/SctBootOption.h>

#include <Protocol/NvmExpressPassthru.h>
#include <Protocol/UfsDeviceConfig.h>

#if OPTION_SUPPORT_CSM
#include <Library/GenericBdsLib.h>
#include <Guid/Capsule.h>
#include <Protocol/LegacyRegion.h>
#include <Protocol/Legacy8259.h>
#include <Protocol/LegacyInterrupt.h>
#include <Protocol/LegacyBios.h>
#include <Protocol/ExitPmAuth.h>

#include <Framework/Hob.h>
#include <Guid/LegacyBios.h>
#endif //OPTION_SUPPORT_CSM

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
#include <Guid/LegacyDevOrderVariable.h>
#include <Protocol/FirmwareVolume.h>
#include <SctLegacy.h>
#include <Legacy16.h>
#include <LegacyBiosIntr.h>
#include <Protocol/SctSwSmiAllocator.h>
#include <Guid/SwSmiValueGuid.h>
#endif


//
// Device-driver specific header files included by this module.
//

#include <SctBootManager.h>             // Boot Manager object definition and function prototypes.
#include <SctLoadOption.h>              // Load Option object definition.
#include <SctHotkey.h>                  // Hotkey object definition.
#include <SctBdsDriverObject.h>         // Driver structure definitions.

#include "MetaInternal.h"
#include "MsTask.h"

extern GUID  gEfiCallerIdGuid;


#endif // _SCT_H_META
