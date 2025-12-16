//
// FILENAME.
//      MetaInternal.h -
//
// FUNCTIONAL DESCRIPTION.
//
// NOTICE.
//      Copyright (C) 2021-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_MILE_STONE_TASK_
#define _SCT_H_MILE_STONE_TASK_

//
// Include standard header files.
//
#include <Uefi.h>
#include <Protocol/SctOemHook.h>

//
// Prototype function of the Milestone tasks
//

//
// PhBootManagerPkg\BootManagerDxe\BootManager.c
//
MS_TASK (MsTaskBdsEntry);

MS_TASK (MsTaskConnectConsoles);
MS_TASK (MsTaskCollectConsole);
MS_TASK (MsTaskConnectConsoleOut);
MS_TASK (MsTaskConnectConsoleIn);
MS_TASK (MsTaskConnectErrorOut);

MS_TASK (MsTaskDisplaySplashScreen);
MS_TASK (MsTaskUpdateHotkeySupportCount);
MS_TASK (MsTaskDisplayHotkey);
MS_TASK (MsTaskTimeout);
MS_TASK (MsTaskUpdateProgress);
MS_TASK (MsTaskConnectDevices);
MS_TASK (MsTaskConnectDrivers);
MS_TASK (MsTaskTpmCheck);
MS_TASK (MsTaskInitializeSecurity);
MS_TASK (MsTaskRunDiagnostics);
#if OPTION_SUPPORT_DIAGNOSTIC_SUMMARY
MS_TASK (MsTaskDisplayDiagnosticSummary);
#endif
MS_TASK (MsTaskHotkeyDetect);
MS_TASK (MsTaskLegacyInit);

MS_TASK (MsTaskProcessBootNextVariable);
MS_TASK (MsTaskProcessBootOrderVariable);
MS_TASK (MsTaskAllBootOptionBootFailed);
MS_TASK (MsTaskDisplayDiagnosticSplashScreen);
MS_TASK (MsTaskNotifyPasswordUnlockError);
MS_TASK (MsTaskAfterReadyToBoot);
#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND
MS_TASK (MsTaskIsPS2KeyboardNoExist);
#endif
MS_TASK (MsTaskConnectSysPreps);
MS_TASK (MsTaskLoadDeferredImage);

#if OPTION_SUPPORT_TCG
MS_TASK (MsTaskMemoryOverwriteControl);
#endif //if OPTION_SUPPORT_TCG

#ifdef OPTION_SUPPORT_BIOS_SELF_HEALING
MS_TASK (MsTaskBiosSelfHealing);
#endif //ifdef OPTION_SUPPORT_BIOS_SELF_HEALING

//
// PhBootManagerPkg\BootManagerDxe\LoadOption.c
//
//MS_TASK (MsTaskAfterReadyToBoot);
//MS_TASK (MsTaskTimeout);
//MS_TASK (MsTaskLegacyInit);

MS_TASK (MsTaskLaunchBootOption);
MS_TASK (MsTaskLaunchApplicationOption);
MS_TASK (MsTaskLaunchDevicePath);

#if OPTION_SUPPORT_OS_INDICATIONS_CAPSULE_DELIVERY
MS_TASK (MsTaskCapsuleFlashUpdate);
#endif // OPTION_SUPPORT_OS_INDICATIONS_CAPSULE_DELIVERY

#if OPTION_SUPPORT_CAPSULE_UPDATE
MS_TASK (MsTaskCapsuleFlashUpdate);
#endif

//
// PhBootManagerPkg\BootManagerDxe\BootManagerPolicy.c
//
//MS_TASK (MsTaskCollectConsole);
//MS_TASK (MsTaskConnectErrorOut);
//MS_TASK (MsTaskConnectConsoleIn);
//MS_TASK (MsTaskConnectConsoleOut);

//
// PhBootManagerPkg\BootManagerDxe\Console.c
//
MS_TASK (MsTaskDetermineDeferredImage);

//
// PhBootManagerPkg\BootManagerDxe\Hotkey.c
//
//MS_TASK (MsTaskLegacyInit);

//
// PhBootManagerPkg\BootManagerDxe\Legacy.c
//
//MS_TASK (MsTaskLegacyInit);
//MS_TASK (MsTaskAfterReadyToBoot);

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
#if OPTION_SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT
MS_TASK (MsTaskDecideLegacyBoot);
#endif // SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT


#endif // _SCT_H_MILE_STONE_TASK_
