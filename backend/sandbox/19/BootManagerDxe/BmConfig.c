//
// FILENAME.
//      Config.c - SecureCore Technology(TM) System Boot Manager Configuration Management.
//
// FUNCTIONAL DESCRIPTION.
//      This module implements an API, callable from the other portions
//      of this driver, that provides management of the driver's
//      configuration through compile time constants (declared in Config.h).
//
//      This module provides the framework for run-time setting of the configuration
//      parameters.
//
//      Throughout this driver, care must be taken to not define ad-hoc
//      parameters (e. g. DELAY_INTERVAL), but instead refer to global variables
//      exposed by this module, which are initialized by compile-time default
//      values (established in Config.h), and overridden by variable settings.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

//
// Private data types used by this module are defined here and any
// static items are declared here.
//

GLOBAL_REMOVE_IF_UNREFERENCED
BOOLEAN     mRequiresProjectLoad = TRUE;

static BOOLEAN ConfigDisplayHotkeys = OPTION_SYSTEM_BOOT_MANAGER_DISPLAY_HOTKEYS;

#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK
#define SCT_COMMAND_VARIABLE_GUID {0x5d3a4ed8, 0xcae7, 0x4be0, { 0xa2, 0xbd, 0xde, 0x4, 0x3d, 0x4e, 0x5d, 0xe5 }}
static EFI_GUID mCommandVariableGuid = SCT_COMMAND_VARIABLE_GUID;

#endif

//
// Prototypes for functions in other modules that are a part of this component.
//

extern
SCT_STATUS
EFIAPI
SetEfiGlobalVariable (
  IN PCHAR16 VariableName,
  IN UINT32 Attributes,
  IN UINTN DataSize,
  IN PVOID Data
  );

//
// Data shared with other modules *within* this component.
//

SCT_SYSTEM_CONFIGURATION mSystemConfiguration;
BOOLEAN mDisplayHotkeysDuringPost = TRUE;
SYSTEM_CONSOLE_REDIRECTION mSystemConRedirect;
extern EFI_BOOT_MODE mBootMode;

#if OPTION_SUPPORT_SECURE_BOOT
BOOLEAN mSecureBoot = TRUE;
#endif

#if OPTION_SUPPORT_TCG
UINT8 mMorControl = 0;
#endif

//
// The Default Load Options and Hotkeys are defined in the project file and
// instantiated in this table.
//
#if (CONFIG_BBS_MULTIBOOT_TYPE == BBS_MULTIBOOT_TYPE_XP)
BOOT_MANAGER_CONFIGURATION mBootManagerConfigurationTable [] = {
  CONFIG_BmConfigTable                  // boot options defined in MODULE.DEF.
};
#endif

#if (CONFIG_BBS_MULTIBOOT_TYPE == BBS_MULTIBOOT_TYPE_3)
BOOT_MANAGER_CONFIGURATION mBootManagerConfigurationTable [] = {
  CONFIG_Mb3BmConfigTable                  // boot options defined in MODULE.DEF.
};
#endif

GLOBAL_REMOVE_IF_UNREFERENCED
UINTN   mBootManagerConfigurationTableSize = sizeof (mBootManagerConfigurationTable);

BOOT_REORDER mBootReorder = {
  .Signature    = '$' | 'B' << 8 | 'O' << 16 | 'D' << 24,
  .ElementSize  = sizeof (BOOT_MANAGER_CONFIGURATION),
  .ElementCount = sizeof (mBootManagerConfigurationTable) / sizeof (BOOT_MANAGER_CONFIGURATION),
  .IsReOrdered  = 'N',
  .ReOrder      = {0}
};

//
// Data defined in other modules and used by this module.
//

//
// Forward declarations for functions declared in this module.
//

BOOLEAN
EFIAPI
QuickBootEnabled (VOID);

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK

static
VOID
InitializeBootOrder (VOID);

#endif

//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      InitializeConfiguration - Establish Runtime Configuration Policies.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called during driver initialization to determine
//      the runtime policies associated with this driver.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
InitializeConfiguration (VOID)
{
  SCT_STATUS Status;
  UINTN VarSize;
#if OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME
  EFI_HANDLE ReadyToBootEvent;
#endif // OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME

  DPRINTF_INIT ("Entry\n");

  mRequiresProjectLoad = FALSE;
  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,                      // attributes.
             NULL,                      // dataSize.
             NULL);                     // data.
  DPRINTF_INIT ("SctLibGetEfiGlobalVariable (BootOrder) returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    mRequiresProjectLoad = TRUE;
  }

  Status = RequiresProjectUpdate ( mBootMode, mBootManagerConfigurationTable, mBootManagerConfigurationTableSize, &mRequiresProjectLoad );
  DPRINTF_INIT ("  RequiresProjectUpdate ret Status = [%r]\n", Status);

#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK
  if (!mRequiresProjectLoad) {
    InitializeBootOrder ();
  }
#endif

  //
  // Initialize Sct System Configuration data.
  //

  VarSize = sizeof (mSystemConfiguration);

  Status = gRT->GetVariable (
                  SYSTEM_CONFIGURATION_VARIABLE_NAME,
                  &gSctSystemConfigurationGuid,
                  NULL,
                  &VarSize,
                  &mSystemConfiguration);

  if (EFI_ERROR (Status)) {
    ZeroMem (&mSystemConfiguration, sizeof (mSystemConfiguration));
    mSystemConfiguration.UefiBoot = TRUE;
    DPRINTF ("Failed to get SYSTEM_CONFIGURATION_VARIABLE_NAME variable, status: %r.\n", Status);
  }

#if OPTION_SUPPORT_SECURE_BOOT

  //
  // Get Secure Boot Option data
  //

  VarSize = sizeof (mSecureBoot);
  Status = gRT->GetVariable (
                  EFI_SECURE_BOOT_MODE_NAME,
                  &gEfiGlobalVariableGuid,
                  NULL,
                  &VarSize,
                  &mSecureBoot);
  DPRINTF_INIT ("GetVariable SecureBoot returned %r.\n", Status);
  if (!EFI_ERROR (Status) && mSecureBoot == TRUE) {

    DPRINTF_INIT ("  Currnet SecureBoot state %d.\n", mSecureBoot);

    //
    // If SecureBoot is enabled,
    // CSM should not be loaded and legacy boot is also disabled.
    //

    mSystemConfiguration.CsmSupport = 0;
    mSystemConfiguration.LegacyBoot = 0;
  }

#endif

  //
  // Get Sct System Console Redirection data
  //

  VarSize = sizeof (mSystemConRedirect);

  Status = gRT->GetVariable (
                  SYSTEM_CONSOLE_REDIRECTION_NAME,
                  &gSctConsoleRedirectionGuid,
                  NULL,
                  &VarSize,
                  &mSystemConRedirect);

  if (EFI_ERROR (Status)) {
    DPRINTF ("Failed to get SYSTEM_CONSOLE_REDIRECTION_NAME variable, status: %r.\n", Status);
  }

#if OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME
  Status = EfiCreateEventReadyToBootEx (
             TPL_CALLBACK,
             BmConnectDeviceEntryCallbackFuction,
             NULL,
             &ReadyToBootEvent);
  InitializeListHead (&ConnectDeviceHandleEntryLink);
#endif // OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME

#if OPTION_SUPPORT_TCG

  ///
  /// The firmware is required to create the MemoryOverwriteRequestControl UEFI variable.
  ///

  VarSize = sizeof (mMorControl);
  Status = gRT->GetVariable (
                  MEMORY_OVERWRITE_REQUEST_VARIABLE_NAME,
                  &gEfiMemoryOverwriteControlDataGuid,
                  NULL,
                  &VarSize,
                  &mMorControl
                  );
  if (EFI_ERROR (Status)) {

    //
    // Set default value to 0.
    //
    VarSize = sizeof (mMorControl);
    mMorControl = 0;
    Status = gRT->SetVariable (
                    MEMORY_OVERWRITE_REQUEST_VARIABLE_NAME,
                    &gEfiMemoryOverwriteControlDataGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                    VarSize,
                    &mMorControl
                    );
    DPRINTF_INIT ("TcgMor: Create MOR variable! Status = %r\n", Status);
  }
#endif

  return EFI_SUCCESS;
} // InitializeConfiguration

//
// FUNCTION NAME.
//      RequiresProjectLoad - Should the Boot Manager load project settings?
//
// FUNCTIONAL DESCRIPTION.
//      This function informs the Boot Manager of the need to load project
//      settings. There may be several conditions that require that the project
//      settings be loaded.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - true if Boot Manager should load project
//                        settings, otherwise False.
//
// WARNINGS.
//      None.
//

BOOLEAN
EFIAPI
RequiresProjectLoad (VOID)
{
  return mRequiresProjectLoad;
} // RequiresProjectLoad

//
// FUNCTION NAME.
//      ShowHotkeyMessages - Should the Boot Manager display the hotkey strings?
//
// FUNCTIONAL DESCRIPTION.
//      This function answers the policy question regarding hotkey display
//      messages. If the function returns TRUE then hotkey messages should be
//      displayed.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - true if hotkey messages should be displayed,
//                        otherwise false.
//
// WARNINGS.
//      None.
//

BOOLEAN
EFIAPI
ShowHotkeyMessages (VOID)
{
  return ((BOOLEAN)ConfigDisplayHotkeys && mDisplayHotkeysDuringPost);
} // ShowHotkeyMessages

//
// FUNCTION NAME.
//      LegacyBootEnabled - Is Legacy Boot Enabled?
//
// FUNCTIONAL DESCRIPTION.
//      This function answers the policy question regarding legacy boot.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN, TRUE if
//
// WARNINGS.
//      None.
//

BOOLEAN
EFIAPI
LegacyBootEnabled (OUT PBOOLEAN LegacyBeforeUefi OPTIONAL)
{
  if (LegacyBeforeUefi != NULL) {
    *LegacyBeforeUefi = mSystemConfiguration.BootPriority;
    if (mSystemConfiguration.BootPriority) {
      DPRINTF_LO ("BootManager.BootPriority: Legacy boot is the priority.\n");
    } else {
      DPRINTF_LO ("BootManager.BootPriority: UEFI boot is the priority.\n");
    }
  }

  BDS_DEBUG_CODE ({
    if (mSystemConfiguration.LegacyBoot) {
      DPRINTF_CONFIG ("BootManager.LegacyBootEnabled: Legacy boot is enabled.\n");
    } else {
      DPRINTF_CONFIG ("BootManager.LegacyBootEnabled: Legacy boot is disabled.\n");
    }
  });

  return mSystemConfiguration.LegacyBoot;

} // LegacyBootEnabled

//
// FUNCTION NAME.
//      UefiBootEnabled - Is Uefi Boot Enabled?
//
// FUNCTIONAL DESCRIPTION.
//      This function answers the policy question regarding Uefi boot.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN, TRUE if
//
// WARNINGS.
//      None.
//

BOOLEAN
EFIAPI
UefiBootEnabled (VOID)
{
  BDS_DEBUG_CODE ({
    if (mSystemConfiguration.UefiBoot) {
      DPRINTF_CONFIG ("BootManager.UefiBootEnabled: Uefi boot is enabled.\n");
    } else {
      DPRINTF_CONFIG ("BootManager.UefiBootEnabled: Uefi boot is disabled.\n");
    }
  });

  return mSystemConfiguration.UefiBoot;
} // UefiBootEnabled

//
// FUNCTION NAME.
//      QuickBootEnabled - Is Quick Boot Enabled?
//
// FUNCTIONAL DESCRIPTION.
//      This function answers the policy question regarding the quick
//      boot variable setting.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN, TRUE if
//
// WARNINGS.
//      None.
//

BOOLEAN
EFIAPI
QuickBootEnabled (VOID)
{
  BDS_DEBUG_CODE ({
    if (mSystemConfiguration.QuickBoot) {
      DPRINTF_CONFIG ("BootManager.QuickBootEnabled: Quick boot is enabled.\n");
    } else {
      DPRINTF_CONFIG ("BootManager.QuickBootEnabled: Quick boot is disabled.\n");
    }
  });

  return mSystemConfiguration.QuickBoot;
} // QuickBootEnabled


//
// Private (static) routines used by this module.
//

#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK

//
// FUNCTION NAME.
//      InitializeBootOrder - Load default BootOrder check.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if RTC error detected and load the default
//      BootOrder.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//
// WARNINGS.
//      None.
//

static
VOID
InitializeBootOrder (VOID)
{
  SCT_STATUS Status;
  UINTN VariableSize;
  BOOLEAN UseDefault;

#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK_RESTORE_BOOT_OPTION
#else
  PUINT16 VariableValue;
#endif

  DPRINTF_INIT ("\n");

  //
  // Check if it is necessary to use default BootOrder.
  //

  VariableSize = sizeof (BOOLEAN);
  Status = gRT->GetVariable (
                  L"GetUseDefault",
                  &mCommandVariableGuid,
                  NULL,
                  &VariableSize,
                  &UseDefault);

  if (!EFI_ERROR (Status) && UseDefault) {

    DPRINTF_INIT ("  Use default BootOrder\n");

#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK_RESTORE_BOOT_OPTION
    SetEfiGlobalVariable (EFI_BOOT_ORDER_VARIABLE_NAME, 0, 0, NULL);
    mRequiresProjectLoad = TRUE;
#else
    Status = SctLibGetVariable (
               L"BootOrderDefault",
               &gSctBdsServicesProtocolGuid,
               NULL,
               &VariableSize,
               &VariableValue);

    DPRINTF_INIT ("  Get vairable BootOrderDefault result %r\n", Status);
    if (!EFI_ERROR (Status)) {

      Status = SetEfiGlobalVariable (
                 EFI_BOOT_ORDER_VARIABLE_NAME,
                 EFI_VARIABLE_NON_VOLATILE|
                 EFI_VARIABLE_BOOTSERVICE_ACCESS|
                 EFI_VARIABLE_RUNTIME_ACCESS,
                 VariableSize,
                 VariableValue);

      SafeFreePool (VariableValue);
    }
#endif
  }
} // InitializeBootOrder

#endif

#if OPTION_SUPPORT_TCG
//
// FUNCTION NAME.
//      IsMorBitSet - Is ClearMemory bit set?
//
// FUNCTIONAL DESCRIPTION.
//      This function check the ClearMemory bit value 0 or 1.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN, TRUE if
//
// WARNINGS.
//      None.
//
BOOLEAN
IsMorBitSet (
  VOID
  )
{
  return (BOOLEAN) (mMorControl & MOR_CLEAR_MEMORY_BIT_MASK);
}
#endif //  OPTION_SUPPORT_TCG

