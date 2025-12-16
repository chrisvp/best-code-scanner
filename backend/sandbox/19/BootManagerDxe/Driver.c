//
// FILENAME.
//      Driver.c - SecureCore Technology(TM) System Boot Manager Driver Initialization.
//
// FUNCTIONAL DESCRIPTION.
//      This module implements the initialization and protocol registration
//      and dispatching associated with the System Boot Manager.
//
//      The protocol provided is EFI_BDS_ARCH_PROTOCOL, an architectural
//      protocol that provides an entry point that DxeMain will call when
//      forward progress is no longer being made through dispatching.
//
//      This driver is not an "EFI Driver Model" driver; meaning that it
//      does not have Supported(), Start(), and Stop() functions.  Once
//      located, this driver's request types may be used immediately.
//
//      This module (Driver.c) implements the entry point called by the
//      EFI run-time library when the system loads this driver during the
//      DXE phase.  The main routine gets control and registers its protocol,
//      then exits, leaving itself in memory so that it can serve requests.
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

//
// Prototypes for functions in other modules that are a part of this component.
//

#if OPTION_SYSTEM_BOOT_MANAGER_DMA_GUARD
extern
EFI_STATUS
EFIAPI
HookConnectController (VOID);
#endif // OPTION_SYSTEM_BOOT_MANAGER_DMA_GUARD

#if (CONFIG_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_PHASE > 0)
VOID BmeOverrideRegisterHandler (VOID);
#endif

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION
extern
SCT_STATUS
InitializeDebug (VOID);
#endif                                  // (OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION)

extern
SCT_STATUS
EFIAPI
InitializeBootManager (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  );

extern
SCT_STATUS
EFIAPI
InitializeConsole (VOID);

extern
SCT_STATUS
EFIAPI
InitializeVariable (VOID);

//
// FUNCTION NAME.
//      BdsEntry - Transfer control from the DXE Foundation to the boot device.
//
// FUNCTIONAL DESCRIPTION.
//      Performs Boot Device Selection (BDS) and transfers control from the DXE
//      Foundation to the selected boot device.
//      The implementation of the boot policy must follow the rules outlined in
//      the Boot Manager chapter of the UEFI specification.
//      This function uses policy data from the platform to determine what
//      operating system or system utility should be loaded and invoked.
//      This function call also optionally uses the user's input to determine
//      the operating system or system utility to be loaded and invoked.
//      When the DXE Foundation has dispatched all the drivers on the dispatch
//      queue, this function is called.
//      This function will attempt to connect the boot devices required to load
//      and invoke the selected operating system or system utility. During this
//      process, additional firmware volumes may be discovered that may contain
//      addition DXE drivers that can be dispatched by the DXE Foundation.
//      If a boot device cannot be fully connected, this function calls the DXE
//      Service Dispatch() to allow the DXE drivers from any newly discovered
//      firmware volumes to be dispatched.
//      Then the boot device connection can be attempted again.
//      If the same boot device connection operation fails twice in a row,
//      then that boot device has failed, and should be skipped.
//      This function should never return.
//

VOID
EFIAPI
BdsEntry (IN EFI_BDS_ARCH_PROTOCOL *This);

//
// Data shared with other modules *within* this component.
//

DRIVER_OBJECT mBootManager = {
  DRIVER_OBJECT_SIGNATURE,
  NULL,                                 // handle.
  {BdsEntry}                            // bdsArchProtocol.
};

GLOBAL_REMOVE_IF_UNREFERENCED
EFI_SMM_COMMUNICATE_HEADER *mSmmCommunicateHeader;

//
// Data defined in other modules and used by this module.
//

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      EntryPoint - DXE Driver Entry Point.
//
// FUNCTIONAL DESCRIPTION.
//      This entry point is defined in the INF file, and called by the DXE
//      dispatcher to initialize this driver.
//
//      If this function returns a failing status code, the driver unloads
//      automatically; however, if it returns a non-failing status code, the
//      driver remains in memory and is considered a part of the system.
//
// ENTRY PARAMETERS.
//      ImageHandle     - EFI Image Handle referencing this driver's image.
//      SystemTable     - ptr to the EFI system table.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
EFIAPI
EntryPoint (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  SCT_STATUS Status;                    // local return code.

  //
  // Initialize Connection controller, so we can filter out expansion
  // card slots to prevent DMA from being enabled without explicit
  // permission from the user.
  //

#if OPTION_SYSTEM_BOOT_MANAGER_DMA_GUARD
  HookConnectController ();
#endif // OPTION_SYSTEM_BOOT_MANAGER_DMA_GUARD

  //
  // Give BME Override code a chance to register appropriate events.
  //

#if (CONFIG_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_PHASE > 0)
  BmeOverrideRegisterHandler ();
#endif

  //
  // Initialize the other modules in this component.
  //

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_INSTRUMENTATION
    Status = InitializeDebug ();
    if (EFI_ERROR (Status)) {
      return Status;
    }
#endif

  Status = InitializeBootManager (ImageHandle, SystemTable);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = InitializeConsole ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = InitializeVariable ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

#if (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)
  mSmmCommunicateHeader = AllocateRuntimeZeroPool (sizeof (EFI_SMM_COMMUNICATE_HEADER));
  if (mSmmCommunicateHeader == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
#endif //(OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)

  Status = SctBdsArchPreSetting();
  if (EFI_ERROR (Status)) {
    DPRINTF_INIT ("Bds Arch PreSetting, Status=%r.\n", Status);
    ASSERT_EFI_ERROR (Status);
  }

  //
  // Publish the BDS Architectural protocol on this image's handle.
  //

  mBootManager.Handle = ImageHandle;
  Status = gBS->InstallProtocolInterface (
                  &mBootManager.Handle,
                  &gEfiBdsArchProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mBootManager.BdsArchProtocol);
  if (EFI_ERROR (Status)) {
    DPRINTF_INIT ("BootManager.EntryPoint: InstallprotocolInterface failed, Status=%r.\n", Status);
    ASSERT_EFI_ERROR (Status);
  } else {
    DPRINTF_INIT ("BootManager installed on handle 0x%x.\n", mBootManager.Handle);
  }

  //
  // Initialization is complete. Return successfully to keep image in memory.
  //

  return Status;
} // EntryPoint

//
// Private (static) routines used by this component.
//
