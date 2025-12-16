//
// FILENAME.
//      BdsSecureBios.h - SecureCore Technology(TM) The header file for SecureBios feature.
//
// FUNCTIONAL DESCRIPTION.
//      Provides funtions for SecureBios feature.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

//
// Data defined in other modules and used by this module.
//

extern EFI_BOOT_MODE mBootMode;

//
// Private datatypes used by this module are defined here and any static
// items are declared here.
//

#if OPTION_SUPPORT_SECURE_BIOS

//
// FUNCTION NAME.
//      SecureBiosFreeze - Lock SPI ROM regions and freeze SPI controller settings.
//
// FUNCTIONAL DESCRIPTION.
//      Locate SCT_SECURE_BIOS_PROTOCOL, protect all SPI regions defined in
//      CONFIG_SECURE_BIOS_LOCKED_REGION_TABLE. And freeze the register settings.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//                        EFI_SUCCESS.
//

EFI_STATUS
EFIAPI
SecureBiosFreeze (VOID)
{
  EFI_STATUS Status = EFI_SUCCESS;
  SCT_SECURE_BIOS_PROTOCOL *SecureBios = NULL;
  UINT32 Index;
  SECURE_BIOS_LOCK_REGION SecureBiosLockedRegion [] = {CONFIG_SECURE_BIOS_LOCKED_REGION_TABLE};

  //
  // Locate SCT_SECURE_BIOS_PROTOCOL.
  //

  Status = gBS->LocateProtocol (
                  &gSctSecureBiosProtocolGuid,
                  NULL,
                  (VOID **) &SecureBios);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Failed to locate SCT_SECURE_BIOS_PROTOCOL. Status = %r.\n", Status);
    //SctLibErrorCodeFunction (0xdead);
    return Status;
  }

  //
  // Protect SPI regions if CONFIG_SYSTEM_SECURE_BIOS_PROTECT_PHASE is 2.
  //

  if ((CONFIG_SYSTEM_SECURE_BIOS_PROTECT_PHASE == 2) && (mBootMode != BOOT_ON_FLASH_UPDATE) && (mBootMode != BOOT_IN_RECOVERY_MODE)) {
    for (Index = 0; Index < sizeof (SecureBiosLockedRegion) / sizeof (SECURE_BIOS_LOCK_REGION); Index++) {

      Status = SecureBios->Protect (
                             SecureBiosLockedRegion[Index].BeginFdlaOffset,
                             SecureBiosLockedRegion[Index].RegionSize,
                             SecureBiosLockedRegion[Index].Action
                             );

      DPRINTF_BM ("SCT_SECURE_BIOS_PROTOCOL.Protect (%x, %x, %x), Status = %r\n",
        SecureBiosLockedRegion[Index].BeginFdlaOffset,
        SecureBiosLockedRegion[Index].RegionSize,
        SecureBiosLockedRegion[Index].Action,
        Status
        );

      if (EFI_ERROR(Status)) {
        if (Status == EFI_ABORTED) {

          //
          // If Protect() returns EFI_ABORTED means the regions are already
          // locked, continue to boot.
          //

          DPRINTF_BM ("SCT_SECURE_BIOS_PROTOCOL.Protect() was aborted, continue.\n");
        } else {
          DPRINTF_BM ("SCT_SECURE_BIOS_PROTOCOL.Protect() failed!\n");
          //SctLibErrorCodeFunction (0xdead);
        }
      } else {
        DPRINTF_BM ("SCT_SECURE_BIOS_PROTOCOL.Protect() succeeded!\n");
      }
    }
  }

  //
  // Freeze SPI controllers to avoid unlocking. Freeze the system if failed.
  //

  Status = SecureBios->Freeze ();
  if (EFI_ERROR(Status)) {
    DPRINTF_BM ("SCT_SECURE_BIOS_PROTOCOL.Freeze() failed. Status = %r.\n", Status);
    //SctLibErrorCodeFunction (0xdead);
  } else {
    DPRINTF_BM ("SCT_SECURE_BIOS_PROTOCOL.Freeze() succeeded.\n");
  }

  return Status;

} // SecureBiosFreeze
#endif // OPTION_SUPPORT_SECURE_BIOS
