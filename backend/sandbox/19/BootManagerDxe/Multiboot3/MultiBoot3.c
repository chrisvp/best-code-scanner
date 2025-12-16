//
// FILENAME.
//      MultiBoot3.c - SecureCore Technology(TM) MultiBoot III Boot Option protocol.
//
// FUNCTIONAL DESCRIPTION.
//      This driver implements MultiBoot III style boot option grouping and
//      expansion.
//
// NOTICE.
//      Copyright (C) 2009-2024 Phoenix Technologies.  All Rights Reserved.
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

//
// Data shared with other modules *within* this component.
//

PSCT_BDS_SERVICES_PROTOCOL mBdsServicesProtocol;
BopInitialization BopInitTable[] = {
  InitializeBopFixedDiskMb3,
  InitializeBopOpticalDriveMb3,
  InitializeBopRemovableDiskMb3,
  InitializeBopPciLanMb3,
};

//
// Data defined in other modules and used by this module.
//

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
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

EFI_STATUS
EFIAPI
EntryPoint (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  UINTN i;
  UINTN InitTableSize;
  EFI_STATUS Status;                    // local return code.

  DPRINTF_INIT ("  BOP Initialization\n" );

  Status = gBS->LocateProtocol (
                  &gSctBdsServicesProtocolGuid,
                  NULL,
                  (VOID **) &mBdsServicesProtocol
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Initialize BOP.
  //

  InitTableSize = sizeof (BopInitTable) / sizeof (BopInitTable[0]);
  for (i = 0; i < InitTableSize; ++i) {
    Status = BopInitTable[i] (ImageHandle);
    if (EFI_ERROR (Status)) {
      DPRINTF_INIT ("  BOP Init Failed. Index=0x%x, Status=0x%x\n", i, Status);
      return Status;
    }
  }

  DPRINTF_INIT ("  BOP Initialization Completed.\n" );
  return Status;
} // EntryPoint
