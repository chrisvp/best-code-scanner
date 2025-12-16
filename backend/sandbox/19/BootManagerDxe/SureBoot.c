//
// FILENAME.
//      SureBoot.c - SecureCore Technology(TM) The header file for SureBoot feature.
//
// FUNCTIONAL DESCRIPTION.
//      Provides functions for SureBoot feature.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

#if OPTION_SUPPORT_SURE_BOOT

//
// Private datatypes used by this module are defined here and any static
// items are declared here.
//

EFI_GUID mSureBootVariableGuid = CONFIG_SURE_BOOT_VARIABLE_GUID;

//
// FUNCTION NAME.
//      ResetSureBootStatus - Reset the SureBootStatus.
//
// FUNCTIONAL DESCRIPTION.
//      Reset the SureBootStatus.
//
// ENTRY PARAMETERS.
//      Data        - not used.
//      DataSize    - not used.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
ResetSureBootStatus (VOID* Data, UINT32 DataSize)
{
  return EFI_SUCCESS;
} // ResetSureBootStatus

//
// FUNCTION NAME.
//      DisableSureBootTimerReset - Disable Sure Boot timer reset.
//
// FUNCTIONAL DESCRIPTION.
//      Set volatile variable so Sure Boot timer does not reset system.
//
// ENTRY PARAMETERS.
//      None
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
DisableSureBootTimerReset (VOID)
{
  EFI_STATUS Status;
  BOOLEAN Disable = TRUE;

  Status = gRT->SetVariable (
                  L"SureBootTimer",
                  &mSureBootVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  sizeof (Disable),
                  &Disable);

  return Status;
}
#endif