//
// FILENAME.
//      BdsBiosDataSelfHealing.c - SecureCore Technology(TM) BIOS data Self Healing in the Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      Provides BIOS data Self Healing support functions for BDS phase.
//
// NOTICE.
//      Copyright (C) 2019-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

//
// Data defined in other modules and used by this module.
//

//
// Prototypes for functions in other modules that are a part of this component.
//

//
// Private datatypes used by this module are defined here and any static
// items are declared here.
//

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

//
// Public API functions implemented by this component.
//

#if OPTION_SUPPORT_BIOS_DATA_SELF_HEALING && OPTION_SYSTEM_BIOS_DATA_SELF_HEALING_BDS_BACKUP

//
// FUNCTION NAME.
//      ProcessBiosDataBackup - Process the BIOS Data backup function.
//
// FUNCTIONAL DESCRIPTION.
//      This function process the BIOS Data Self Healing backup function.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
ProcessBiosDataBackup (VOID)
{
  EFI_STATUS Status;
  SCT_SECURE_VARIABLE_STORAGE_PROTOCOL *SctSecureVarStorageProtocol;
  EFI_PHYSICAL_ADDRESS NvStorageBase;
  UINT8 *NvStorageData;
  UINT64 NvStorageSize;
  EFI_PHYSICAL_ADDRESS VariableStoreBase;
  UINT64 VariableStoreLength;
  EFI_FIRMWARE_VOLUME_HEADER *FvHeader;

  SctSecureVarStorageProtocol = NULL;

  Status = GetVariableFlashNvStorageInfo (&NvStorageBase, &NvStorageSize);
  ASSERT_EFI_ERROR (Status);

  //
  // Locate Sct Secure Variable Storage protocol
  //

  Status = gBS->LocateProtocol (
                  &gSctSecureVariableStorageProtocolGuid,
                  NULL,
                  (VOID **) &SctSecureVarStorageProtocol);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Locate Sct secure variable storage protocol return %r\n", Status));
    return;
  }

  if (SctSecureVarStorageProtocol != NULL) {

    NvStorageData = AllocateZeroPool (NvStorageSize);
    if (NvStorageData == NULL) {
      DEBUG ((DEBUG_ERROR, "NvStorageData allocate failed\n"));
      return;
    }

    SetMem (NvStorageData, NvStorageSize, 0xFF);

    //
    // Copy NV storage data to the memory buffer.
    //

    CopyMem (NvStorageData, (UINT8 *) (UINTN) NvStorageBase, NvStorageSize);

    FvHeader = (EFI_FIRMWARE_VOLUME_HEADER *) NvStorageData;

    VariableStoreBase = (UINTN) FvHeader + FvHeader->HeaderLength;
    VariableStoreLength = NvStorageSize - FvHeader->HeaderLength;

    DEBUG ((DEBUG_ERROR, "Call SctSecureVarStorageProtocol->Backup from BDS\n"));
    DEBUG ((DEBUG_ERROR, "  VariableStoreLength = 0x%x\n", VariableStoreLength));
    Status = SctSecureVarStorageProtocol->Backup ((VOID *)VariableStoreBase, VariableStoreLength);
    DEBUG ((DEBUG_ERROR,"Call SctSecureVarStorageProtocol->Backup return %r\n", Status));
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR,"Call SctSecureVarStorageProtocol->Backup return %r\n", Status));
    }

    //
    // Free the allocated pool.
    //

    if (NvStorageData != NULL) {
      FreePool (NvStorageData);
      NvStorageData = NULL;
    }
  }
} // ProcessBiosDataBackup

#endif // OPTION_SUPPORT_BIOS_DATA_SELF_HEALING && OPTION_SYSTEM_BIOS_DATA_SELF_HEALING_BDS_BACKUP
