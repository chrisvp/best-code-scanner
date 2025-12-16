//
// FILENAME.
//      BdsBiosSelfHealing.c - SecureCore Technology(TM) BIOS Self Healing in the Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      Provides BIOS Self Healing support funtions for BDS phase.
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


#if OPTION_SUPPORT_BIOS_SELF_HEALING

//
// FUNCTION NAME.
//      ProcessBiosSelfHealing - Process the BIOS Self Healing function.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called when the ReadyToBoot event occurs.
//
//      This function process the BIOS Self Healing backup or restore function.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      None.
//

VOID
ProcessBiosSelfHealing (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_STATUS Status;
  UINTN InfoSize;
  UINT8 *InfoBuffer;
  SCT_BIOS_SELF_HEALING_PROTOCOL *BiosSelfHealingProtocol;
  SCT_BIOS_SELF_HEALING_CUSTOM_PROTOCOL *BiosSelfHealingCustomProtocol;
  SCT_BDS_MILESTONE_BIOS_SELF_HEALING_DATA *BiosSelfHealingData;
  VOID *HobList;
  EFI_PEI_HOB_POINTERS Hob;
  INT32 StoMode;
  INT32 GopMode;
  BOOLEAN BackupInfoDifferent;
  BOOLEAN BackupRegionDifferent;
  EFI_HANDLE *HandleBuffer;
  UINTN NumberOfHandles;
  UINTN Index;

  Status = EFI_SUCCESS;
  InfoSize = 0;
  InfoBuffer = NULL;
  BackupInfoDifferent = FALSE;
  BackupRegionDifferent = FALSE;
  BiosSelfHealingProtocol = NULL;
  BiosSelfHealingCustomProtocol = NULL;
  NumberOfHandles = 0;

  if ((MilestoneData == NULL) || (MilestoneDataSize == 0)) {
    DPRINTF_BM ("ProcessBiosSelfHealing return Invalid Parameters\n");
    return;
  }

  BiosSelfHealingData = (SCT_BDS_MILESTONE_BIOS_SELF_HEALING_DATA *)MilestoneData;
  DPRINTF_BM ("BIOS Self-Healing Mode %d.\n", BiosSelfHealingData->BiosSelfHealingMode);
  DPRINTF_BM ("BIOS Self-Healing Attributes %d.\n", BiosSelfHealingData->Attributes);

  //
  // Locate the BiosSelfHealingCustom protocol.
  //

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctBiosSelfHealingCustomProtocolGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer
                  );
  if (EFI_ERROR(Status)) {
    DPRINTF_BM ("Locate BiosSelfHealingCustom protocol - %r\n", Status);
  }

  if (BiosSelfHealingData->BiosSelfHealingMode == BIOS_SELF_HEALING_MODE_NORMAL) {
    if (NumberOfHandles != 0) {
      for (Index = 0; Index < NumberOfHandles; Index++) {
        Status = gBS->HandleProtocol (
                        HandleBuffer [Index],
                        &gSctBiosSelfHealingCustomProtocolGuid,
                        (VOID **) &BiosSelfHealingCustomProtocol);
        if (EFI_ERROR (Status) || BiosSelfHealingCustomProtocol == NULL) {
          continue;
        }

        //
        // Verify signature of Esp backup region.
        //

        Status = BiosSelfHealingCustomProtocol->Verify ();
        if (Status == EFI_NO_MEDIA) {
          DPRINTF_ERROR ("ESP not found. Do not perform BSH ESP backup.\n");
          return;
        } else if (EFI_ERROR (Status)) {
          DPRINTF_ERROR ("Verify %x backup signature failed, status %r.\n", HandleBuffer [Index], Status);
        } else {
          //DPRINTF_BM ("Verify %x backup signature SUCCESS.\n", HandleBuffer [Index]);

          //
          // Continues to check Esp backup info and content between Current Bios and Esp backup region.
          //

          Status = BiosSelfHealingCustomProtocol->CheckBackup (&BackupInfoDifferent, &BackupRegionDifferent);
          if (Status == EFI_NO_MEDIA) {
            DPRINTF_ERROR ("ESP not found. Do not perform BSH ESP backup.\n");
            return;
          }

          //
          // Perform Esp backup process directly if backup info, region or signature is different.
          //

          if ((BackupInfoDifferent == FALSE) && (BackupRegionDifferent == FALSE)) {
            //DPRINTF_BM ("Verify signature pass and Backup Region are the same.\n");
            return;
          }
        }

        DPRINTF_BM ("Backup region incorrect. Start to perform BIOS Self Healing Esp backup.\n");

        //
        // Set screen resolution.
        //

        SetVideoToProperRes (
          &StoMode, 
          &GopMode, 
          CONFIG_SYSTEM_BIOS_SELF_HEALING_RESOLUTION_X, 
          CONFIG_SYSTEM_BIOS_SELF_HEALING_RESOLUTION_Y);

        //
        // Perform BiosSelfHealingCustomProtocol->Backup directly.
        //

        Status = BiosSelfHealingCustomProtocol->Backup (InfoSize, InfoBuffer);
        if (EFI_ERROR (Status)) {
          DPRINTF_ERROR ("Call BIOS Self Healing Esp backup failed, status %r.\n", Status);
        }

        //
        // Restore screen resolution.
        //

        RestoreVideoMode (StoMode, GopMode);
      }

      if (Index == NumberOfHandles) {
        DPRINTF_BM ("BiosSelfHealingCustomProtocol not supported.\n");
      }
    }

    //
    // No matter backup was processed or not, continue to boot.
    //

    return;
  }

  //
  // Skip performing Bios Self Healing Recovery process due to SelfHealing.fd is not installed.
  //

  if ((BiosSelfHealingData->BiosSelfHealingMode == BIOS_SELF_HEALING_MODE_RECOVERY) &&
      ((BiosSelfHealingData->Attributes & BIOS_SELF_HEALING_ATTRIBUTES_RECOVERY_SKIP) != BIOS_SELF_HEALING_ATTRIBUTES_RECOVERY_SKIP)) {
    DPRINTF_ERROR ("BiosSelfHealing backup regions are not loaded. Skip BSH recovery procedure here.\n");
    return;
  }

  //
  // Locate the BiosSelfHealing protocol.
  //

  Status = gBS->LocateProtocol (
                  &gSctBiosSelfHealingProtocolGuid,
                  NULL,
                  (VOID **) &BiosSelfHealingProtocol);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Locate gSctBiosSelfHealingProtocolGuid failed, status %r.\n");
    return;
  }

  SetVideoToProperRes (&StoMode, &GopMode, CONFIG_SYSTEM_BIOS_SELF_HEALING_RESOLUTION_X, CONFIG_SYSTEM_BIOS_SELF_HEALING_RESOLUTION_Y);

  //
  // Boot mode should be changed by the BIOS Self Healing PEI driver during the PEI phase to
  // prevent the SecureBios lock down the system, so the BIOS Self Healing driver could perform
  // the backup or restore.
  //

  if (BiosSelfHealingData->BiosSelfHealingMode == BIOS_SELF_HEALING_MODE_BACKUP) {

    //
    // Try to get the hob which is created by platform driver and pass-in the backup information
    // to the backup area.
    //

    Status = EfiGetSystemConfigurationTable (&gEfiHobListGuid, &HobList);
    if (HobList == NULL) {
      DPRINTF_BM ("  Couldn't get the hob list, %r.\n", Status);
      return;
    } else {

      Hob.Raw = GetNextGuidHob (&gSctBiosSelfHealingSignatureGuid, HobList);
      if ((Hob.Raw == NULL) || ((InfoBuffer = GET_GUID_HOB_DATA (Hob.Guid)) == NULL)) {
        DPRINTF_BM ("  Get the BIOS Self Healing guid hob not found");
        return;
      }

      InfoSize = GET_GUID_HOB_DATA_SIZE (Hob.Guid);
    }

    //
    // After BIOS Self Healing backup, it will always reset the platform.
    //

    Status = BiosSelfHealingProtocol->Backup (InfoSize, InfoBuffer);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("Call BIOS Self Healing backup failed, status %r.\n", Status);
    }

  } else if (BiosSelfHealingData->BiosSelfHealingMode == BIOS_SELF_HEALING_MODE_RECOVERY) {

    //
    // Call ConnectAllHandles to ensure that all the device has been connected
    // to make sure other protocols such as blkio has been produced.
    //

    //Status = ConnectAllHandles ();

    //
    // If the boot mode is under recovery mode, then always restore the BIOS
    // then reset the platform.
    //

    Status = BiosSelfHealingProtocol->Restore ();
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("Call BIOS Self Healing Restore failed, status %r.\n");
    }
  }

  if (InfoBuffer != NULL) {
    SafeFreePool (InfoBuffer);
    InfoBuffer = NULL;
  }

  if (HandleBuffer != NULL) {
    FreePool(HandleBuffer);
  }

  //
  // Reset the system.
  //

  DPRINTF_BM ("ResetSystem...\n");

  gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0 , NULL);
  CpuDeadLoop ();

} // ProcessBiosSelfHealing
#endif // OPTION_SUPPORT_BIOS_SELF_HEALING
