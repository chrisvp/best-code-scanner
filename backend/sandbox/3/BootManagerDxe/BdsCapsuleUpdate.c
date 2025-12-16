//
// FILENAME.
//      BdsCapsuleUpdate.c - SecureCore Technology(TM) Capsule Update Supporting in the Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      Provides Capsule Update functions for BDS phase.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

#if OPTION_SUPPORT_CAPSULE_UPDATE

//
// Data defined in other modules and used by this module.
//

extern EFI_BOOT_MODE mBootMode;
extern BOOLEAN mCapsuleEspDelivery;

extern
VOID
EFIAPI
UnlockAllHdd (VOID);

extern
SCT_STATUS
EFIAPI
ConnectAllHandles (VOID);

extern
SCT_STATUS
EFIAPI
ConnectDevices (IN PBOOT_MANAGER_CONNECTION_DEVICE DeviceList);

//
// Private datatypes used by this module are defined here and any static
// items are declared here.
//

#define OPTION_SYSTEM_CAPSULE_UPDATE_PATCH_ACPI_SLEEP_TYPE 1

#if OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS
STATIC BOOLEAN mCheckPowerStatus = FALSE;
STATIC CHAR16 mCheckPowerStatusErrorStr[] = CONFIG_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_ERROR_MESSAGE;
#endif

STATIC BOOT_MANAGER_CONNECTION_DEVICE mCapsuleUpdateHddUnlockConnectList [] = { CONFIG_CapsuleUpdateHddUnlockConnectList };

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

//
// Public API functions implemented by this component.
//

#if OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS

//
// FUNCTION NAME.
//      TdkServiceGetPowerStatus - Handles requests to TDK_SERVICE_GET_POWER_STATUS.
//
// FUNCTIONAL DESCRIPTION.
//      This function handles requests to TDK_SERVICE_GET_POWER_STATUS.
//      It designed to as one SCT milestone task.
//
// ENTRY PARAMETERS.
//      SctFlashSharedMemory - Address of SCT Flash Shared Memory.
//      DataSize        - Not used.
//
// EXIT PARAMETERS.
//      EFI_SUCCESS     - Operation successful, allowing after phase of OEM hook
//                        to be executed.
//

EFI_STATUS
TdkServiceGetPowerStatus (VOID* Data, UINT32 DataSize)
{
  TDK_SERVICE_GET_POWER_STATUS_PARAMETER *GetPowerStatusParameter;

  GetPowerStatusParameter = (TDK_SERVICE_GET_POWER_STATUS_PARAMETER *)Data;
  GetPowerStatusParameter->Header.Size = sizeof (TDK_SERVICE_GET_POWER_STATUS_PARAMETER);
  GetPowerStatusParameter->Header.ReturnStatus = EFI_UNSUPPORTED;

  return EFI_SUCCESS;
} // TdkServiceGetPowerStatus

//
// FUNCTION NAME.
//      CheckPowerStatus - Check power status.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check AC status and battery capacity before system performs
//      capsule update.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
CheckPowerStatus (VOID)
{
  TDK_SERVICE_GET_POWER_STATUS_PARAMETER GetPowerStatusParameter;

  ZeroMem (&GetPowerStatusParameter, sizeof (TDK_SERVICE_GET_POWER_STATUS_PARAMETER));

  GetPowerStatusParameter.Header.TdkServiceFunction = TDK_SERVICE_GET_POWER_STATUS;
  GetPowerStatusParameter.Header.Size = sizeof (TDK_SERVICE_GET_POWER_STATUS_PARAMETER);
  CopyMem (&GetPowerStatusParameter.Header.FlashIdentificationId, &gSctFlashIdentificationGuid, sizeof (EFI_GUID));

  SCT_MILESTONE_TASK (TDK_SERVICE_GET_POWER_STATUS_TASK_ID, TdkServiceGetPowerStatus, &GetPowerStatusParameter, 0);

  if (!EFI_ERROR (GetPowerStatusParameter.Header.ReturnStatus)) {
    if (GetPowerStatusParameter.AcStatus == 0) {
      if (GetPowerStatusParameter.BatteryPercentage < CONFIG_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_BATTERY_PERCENTAGE) {
        return EFI_UNSUPPORTED;
      }
    }
    return EFI_SUCCESS;
  }

  return EFI_UNSUPPORTED;
}

#endif

#if OPTION_SUPPORT_WUFU

//
// FUNCTION NAME.
//      SetTdkStatus - Set TDK status variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function will set TDK status variable for system firmware.
//
// ENTRY PARAMETERS.
//      ErrorLevel - The error status.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
SetTdkStatus (
  IN UINT8 ErrorLevel
  )
{
  EFI_STATUS Status;
  UINTN VarTdkStatusSize;
  FLASH_STATUS_INFO TdkStatus;
  FLASH_STATUS_EXTEND_INFO TdkStatusEx;
  EFI_GUID VarTdkStatusGuid = SCT_VARIABLE_TDK_STATUS_GUID;

  //
  // Get the TDK status, and write back to the ESRT table variable.
  //

  VarTdkStatusSize = sizeof (FLASH_STATUS_INFO);

  Status = gRT->GetVariable (
                  VAR_TDK_STATUS_NAME,
                  &VarTdkStatusGuid,
                  NULL,
                  &VarTdkStatusSize,
                  &TdkStatus);
  if (EFI_ERROR (Status)) {

    DPRINTF_BM ("TdkStatus variable could not be found.\n");

    //
    // Create a new variable if it does not exist and write to indicate the ESRT that it
    // is verify failed with BIOS firmware.
    //

    TdkStatus.FlashDate = 0;
    TdkStatus.FlashTime = 0;
    TdkStatus.BuildDate = 0;
    TdkStatus.BuildTime = 0;
    TdkStatus.Status = TDK_SUCCESS;

    VarTdkStatusSize = sizeof (FLASH_STATUS_INFO);
  }

  TdkStatus.ErrorLevel = ErrorLevel;

  //
  // Write the TdkStatus variable to indicate the ESRT that it
  // is verify failed.
  //

  Status = gRT->SetVariable (
                  VAR_TDK_STATUS_NAME,
                  &VarTdkStatusGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  VarTdkStatusSize,
                  &TdkStatus);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Set TdkStatus status failed, status %r\n", Status);
  }

  //
  // Get the TDK status, and write back to the ESRT table variable.
  //

  VarTdkStatusSize = sizeof (FLASH_STATUS_EXTEND_INFO);

  Status = gRT->GetVariable (
                  VAR_TDK_STATUS_EXTEND_NAME,
                  &VarTdkStatusGuid,
                  NULL,
                  &VarTdkStatusSize,
                  &TdkStatusEx);
  if (EFI_ERROR (Status)) {

    DPRINTF_BM ("TdkStatus variable could not be found.\n");

    //
    // Create a new variable if it does not exist and write to indicate the ESRT that it
    // is verify failed with BIOS firmware.
    //

    ZeroMem (&TdkStatusEx, sizeof (TdkStatusEx));
    TdkStatusEx.Status = TDK_SUCCESS;

    VarTdkStatusSize = sizeof (FLASH_STATUS_EXTEND_INFO);
  }

  TdkStatusEx.ErrorLevel = ErrorLevel;

  //
  // Write the TdkStatus variable to indicate the ESRT that it
  // is verify failed.
  //

  Status = gRT->SetVariable (
                  VAR_TDK_STATUS_EXTEND_NAME,
                  &VarTdkStatusGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                  VarTdkStatusSize,
                  &TdkStatusEx);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Set TdkStatus status failed, status %r\n", Status);
  }

  return Status;
}

//
// FUNCTION NAME.
//      SetLdfStatus - Set LDF status variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function will set LDF variable with the status.
//
// ENTRY PARAMETERS.
//      CapsuleGuid       - The device GUID to get and set the variable.
//      LastAttemptStatus - The error status.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
SetLdfStatus (
  IN EFI_GUID *CapsuleGuid,
  IN UINT32 LastAttemptStatus
  )
{
  EFI_STATUS Status;
  UINT32 VarDevStatusAttr;
  UINTN VarDevStatusSize;
  DEVICE_FIRMWARE_FLASH_STATUS_INFO *VarDevInfo;

  //
  // If it is other device capsule guid, then try to find the ESRT entry from the
  // ESRT variable and then add the verify failed status back to the ESRT entry.
  //

  VarDevStatusSize = 0;
  VarDevInfo = NULL;

  Status = gRT->GetVariable (
                  VAR_LDF_STATUS_NAME,
                  CapsuleGuid,
                  &VarDevStatusAttr,
                  &VarDevStatusSize,
                  VarDevInfo);

  if (Status == EFI_NOT_FOUND) {
    DPRINTF_BM ("Device firmware status variable is not exist, status %r\n", Status);

    //
    // In case the device's PLDFS variable could not be found, create a new PLDFS
    // and report the verify failed status.
    //

    VarDevStatusSize = sizeof (DEVICE_FIRMWARE_FLASH_STATUS_INFO);
    VarDevInfo = AllocateZeroPool (sizeof (DEVICE_FIRMWARE_FLASH_STATUS_INFO));
    if (VarDevInfo == NULL) {
      DPRINTF_BM ("Allocate buffer for device firmware status variable, status %r\n", Status);
      return EFI_OUT_OF_RESOURCES;
    }

    CopyMem (&VarDevInfo->FirmwareClass, CapsuleGuid, sizeof (EFI_GUID));
    VarDevInfo->FirmwareType = 2; // Device firmware
    VarDevInfo->CurrentFirmwareVersion= 0;
    VarDevInfo->LowestSupportedFirmwareVersion = 0;
    VarDevInfo->LastAttemptVersion = 0;

    VarDevStatusAttr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;

  } else if (Status == EFI_BUFFER_TOO_SMALL) {

    VarDevInfo = AllocateZeroPool (VarDevStatusSize);
    if (VarDevInfo == NULL) {
      DPRINTF_BM ("Allocate buffer for device firmware status variable, status %r\n", Status);
      return EFI_OUT_OF_RESOURCES;
    }

    Status = gRT->GetVariable (
                    VAR_LDF_STATUS_NAME,
                    CapsuleGuid,
                    &VarDevStatusAttr,
                    &VarDevStatusSize,
                    VarDevInfo);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("Get device firmware status failed, status %r\n", Status);
      FreePool (VarDevInfo);
      return Status;
    }

  } else {
    DPRINTF_BM ("Get device firmware status failed, status %r\n", Status);
  }

  if (Status == EFI_NOT_FOUND || Status == EFI_SUCCESS) {
    VarDevInfo->LastAttemptStatus = LastAttemptStatus;

    Status = gRT->SetVariable (
                    VAR_LDF_STATUS_NAME,
                    CapsuleGuid,
                    VarDevStatusAttr,
                    VarDevStatusSize,
                    VarDevInfo);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("Set device firmware status failed, status %r\n", Status);
    }

    FreePool (VarDevInfo);
  }

  return Status;
}
#endif // OPTION_SUPPORT_WUFU

//
// FUNCTION NAME.
//      UpdateCapsuleFromHob - Update capsule file from memory Hob.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to get the capsule file from memory HOB.
//      The CV type hob is usually build from the PEI phase.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
UpdateCapsuleFromHob (VOID)
{
  EFI_STATUS Status;
  VOID *HobList;
  EFI_PEI_HOB_POINTERS Hob;
  EFI_CAPSULE_HEADER *CapsuleHeader;
  BOOLEAN FoundCapsuleHob;    SUPPRESS_WARNING_IF_UNUSED(FoundCapsuleHob);
  SCT_SECURE_FLASH_AUTHENTICATION_PROTOCOL *SecureFlashAuth = NULL;
  BOOLEAN IsFmpCap = FALSE;

  //
  // Local variables for ACPI status change from S3 to S5.
  // In some case, the ACPI value need this patch for the ACPI status to change for
  // S3 capsule update to perform successfully.
  //

#if OPTION_SYSTEM_CAPSULE_UPDATE_PATCH_ACPI_SLEEP_TYPE

  EFI_ACPI_SDT_PROTOCOL *AcpiSdt = NULL;
  EFI_CPU_IO2_PROTOCOL *CpuIo2 = NULL;
  EFI_ACPI_SDT_HEADER *Table;
  EFI_ACPI_TABLE_VERSION Version;
  INTN Index = 0;
  UINTN Handle;
  UINT8 *CurrPtr;
  UINT8 *DsdtPointer;
  UINT32 AcpiPm1aCntBlk = 0;
  UINT8 S3String [5] = {0x08, 0x5F, 0x53, 0x33, 0x5F}; //ASL name opcode 0x08 + "_S3_".
  UINT8 S5String [5] = {0x08, 0x5F, 0x53, 0x35, 0x5F}; //ASL name opcode 0x08 + "_S5_".
  UINT8 S3SleepType = 0;
  UINT8 S5SleepType = 0;
  BOOLEAN foundFadt = FALSE;
  BOOLEAN foundDsdt = FALSE;
  UINT16 Data16 = 0;
#endif // OPTION_SYSTEM_CAPSULE_UPDATE_PATCH_ACPI_SLEEP_TYPE

  Status = EFI_SUCCESS;
  CapsuleHeader = NULL;
  FoundCapsuleHob = FALSE;

  //
  // Get the Hob List.  Check if the capsule HOB is from the memory.
  //

  EfiGetSystemConfigurationTable (&gEfiHobListGuid, &HobList);

  //
  // Parse the HOB list, stop if end of list reached or EFI_HOB_TYPE_UEFI_CAPSULE
  // HOB type found.
  //

  Hob.Raw = (UINT8*)HobList;
  while (!END_OF_HOB_LIST (Hob) ) {

    //
    // Capsule Hob has been found.
    //

    if (Hob.Header->HobType == EFI_HOB_TYPE_UEFI_CAPSULE) {

      DPRINTF_BM ("FoundCapsuleHob\n");
      FoundCapsuleHob = TRUE;

#if OPTION_SYSTEM_CAPSULE_UPDATE_PATCH_ACPI_SLEEP_TYPE

      //
      // If the boot mode is BOOT_ON_FLASH_UPDATE, then change the acpi value
      // from S3 to S5.  For some platform, when change the S5 to S3 while resetting
      // after flash is done, chipset might mistake that this is still in the S3 resume
      // mode during next boot and cause some silicon driver malfunction because it will
      // still looks into the SLP_TYP states.
      //

      if (mBootMode == BOOT_ON_FLASH_UPDATE) {

        //
        // Change the SLP_TYP from S3 to S5 in the ACPI table
        // to avoid the problem of some platforms might mistake
        // to set the wrong boot mode during the next boot in
        // the PEI phase.
        //

        Status = gBS->LocateProtocol (
                        &gEfiAcpiSdtProtocolGuid,
                        NULL,
                        (VOID **) &AcpiSdt);

        if (!EFI_ERROR (Status)) {

          //
          // Get the PM1A Control Register from ACPI FACP table.
          // And get the S3, S5 sleep type value from DSDT table.
          //

          while (TRUE) {
            Status = AcpiSdt->GetAcpiTable (Index, &Table, &Version, &Handle);

            if (Status == EFI_NOT_FOUND) {
              break;
            }

            if (Table->Signature == EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE) {

              //
              // Get the ACPI Pm1aCntBlk from the
              // EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE.
              //

              AcpiPm1aCntBlk = ((EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE*)Table)->Pm1aCntBlk;

              foundFadt = TRUE;
            }

            if (Table->Signature == EFI_ACPI_3_0_DIFFERENTIATED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) {

              //
              // Get the S3 sleep type from the ACPI DSDT table.
              //

              CurrPtr = (UINT8*) Table;

              //
              // Loop through the ASL looking for _S3 and _S5 value.
              //

              for (DsdtPointer = CurrPtr; DsdtPointer <= (CurrPtr + ((EFI_ACPI_COMMON_HEADER*) CurrPtr)->Length); DsdtPointer++) {

                //
                // Check if this is the signature we are looking for.
                //

                if (!CompareMem (DsdtPointer, S3String, sizeof (S3String))) {

                  //
                  // Skip package opcode, package length and number of
                  // elements byte, and skip 0x0a BytePrefix. So we
                  // skip totally 4 bytes to get the correct S3 value.
                  //

                  DsdtPointer = DsdtPointer + sizeof (S3String) + 4;
                  S3SleepType = *DsdtPointer;
                }

                if (!CompareMem (DsdtPointer, S5String, sizeof (S5String))) {

                  //
                  // Skip package opcode, package length and number of
                  // elements byte, and skip 0x0a BytePrefix. So we
                  // skip totally 4 bytes to get the correct S5 value.
                  //

                  DsdtPointer = DsdtPointer + sizeof (S5String) + 4;
                  S5SleepType = *DsdtPointer;
                }

                if ((S3SleepType != 0) && (S5SleepType != 0)) {
                  foundDsdt = TRUE;
                  break;
                }
              }
            }

            if ((foundFadt == TRUE) && (foundDsdt == TRUE)) {
              break;
            }

            Index++;
          }
        }
      }

      //
      // If the sleep type were found from the ACPI table, then change it.
      //

      if ((foundFadt == TRUE) && (foundDsdt == TRUE)) {
        Status = gBS->LocateProtocol (&gEfiCpuIo2ProtocolGuid, NULL, (VOID **) &CpuIo2);
        if (!EFI_ERROR (Status)) {
          CpuIo2->Io.Read (CpuIo2, EfiCpuIoWidthUint16, AcpiPm1aCntBlk, 1, &Data16);

          //
          // Change the ACPI sleep type to S5 if it is S3.
          //

          if ((UINT8)((Data16 & 0x1c00) >> 10) == S3SleepType) {
            Data16 = (Data16 & 0xc3ff) | (S5SleepType << 10);
            CpuIo2->Io.Write (CpuIo2, EfiCpuIoWidthUint16, AcpiPm1aCntBlk, 1, &Data16);
          }
        }
      }
#endif // OPTION_SYSTEM_CAPSULE_UPDATE_PATCH_ACPI_SLEEP_TYPE

      //
      // Get the capsule header form the Capsule hob and reset the flags to 0.
      // So when it call the RT->UpdateCapsule to process the capsule FV, it does not
      // need to reset the platform again since the reset is already processed
      // with the previous action.
      //

      CapsuleHeader = (EFI_CAPSULE_HEADER *)(UINTN)Hob.Capsule->BaseAddress;
      CapsuleHeader->Flags = 0;

#if (OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS && !OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS_WUFU_ONLY)
      if (!mCheckPowerStatus) {
        DPRINTF_BM ("Check power failure during HOB capsule update.\n");
        return EFI_UNSUPPORTED;
      }
#endif

      IsFmpCap = FALSE;
#if OPTION_SUPPORT_FMP_CAPSULE_UPDATE

      //
      // Check if it is the firmware management capsule by checking if it is FMP capsule guid.
      //

      if (CompareGuid (&CapsuleHeader->CapsuleGuid, &gEfiFmpCapsuleGuid) == TRUE) {
        IsFmpCap = TRUE;
      }

#endif // OPTION_SUPPORT_FMP_CAPSULE_UPDATE


      if (IsFmpCap == FALSE) {

        //
        // Get the SCT_SECURE_FLASH_AUTHENTICATION_PROTOCOL to verify the capsule.
        //

        Status = gBS->LocateProtocol (&gSctSecureFlashAuthenticationProtocolGuid, NULL, (VOID **) &SecureFlashAuth);
        if (EFI_ERROR (Status)) {
          DPRINTF_BM ("Failed to locate SCT_SECURE_FLASH_AUTHENTICATION_PROTOCOL, Status = %r\n", Status);
          if (OPTION_SUPPORT_SECURE_FLASH) {
            DPRINTF_BM ("Unable to verify the capsule, abort updating!\n");
            return Status;
          }
        } else {
          DPRINTF_BM ("Located SecureFlashAuth = 0x%x\n", SecureFlashAuth);
        }

        //
        // Verify the signature of the capsule file before launched the capsule.
        //

        if (SecureFlashAuth != NULL) {
          Status = SecureFlashAuth->VerifyCapsule ((UINT8 *) CapsuleHeader);
          if (Status != EFI_SUCCESS) {
            DPRINTF_BM ("Capsule verification failed!\n");
            return Status;
          } else {
            DPRINTF_BM ("Capsule verified.\n");
          }
        }

        //
        // ScatterGatherList is only referenced if the capsules are defined to persist
        // across system reset.  This function should not return since the capsule's
        // flash update driver should call the reset after the flash is done.
        //

        gST->ConOut->ClearScreen(gST->ConOut);

#if OPTION_SUPPORT_SURE_BOOT

        //
        // Reset the sure boot status before updating capsule.
        //

        DPRINTF_INIT ("  Reset the SureBootStatus.\n");
        SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_RESET_SURE_BOOT_STATUS, ResetSureBootStatus, NULL, 0);
#endif
      }
      gRT->UpdateCapsule (&CapsuleHeader, 1, (EFI_PHYSICAL_ADDRESS) NULL);
      break;
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  return Status;
} // UpdateCapsuleFromHob

#if OPTION_SYSTEM_CAPSULE_UPDATE_HDD || OPTION_SUPPORT_WUFU


//
// FUNCTION NAME.
//      UpdateCapsuleFromHdd - Update capsule file from HDD.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to update the capsule file from GPT HDD.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
UpdateCapsuleFromHdd (VOID)
{
  EFI_STATUS Status;
  SCT_CAPSULE_STORAGE_PROTOCOL *CapsuleStorage;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  EFI_CAPSULE_HEADER *CapsuleHeaderPtr [MAX_CAPSULE_COUNT];
  SCT_CAPSULE_POLICY_PROTOCOL *CapsulePolicy;
  UINTN CapsuleCount;
  UINTN i, j;

  SCT_ERROR_PROTOCOL *ErrorLog;
  CHAR16 *VerifyFailedErrorLogStr = L"Secure Flash Authentication failed";
  CHAR16 *DetailErrorLogStr = L"Capsule data is invalid";
  SCT_ERROR_DETAILS Details;
  SCT_ERROR_NOTIFY Notify;

  EFI_HANDLE *CapsulePolicyHandleBuffer;
  UINTN CapsulePolicyHandleCount;
  BOOLEAN HddUpdateCapsuleCalled = FALSE;
  SCT_SECURE_FLASH_AUTHENTICATION_PROTOCOL *SecureFlashAuth = NULL;
  BOOLEAN IsFmpCap = FALSE;

#if OPTION_SUPPORT_WUFU
  EFI_GUID SystemFirmwareGuid = CONFIG_SCT_ESRT_SYSTEM_FIRMWARE_CLASS_GUID;
#endif // OPTION_SUPPORT_WUFU

  Status = EFI_SUCCESS;
  HandleCount = 0;
  HandleBuffer = NULL;
  ErrorLog = NULL;

  SetMem (CapsuleHeaderPtr, sizeof (CapsuleHeaderPtr), 0);

  if (mBootMode == BOOT_ON_FLASH_UPDATE) {

    //
    // Get the SCT_SECURE_FLASH_AUTHENTICATION_PROTOCOL to verify the capsule.
    //

    Status = gBS->LocateProtocol (&gSctSecureFlashAuthenticationProtocolGuid, NULL, (VOID **) &SecureFlashAuth);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("Failed to locate SCT_SECURE_FLASH_AUTHENTICATION_PROTOCOL, Status = %r\n", Status);
      if (OPTION_SUPPORT_SECURE_FLASH) {
        DPRINTF_BM ("Unable to verify the capsule, abort updating!\n");
        return Status;
      }
    } else {
      DPRINTF_BM ("Located SecureFlashAuth = 0x%x\n", SecureFlashAuth);
    }

    //
    // Locate the CapsuleStorageProtocol, the protocol itself will then
    // read the capsule data either from the HDD, GPT HDD or any other
    // external device.
    //

    Status = gBS->LocateHandleBuffer (
                    ByProtocol,
                    &gSctCapsuleStorageProtocolGuid,
                    NULL,
                    &HandleCount,
                    &HandleBuffer);
    if (EFI_ERROR (Status) || HandleCount == 0) {
      return Status;
    }

    if (mCapsuleUpdateHddUnlockConnectList->TextDevicePath == NULL) {
      ConnectAllHandles ();
    } else {
      ConnectDevices (mCapsuleUpdateHddUnlockConnectList);
    }

    UnlockAllHdd ();

    for (i = 0; i < HandleCount; i ++) {

      Status = gBS->HandleProtocol (
                      HandleBuffer [i],
                      &gSctCapsuleStorageProtocolGuid,
                      (VOID **) &CapsuleStorage);
      if (EFI_ERROR (Status)) {
        continue;
      }

      //
      // Check if the serviced is CAPSULE_STORAGE_ESP_DELIVERY_SERVICE_ID if
      // the capsule delivery flag has been set.
      //

      if (mCapsuleEspDelivery == TRUE) {
        if (CapsuleStorage->ServiceId != CAPSULE_STORAGE_ESP_DELIVERY_SERVICE_ID) {
          continue;
        }
      }

      Status = CapsuleStorage->QuerySupport (CapsuleStorage);
      if (EFI_ERROR (Status)) {
        continue;
      }

      Status = CapsuleStorage->NotifyPhase (CapsuleStorage, SctCapsuleStorageInitialization);
      if (EFI_ERROR (Status)) {
        continue;
      }

      Status = CapsuleStorage->NotifyPhase (CapsuleStorage, SctCapsuleStorageBeforeRead);
      if (EFI_ERROR (Status)) {
        continue;
      }

      CapsuleCount = MAX_CAPSULE_COUNT;

      Status = CapsuleStorage->ReadCapsule (CapsuleStorage, CapsuleHeaderPtr, &CapsuleCount);
      if (EFI_ERROR (Status)) {
        continue;
      }

      Status = CapsuleStorage->NotifyPhase (CapsuleStorage, SctCapsuleStorageAfterRead);
      if (EFI_ERROR (Status)) {
        continue;
      }

      Status = CapsuleStorage->EraseCapsule (CapsuleStorage);
      if (EFI_ERROR (Status)) {
        continue;
      }

      Status = CapsuleStorage->NotifyPhase (CapsuleStorage, SctCapsuleStorageProcessImage);
      if (EFI_ERROR (Status)) {
        continue;
      }

      if (CapsuleCount != 0) {
        HddUpdateCapsuleCalled = TRUE;
      }

      //
      // Process capsules with capsule policy.  In case if there is any special tasks
      // needed before send the capsule into UpdateCapsule() function.  User is able to
      // install a new CapsulePolicy protocol then perform additional tasks.
      // For example, WUFU logo capsule need to display the logo on the screen but does
      // not necessary send to UpdateCapsule() function.
      //

      DPRINTF_BM ("Pass-in CapsuleCount = %x\n", CapsuleCount);
      Status = gBS->LocateHandleBuffer (
                      ByProtocol,
                      &gSctCapsulePolicyProtocolGuid,
                      NULL,
                      &CapsulePolicyHandleCount,
                      &CapsulePolicyHandleBuffer);
      if (!EFI_ERROR (Status)) {

        for (j = 0; j < CapsulePolicyHandleCount; j++) {

          Status = gBS->HandleProtocol (
                          CapsulePolicyHandleBuffer [j],
                          &gSctCapsulePolicyProtocolGuid,
                          (VOID **) &CapsulePolicy);
          if (!EFI_ERROR (Status)) {
            CapsulePolicy->ProcessCapsule (
                             CapsulePolicy,
                             CapsuleHeaderPtr,
                             &CapsuleCount,
                             MAX_CAPSULE_COUNT);
          }
        }

        FreePool (CapsulePolicyHandleBuffer);

      } else {
        DPRINTF_BM ("Capsule policy not found.\n");
      }

      //
      // Reset each capsule flags to 0 since it is doing the actual flash update.
      //

      for (j = 0; j < CapsuleCount; j++) {
        CapsuleHeaderPtr [j]->Flags = 0;
      }

      DPRINTF_BM ("CapsuleCount = 0x%x\n", CapsuleCount);
      Status = CapsuleStorage->NotifyPhase (CapsuleStorage, SctCapsuleStorageSecureVerify);
      if (EFI_ERROR (Status)) {
        continue;
      }

#if OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS
      if (!mCheckPowerStatus) {
        DPRINTF_BM ("Check power failure during HDD capsule update.\n");

        for (j = 0; j < CapsuleCount; j++) {

          //
          // Skip the capsules if power check failure
          //

          CapsuleHeaderPtr [j]->CapsuleImageSize = 0;
          CapsuleHeaderPtr [j]->HeaderSize = 0;

#if OPTION_SUPPORT_WUFU

          //
          // Check if the capsule guid is system firmware.
          //

          if (CompareGuid ((EFI_GUID *) CapsuleHeaderPtr [j], &SystemFirmwareGuid)) {

            //
            // Get the TDK status, and write back to the ESRT table variable.
            //

            SetTdkStatus (FLASH_ERROR_POWER_STATUS_BATTERY);
          } else {

            //
            // If it is other device capsule guid, then try to find the ESRT entry from the
            // ESRT variable and then add the verify failed status back to the ESRT entry.
            //

            SetLdfStatus ((EFI_GUID *) CapsuleHeaderPtr [j], LAST_ATTEMPT_STATUS_ERROR_PWR_EVT_BATT);
          }
#endif // OPTION_SUPPORT_WUFU
        }

        return EFI_UNSUPPORTED;
      }
#endif // OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS

      //
      // If mCapsuleEspDelivery flag is set, then actual security check will
      // be performed by the FMP itself.
      //

      if ((SecureFlashAuth != NULL) && (mCapsuleEspDelivery == FALSE)) {
        for (j = 0; j < CapsuleCount; j++) {

          IsFmpCap = FALSE;
#if OPTION_SUPPORT_FMP_CAPSULE_UPDATE

          //
          // Check if it is the firmware management capsule by checking the FMP capsule guid.
          //

          if (CompareGuid (&CapsuleHeaderPtr [j]->CapsuleGuid, &gEfiFmpCapsuleGuid) == TRUE) {
            IsFmpCap = TRUE;
          }

#endif // OPTION_SUPPORT_FMP_CAPSULE_UPDATE

          //
          // If the capsule is FMP, then skip the SecureFlash verification.
          //

          if (IsFmpCap == TRUE) {
            continue;
          }

          Status = SecureFlashAuth->VerifyCapsule ((UINT8 *) CapsuleHeaderPtr [j]);
          if (Status != EFI_SUCCESS) {
            DPRINTF_BM ("Capsule verification failed!\n");

            //
            // If current capsule verify failed, then set the CapsuleImageSize and HeaderSize to
            // 0, so when it calls the UpdateCapsule, it will skip.
            //

            CapsuleHeaderPtr [j]->CapsuleImageSize = 0;
            CapsuleHeaderPtr [j]->HeaderSize = 0;
            if (Status == EFI_SECURITY_VIOLATION) {

              //
              // Report the error to the ErrorManager if authentication failed.
              //

              Status = gBS->LocateProtocol (&gSctErrorProtocolGuid, NULL, (VOID **) &ErrorLog);
              if (EFI_ERROR (Status)) {
                DPRINTF_BM ("Unable to locate System Error Manager Protocol (%r)\n", Status);
              } else {

                //
                // Log error.
                //

                Details = SCT_ERROR_LOG_TIMESTAMP;
                Notify = SCT_ERROR_NOTIFY_STYLE_PROMPT_CONTINUE | SCT_ERROR_NOTIFY_PREBOOT;
                Status = ErrorLog->Log (
                                     EFI_ERROR_CODE | EFI_ERROR_MINOR,
                                     0,
                                     Details,
                                     Notify,
                                     NULL,
                                     (CHAR8 *)"0",
                                     VerifyFailedErrorLogStr,
                                     DetailErrorLogStr);
              }
            }

#if OPTION_SUPPORT_WUFU

            //
            // For WUFU support, if the firmware or device capsule verify failed, it need to write
            // the status back to LFS or PLDFS variable to indicate the update status back to the
            // ESRT table.
            //

            //
            // Check if the capsule guid is system firmware.
            //

            if (CompareGuid ((EFI_GUID *) CapsuleHeaderPtr [j], &SystemFirmwareGuid)) {

              //
              // Get the TDK status, and write back to the ESRT table variable.
              //

              SetTdkStatus (FLASH_ERROR_VERIFY_CAPSULE);
            } else {

              //
              // If it is other device capsule guid, then try to find the ESRT entry from the
              // ESRT variable and then add the verify failed status back to the ESRT entry.
              //

              SetLdfStatus ((EFI_GUID *) CapsuleHeaderPtr [j], LAST_ATTEMPT_STATUS_ERROR_AUTH_ERROR);
            }
#endif // OPTION_SUPPORT_WUFU
          } else {
            DPRINTF_BM ("Capsule verified.\n");
          }
        }
      }

      Status = CapsuleStorage->NotifyPhase (CapsuleStorage, SctCapsuleStorageBeforeUpdate);
      if (EFI_ERROR (Status)) {
        continue;
      }

      DPRINTF_BM ("Calling UpdateCapsule\n");
      Status = gRT->UpdateCapsule (CapsuleHeaderPtr, CapsuleCount, (EFI_PHYSICAL_ADDRESS) NULL);
      if (EFI_ERROR (Status)) {
        DPRINTF_BM ("UpdateCapsule return %r.\n", Status);
      }

      Status = CapsuleStorage->NotifyPhase (CapsuleStorage, SctCapsuleStorageAfterUpdate);
      if (EFI_ERROR (Status)) {
        continue;
      }
    }

    //
    // If it gets here, then it means that the capsule file did not verify successfully
    // or for unknown reason it return from UpdateCapsule. Normally, if the flash update
    // success, the flash tool in the capsule should reset the platform.  So reset the
    // platform.
    //

    if (HddUpdateCapsuleCalled == TRUE) {
      gRT->ResetSystem ((EFI_RESET_TYPE)EfiResetWarm, EFI_SUCCESS, 0, (CHAR16 *)NULL);
    }
  }

  return Status;
} // UpdateCapsuleFromHdd
#endif // OPTION_SYSTEM_CAPSULE_UPDATE_HDD


//
// FUNCTION NAME.
//      UpdateCapsuleService - Update capsule service.
//
// FUNCTIONAL DESCRIPTION.
//      This function will get the capsule file either from HOB or
//      HDD partition and launch the capsule file by calling
//      RT->UpdateCapsule ().
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
UpdateCapsuleService (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_STATUS Status;

  Status = EFI_SUCCESS;

  //
  // Check if the boot mode is BOOT_ON_FLASH_UPDATE or BOOT_IN_RECOVERY_MODE.
  //

  if ((mBootMode == BOOT_ON_FLASH_UPDATE) || (mBootMode == BOOT_IN_RECOVERY_MODE)) {

#if OPTION_SYSTEM_CAPSULE_UPDATE_CHECK_POWER_STATUS

    //
    // Check the power status
    //

    Status = CheckPowerStatus ();
    mCheckPowerStatus = !EFI_ERROR (Status);

    if (!mCheckPowerStatus) {

      //
      // Print the error message
      //

      gST->ConOut->SetAttribute (gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
      gST->ConOut->SetCursorPosition (
                      gST->ConOut,
                      0,
                      0);

      gST->ConOut->OutputString (
                      gST->ConOut,
                      mCheckPowerStatusErrorStr);

      gBS->Stall (5000000);
    }
#endif

    //
    // Check if the capsule could be update from the memory hob.
    //

    if (mCapsuleEspDelivery == FALSE) {

      //
      // If mCapsuleEspDelivery has been set, then no need to check the capsule
      // from the HOB.
      //

      Status = UpdateCapsuleFromHob ();
      DPRINTF_BM ("UpdateCapsuleFromHob return %r\n", Status);
    }

#if OPTION_SYSTEM_CAPSULE_UPDATE_HDD || OPTION_SUPPORT_WUFU

    //
    // Check if the capsule could be update from the GPT HDD.
    //

    Status = UpdateCapsuleFromHdd ();
    DPRINTF_BM ("UpdateCapsuleFromHdd return %r\n", Status);

    //
    // Delete the variable to prevent a situation that the variable exists but the capsule file has gone.
    //

    gRT->SetVariable (
           SCT_HDD_CAPSULE_VARIABLE_NAME,
           &gEfiCapsuleVendorGuid,
           EFI_VARIABLE_NON_VOLATILE |
           EFI_VARIABLE_BOOTSERVICE_ACCESS |
           EFI_VARIABLE_RUNTIME_ACCESS,
           0,
           (VOID *) NULL);

#endif // (OPTION_SYSTEM_CAPSULE_UPDATE_HDD)

#if OPTION_SYSTEM_CAPSULE_UPDATE_RESET_ALWAYS
    //
    // Always reset the system to make sure during the capsule flash update mode, if
    // the update process failed for any reasons, no other boot device should boot,
    // so that the BIOS flash service won't be consumed by other unauthorized EFI/OS
    // drivers.
    //

    gRT->ResetSystem ((EFI_RESET_TYPE)EfiResetWarm, EFI_SUCCESS, 0, (CHAR16 *)NULL);
#endif // OPTION_SYSTEM_CAPSULE_UPDATE_RESET_ALWAYS
  }

  return Status;
} // UpdateCapsuleService

#endif // OPTION_SUPPORT_CAPSULE_UPDATE
