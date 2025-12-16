//
// FILENAME.
//      Legacy.c - SecureCore Technology(TM) Support for booting through the CSM.
//
// FUNCTIONAL DESCRIPTION.
//      This module provides support for legacy boot. Legacy boot is using the
//      LegacyBoot function of the LegacyBios protocol to boot to an OS that
//      does not have support for booting in an EFI way, the OS does not know
//      about or does not support EFI.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

#define CONVENTIONAL_MEMORY_TOP   0xA0000

//
// External references.
//

#if (OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)
extern
SCT_STATUS
PromptForLoadingCsm (VOID);
#endif // OPTION_CSM_AUTO_OPTION && OPTION_CSM_OPTION_OUT


#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

//
// Private data types used by this module are defined here and any
// static items are declared here.
//

EFI_LEGACY_BIOS_PROTOCOL *mLegacyBios = NULL;
static BOOLEAN mLegacyInitialized = FALSE;
static BOOLEAN mLegacyOpromShadowed = FALSE;
static EFI_LEGACY_REGION_PROTOCOL *mLegacyRegion = NULL;

static UINTN mSwappedIndex = 0;

static UINT8 RemovableSdmem = SDMEM_FDD_BOOT_START_INDEX;
static UINT8 RemovableDeviceCount = 0;
static UINT8 UsbFloppyDeviceCount = 0;
static UINT8 UsbZipDeviceCount = 0;
static UINT8 IdeInfo = 0;
static UINT8 AhciInfo = 0;
static UINT8 NvmeInfo = 0;
static UINT8 HardDiskDeviceCount = 0;
static UINT8 HardDiskIde = IDE_HDD_BOOT_START_INDEX;
static UINT8 HardDiskScsi = SCSIHDD_BOOT_START_INDEX;
static UINT8 HardDiskSdmem = SDMEM_HDD_BOOT_START_INDEX;
static UINT8 HardDiskAhci = AHCIHDD_BOOT_START_INDEX;
static UINT8 HardDiskNvme = NVMEHDD_BOOT_START_INDEX;
static UINT8 CdromDeviceCount = 0;
static UINT8 CdromIde = IDE_CDROM_BOOT_START_INDEX;
static UINT8 CdromUsb = USBCDROM_BOOT_START_INDEX;
static UINT8 CdromAhci = AHCICDROM_BOOT_START_INDEX;

#if OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER
static UINT8 LANDeviceCount = 0;
static UINT8 BEVDeviceCount = 0;
#endif // OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER

//
// Backup buffer for BBS_TABLE.
//

static BBS_TABLE *mBackupBbsTable = NULL;
#endif //OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

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

extern
BOOLEAN
EFIAPI
LegacyBootEnabled (OUT PBOOLEAN LegacyBeforeUefi OPTIONAL);

extern
SCT_STATUS
EFIAPI
ExpandDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

extern
EFI_STATUS
SignalBootFail (IN UINT8 Type);

extern
EFI_DEVICE_PATH_PROTOCOL *
CreateBbsDevicePath (
  IN UINT16 DeviceType,
  IN UINT16 StatusFlag,
  IN CHAR16 *DescriptionString
  );

extern
EFI_STATUS
EFIAPI
ReConnectVgaToThunkDriver (VOID);

extern
EFI_STATUS
EFIAPI
UnlockHdd (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

extern
SCT_STATUS
DestroyBopChildList (IN PSCT_BOOT_OPTION_NODE ChildList);

extern
BOOLEAN
IsUsbLanExisted (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

extern
BOOLEAN
IsUsbLanManagedByUefi (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

extern
EFI_STATUS
LoadUsbLanOpromFromFV (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

//
// Data shared with other modules *within* this component.
//

BOOT_MANAGER_CONNECTION_DEVICE LegacyConnectList [] = {
  CONFIG_BmLegacyConnectList
};


//
// Data defined in other modules and used by this module.
//

extern BOOLEAN mDxeSmmReadyToLockProtocol;

extern LEGACY_USBLAN_OPROM OpromTable[];

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

static
IBV_BBS_TABLE *
LegacyGetIbvBbs (VOID);

static
SCT_STATUS
LegacyUpdateBbsTables (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN CONST PCHAR16 BootListName
  );

static
SCT_STATUS
PrepareToBootLegacy (IN UINT16 OptionNumber);

static
EFI_STATUS
BackupBbsTable (VOID);

static
EFI_STATUS
RestoreBbsTable (VOID);

static
VOID
FillIbvUsbDiskInfo (
  IN OUT PIBV_BBS_TABLE IbvBbs,
  IN UINT16 BbsCount,
  IN BBS_TABLE *BbsTable,
  IN EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths
  );

static
SCT_STATUS
UpdateLegacyUsbToBbsTable (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsCount,
  IN EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths,
  IN EFI_DEVICE_PATH_PROTOCOL * UsbDevicePath OPTIONAL,
  OUT int *BbsTableIndex OPTIONAL
  );

EFI_STATUS
UpdateBbsDriveNumber (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsCount,
  IN PIBV_BBS_TABLE IbvBbs
  );

#if OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER

static
VOID
ArrangeDevOrderAccordingToBootOrder (
  IN UINT16 *Buffer,
  IN UINTN Count
  );

SCT_STATUS
BootOptionProtocolDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

#endif // OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER

#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

//
// Public API functions implemented by this component.
//

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
SCT_STATUS
EFIAPI
GetBbsEntryByDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT UINT16 *BbsIndex,
  OUT BBS_TABLE **BbsEntry
  );
#endif

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
static
EFI_STATUS
CreateUsbIrqSwSmiTable (IN EFI_TO_COMPATIBILITY16_BOOT_TABLE *EfiToLegacy16BootTable);
#endif

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
static EFI_GUID mCsmSwSmiGuidArray [SCT_CSM_SW_SMI_FUNCTION_COUNT] = SCT_CSM_SW_SMI_GUID_ARRAY;
#endif //OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
GLOBAL_REMOVE_IF_UNREFERENCED BOOLEAN Flag = FALSE;

EFI_DEVICE_PATH_PROTOCOL *mCurrentBootDevicePath;
BOOLEAN mIsCurrentBootCreatedInIBV = FALSE;

//
// Below functions are public with EFIAPI prefix.
//

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
//
// FUNCTION NAME.
//      GetBbsEntryByDevicePath - Get Bbs entry according to DevicePath.
//
// FUNCTIONAL DESCRIPTION.
//      This function will finds the BbsTable index and entry according to the
//      input DevicePath.
//
// ENTRY PARAMETERS.
//      DevicePath      - DevicePath to be searched.
//
// EXIT PARAMETERS.
//      BbsIndex        - Index of BbsTable entry.
//      BbsEntry        - Pointer points to the BbsTable entry.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
GetBbsEntryByDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT UINT16 *BbsIndex,
  OUT BBS_TABLE **BbsEntry
  )
{
  int i;
  UINT16 Index;
  UINT16 HddCount;
  UINT16 BbsCount;
  SCT_STATUS Status;
  HDD_INFO *HddInfo;
  BBS_TABLE *BbsTable;
  EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths;

  i = 0;
  Index = 0;
  HddCount = 0;
  BbsCount = 0;

  DPRINTF_LEGACY (":\n");

  if (BbsIndex == NULL || BbsEntry == NULL) {
    DPRINTF_LEGACY ("  Invalid parameter \n");
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get the BBS Table from the LegacyBios driver.
  //

  if (mLegacyBios == NULL) {
    DPRINTF_LEGACY ("  Not ready \n");
    return SCT_STATUS_NOT_READY;
  }

  Status = mLegacyBios->GetBbsInfo (
                          mLegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          &BbsTable);

  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  GetBbsInfo fail \n");
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gBbsTableDevicePathsTableGuid,
                  NULL,
                  (VOID **) &BbsTableDevicePaths);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  LocateProtocol fail \n");
    return Status;
  }

  for (Index = 0; Index < BbsCount; Index++) {
    if (BbsTableDevicePaths [Index] != NULL) {
      if (CompareDevicePath (DevicePath, BbsTableDevicePaths [Index])) {
        break;
      }
    }
  }

  if (Index == BbsCount) {
    DPRINTF_LEGACY ("  Not found \n");
    return SCT_STATUS_NOT_FOUND;
  }

  *BbsIndex = Index;
  *BbsEntry = &BbsTable [Index];
  return SCT_STATUS_SUCCESS;
} // GetBbsEntryByDevicePath
#endif


//
// FUNCTION NAME.
//      InitializeLegacy - Initialize Legacy Module.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called during driver initialization to initialize
//      the .
//
//      In the current implementation, this routine performs no work.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
InitializeLegacy (VOID)
{
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  SCT_STATUS Status;

  DPRINTF_LEGACY ("InitializeLegacy:\n");

  if (!LegacyBootEnabled (NULL)) {
    DPRINTF_LEGACY ("  Legacy Boot is disabled.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  if (mLegacyInitialized) {
    DPRINTF_LEGACY ("  Already initialized.\n");
    return SCT_STATUS_SUCCESS;
  }

  //
  // Locate LegacyBios and LegacyRegion protocol.
  //

  Status = gBS->LocateProtocol (
                  &gEfiLegacyRegion2ProtocolGuid,
                  NULL,
                  (VOID **) &mLegacyRegion);

  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  Failed to locate LegacyRegion2 Protocol\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  Status = gBS->LocateProtocol (
                  &gEfiLegacyBiosProtocolGuid,
                  NULL,
                  (VOID **) &mLegacyBios);

  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  Failed to locate LegacyBios Protocol\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  {
    LEGACY_BIOS_INSTANCE *Private;
    EFI_IA32_REGISTER_SET Regs;
    LOW_MEMORY_THUNK *IntThunk;
    EFI_TO_COMPATIBILITY16_BOOT_TABLE *EfiToLegacy16BootTable;
    EFI_LEGACY_BIOS_PLATFORM_PROTOCOL *LegacyBiosPlatform;

    //
    // We must rewind to private data to get Private->Legacy16CallSegment
    // and Private->Legacy16CallOffset which are needed to make a Compatability16
    // function call which we need to do to update our SMM table in our CSM.
    //

    Private = LEGACY_BIOS_INSTANCE_FROM_THIS (mLegacyBios);
    IntThunk  = Private->IntThunk;
    EfiToLegacy16BootTable = &Private->IntThunk->EfiToLegacy16BootTable;

    Status = gBS->LocateProtocol (
                    &gEfiLegacyBiosPlatformProtocolGuid,
                    NULL,
                    (VOID **) &LegacyBiosPlatform);
    if (EFI_ERROR (Status)) {
      DPRINTF_LEGACY ("  Couldn't locate Legacy Bios Platform Protocol, %r.\n", Status);
      return Status;
    }

    //
    // Unlock the Legacy BIOS region.
    //

    Status = mLegacyRegion->UnLock (
                              mLegacyRegion,
                              EGROUP_START_ADDRESS,
                              LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                              NULL);
    if (EFI_ERROR (Status)) {
      DPRINTF_LEGACY ("  Could not unlock legacy region, %r.\n", Status);
      return Status;
    }

    //
    // Ask the platform driver to make sure that any SMM drivers are loaded.
    //

    Status = CreateUsbIrqSwSmiTable (EfiToLegacy16BootTable);

    if (Status == EFI_SUCCESS) {
      LegacyBiosPlatform->SmmInit (LegacyBiosPlatform, EfiToLegacy16BootTable);

      //
      // Call into Legacy16 code to do Legacy16CsmSmmInit. This will update the
      // internal table in the CSM that allows SwSmi to be routed to the correct
      // number per function.
      //

      ZeroMem (&Regs, sizeof (EFI_IA32_REGISTER_SET));
      Regs.X.AX = Legacy16EarlySmmInit;
      Regs.X.ES = EFI_SEGMENT (*((UINT32 *) &EfiToLegacy16BootTable));
      Regs.X.BX = EFI_OFFSET (*((UINT32 *) &EfiToLegacy16BootTable));

      Status = mLegacyBios->FarCall86 (
                              mLegacyBios,
                              Private->Legacy16CallSegment,
                              Private->Legacy16CallOffset,
                              &Regs,
                              NULL,
                              0);
      if (EFI_ERROR (Status)) {
        DPRINTF_LEGACY ("  Problem loading SwSmi table in CSM, %r.\n", Status);
        mLegacyRegion->Lock (
                         mLegacyRegion,
                         EGROUP_START_ADDRESS,
                         LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                         NULL);
        return Status;
      }
    }

    //
    // Re-lock the legacy region.
    //

    mLegacyRegion->Lock (
                     mLegacyRegion,
                     EGROUP_START_ADDRESS,
                     LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                     NULL);
  }

  //
  // Legacy initialization was successful. No need to do it again.
  //

  DPRINTF_LEGACY ("  Legacy has been initialized\n");
  DPRINTF_LEGACY ("  mLegacyRegion = 0x%x\n", mLegacyRegion);
  DPRINTF_LEGACY ("  mLegacyBios   = 0x%x\n", mLegacyBios);

  mLegacyInitialized = TRUE;

#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  return SCT_STATUS_SUCCESS;
} // InitializeLegacy




#if OPTION_SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT

//
// FUNCTION NAME.
//      CheckActivePartition - Check the Active status in Partition table
//
// FUNCTIONAL DESCRIPTION.
//      This function will process to Check the Active status in Partition table.
//      Only check HDD type, others just return TRUE.
//
// ENTRY PARAMETERS.
//      DevicePath   - Additional data for the milestone task to process.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN, TRUE is Boot, FALSE is none bootable.
//

BOOLEAN
EFIAPI
CheckActivePartition (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  UINTN i;
  VOID *Buffer;
  UINT8 TempValue;
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  UINT8 *TempBuffer;
  BOOLEAN BoolReturn;
  UINTN DevicePathBootType;
  EFI_BLOCK_IO_PROTOCOL *BlkIo;
  EFI_BLOCK_IO_MEDIA *BlkMedia;
  EFI_HANDLE ImageHandle = (VOID *) NULL;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  BoolReturn = FALSE;

  if (DevicePath == NULL) {
    return FALSE;
  }

  DPRINTF_LEGACY ("DevicePath:");
  DEBUG_LO (
    CHAR16* Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_LO ("%s.\n", Str);
    SafeFreePool (Str);
  )

  DevicePathBootType = GetBootTypeFromDevicePath (DevicePath);
  if (DevicePathBootType != BDS_EFI_MESSAGE_ATAPI_BOOT) {
    DPRINTF_LEGACY ("Not HDD type. The Boot Type is:0x%x\n", DevicePathBootType);
    return TRUE;
  }

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("FALSE:LocateDevicePath error.\n");
    return TRUE;
  }

  //
  // Get the BlockIo Protocol instance that is installed on this handle.
  // If the device no BlockIo, just skip it.
  //

  Status = gBS->OpenProtocol (
                  Handle,               // the handle being tested.
                  &gEfiBlockIoProtocolGuid,
                  (VOID **) &BlkIo,               // interface.
                  ImageHandle,         // the handle who is testing.
                  NULL,                 // no controller handle.
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  DPRINTF_LEGACY (
    "  IsRemovableMediaDevicePath.OpenProtocol (gEfiBlockIoProtocolGuid):\n"
    "    Status = %r\n",
    Status);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("Can notOpenBlockIo Protocol.\n");
    return TRUE;
  }

  BoolReturn = FALSE;

  BlkMedia  = BlkIo->Media;
  Buffer = AllocatePool (BlkMedia->BlockSize);
  if (Buffer) {
    BlkIo->ReadBlocks (
             BlkIo,
             BlkMedia->MediaId,
             0,
             BlkMedia->BlockSize,
             Buffer);

    if (BlkMedia->MediaPresent) {
      TempBuffer = (UINT8 *) Buffer;
      if ((TempBuffer[PARTITION_SIGNATURE_OFFSET] !=0x55) ||
        (TempBuffer[PARTITION_SIGNATURE_OFFSET+1] !=0xAA)) {

        return BoolReturn;
      } // if ((TempBuffer[PARTITION_SIGNATURE_OFFSET]
      for (i = PARTITION_TABLE_OFFSET; i < PARTITION_SIGNATURE_OFFSET;) {
        TempValue = TempBuffer[i];
        if (TempValue == PARTITION_ACTIVE) {
          BoolReturn = TRUE;
          break;
        } // if (TempValue == PARTITION_ACTIVE) {
        i += SIZE_OF_PARTITION_ENTRY;
      } // for (i=0x1BE; i< 0x1FE;)
    } // if (BlkMedia->MediaPresent) {
    SafeFreePool (Buffer);
  } // if (Buffer)
  gBS->CloseProtocol(Handle, &gEfiBlockIoProtocolGuid, ImageHandle, NULL);

  return BoolReturn;

} // CheckActivePartition

//
// FUNCTION NAME.
//      MsTaskDecideLegacyBoot - Default task for the DecideLegacyBoot
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the DecideLegacyBoot
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
MsTaskDecideLegacyBoot (
  IN VOID *MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  BOOLEAN DecideBoot;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  PSCT_BDS_DECIDE_BOOT_DEVICE_PATH_DATA MilestoneDecideData;

  MilestoneDecideData = (PSCT_BDS_DECIDE_BOOT_DEVICE_PATH_DATA) MilestoneData;

  DevicePath = MilestoneDecideData->DevicePath;

  DecideBoot = CheckActivePartition (DevicePath);
  if (DecideBoot) {
    MilestoneDecideData->ReturnStatus = EFI_SUCCESS;
  } else {
    MilestoneDecideData->ReturnStatus = EFI_DEVICE_ERROR;
  }
  return EFI_SUCCESS;
}
#endif // // OPTION_SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT

//
// FUNCTION NAME.
//      LegacyBoot - Boot to a device using the legacy method.
//
// FUNCTIONAL DESCRIPTION.
//      This function uses the Legacy BIOS Protocol to attempt to launch a BBS
//      Device Node.
//
//      This function will update the IbsBbs table such that the DeviceType of
//      this BBS Device Node is the only group listed in BootSeq_Item_Order.
//
// ENTRY PARAMETERS.
//      FilePathList    - The Device Path for the Device Type to boot.
//      OptionNumber    - The Option Number for this Device Path.
//      OptionalData    - The Data to pass to the boot.
//      OptionalDataLength - The number of byte of data.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
LegacyBoot (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN UINT16 OptionNumber,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  )
{
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  EFI_TPL Tpl;
  SCT_STATUS Status, rc;
  EFI_HANDLE BootDeviceHandle;
#if OPTION_SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT
  UINT32 DataSize;
  SCT_BDS_DECIDE_BOOT_DEVICE_PATH_DATA DecideLegacyBoot;
#endif // // OPTION_SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT
  DPRINTF_LEGACY ("LegacyBoot:\n");

  if (!LegacyBootEnabled (NULL)) {
    DPRINTF_LEGACY ("  Legacy Boot is disabled.\n");
    return SCT_STATUS_UNSUPPORTED;
  }
#if OPTION_SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT
  DecideLegacyBoot.DevicePath = FilePathList;
  DecideLegacyBoot.OptionNumber = OptionNumber;
  DecideLegacyBoot.OptionalData = OptionalData;
  DecideLegacyBoot.OptionalDataLength = OptionalDataLength;
  DecideLegacyBoot.ReturnStatus = EFI_SUCCESS;
  DataSize = sizeof (DecideLegacyBoot);

  PERF_START (0, "DecideLegacyBoot", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_DECIDE_LEGACY_BOOT, MsTaskDecideLegacyBoot, &DecideLegacyBoot, DataSize);
  PERF_END (0, "DecideLegacyBoot", "BootManager", 0);

  if (EFI_ERROR (DecideLegacyBoot.ReturnStatus)) {
    DPRINTF_LEGACY ("  Decide not boot to Legacy code.\n");
    return SCT_STATUS_UNSUPPORTED;
  }
#endif // OPTION_SYSTEM_BOOT_MANAGER_PRECHECK_LEGACY_BOOT

  PERF_START (0, "LegacyInit", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_LEGACY_INIT, MsTaskLegacyInit, NULL, 0);
  PERF_END (0, "LegacyInit", "BootManager", 0);

#if (OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)
  if (!mLegacyInitialized && mSystemConfiguration.CsmSupport == 2) {

    //
    // Since the essential CSM module has not been loaded, query the user.
    //

    return PromptForLoadingCsm ();
  }
#endif // OPTION_CSM_AUTO_OPTION && OPTION_CSM_OPTION_OUT

  if (!mAllOpromShadowed) {
    Status = LoadOpromFromDevicePath (FilePathList, NULL, NULL);
    if (EFI_ERROR (Status)) {
      DPRINTF_LEGACY ("  Failed to load OPROM from device path, status: %r.\n", Status);
    }
  }

#if OPTION_SYSTEM_BOOT_MANAGER_LOAD_OPROM_BEFORE_LEGACY_BOOT

  //
  // Shadow all OPROMs based on legacy connect list.
  // Note: Before shadowing any OPROM, all corresponding devices or controllers
  // should be started via ConnectController first.
  //

  if (!mLegacyOpromShadowed) {
    ShadowOproms (LegacyConnectList);
    mLegacyOpromShadowed = TRUE;
  }

#endif // OPTION_SYSTEM_BOOT_MANAGER_LOAD_OPROM_BEFORE_LEGACY_BOOT

  //
  // Unlock this HDD first and connect the associated handle again.
  //

  DPRINTF_LEGACY ("  Unlock HDD first\n");
  Status = UnlockHdd (FilePathList);
  if (!EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  Connect boot device recursively\n");
    ConnectDevicePathWithRecurse (FilePathList, &BootDeviceHandle, TRUE);
  }

  //
  // Update the tables here so that the chosen bootable device can be assigned
  // to the beginning of the list.
  //

  Status = LegacyUpdateBbsTables (FilePathList, EFI_BOOT_ORDER_VARIABLE_NAME);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  Failed to update Legacy Tables, status: %r.\n", Status);
    return Status;
  }

  //
  // Backup whole BBS_TABLE first.
  //

  BackupBbsTable ();

  //
  // Force the TPL to TPL_APPLICATION.
  //

  DPRINTF_LEGACY ("  PrepareToBootLegacy\n");

  PERF_START (0, LEGACY_BOOT_TOK, "PrepareToBootLegacy", 0);
  Status = PrepareToBootLegacy (OptionNumber);
  PERF_END (0, LEGACY_BOOT_TOK, "PrepareToBootLegacy", 0);

  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  PrepareToBootLegacy returned %r.\n", Status);
  }

  ReConnectVgaToThunkDriver ();

  Tpl = SetTpl (TPL_APPLICATION);

  PERF_START (0, LEGACY_BOOT_TOK, "LegacyBiosBoot", 0);
  rc = mLegacyBios->LegacyBoot (
                      mLegacyBios,
                      (BBS_BBS_DEVICE_PATH *) FilePathList,
                      OptionalDataLength,
                      OptionalData);
  PERF_END (0, LEGACY_BOOT_TOK, "LegacyBiosBoot", 0);

  SetTpl (Tpl);

  DPRINTF_LEGACY ("  LegacyBoot returned %r, Signal Boot Fail\n", rc);
  Status = SignalBootFail (SCT_BDS_LEGACY_BOOT_FAIL);
  DPRINTF_LEGACY ("  SignalBootFail returned %r\n", Status);

  //
  // Restore whole BBS_TABLE.
  //

  RestoreBbsTable ();

  //
  // The legacy boot attempt returned, cleanup.
  //

  SetEfiGlobalVariable (
    EFI_BOOT_CURRENT_VARIABLE_NAME,
    EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS,
    0,
    NULL);

  return rc;
#else
  return SCT_STATUS_UNSUPPORTED;
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
} // LegacyBoot



//
// Private (static) routines used by this component.
//

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

//
// FUNCTION NAME.
//      LegacyGetIbvBbs - Get the Legacy BIOS Ibv Bbs table.
//
// FUNCTIONAL DESCRIPTION.
//      This function finds the compatibility table and gets the address of the
//      Phoenix Specific BBS Table.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - The address of the Ibv Bbs Table.
//

PIBV_BBS_TABLE
LegacyGetIbvBbs (VOID)
{
  EFI_IBV_COMPATIBILITY16_TABLE *IbvCompatibility16Table;
  MEMORY_POINTER p;

  DPRINTF_LEGACY ("LegacyGetIbvBbs:\n");

  //
  // Search from the start of option ROM space to the end of the F0000 block
  // for the Ibv Compatability16 Table.
  //

  p.address = EGROUP_START_ADDRESS;
  while (TRUE) {
    if (p.address >= 0x100000) {
      DPRINTF_LEGACY ("  Couldn't find the IbvCompatibility16Table.\n");
      return NULL;
    }
    if (*p.puint32 == EFI_SIGNATURE_32 ('V', 'B', 'I', '$')) {
      IbvCompatibility16Table = p.pvoid;
      DPRINTF_LEGACY ("  Found the IbvCompatibility16Table @ 0x%x.\n",
        IbvCompatibility16Table);
      break;
    }
    p.address += 0x10;  // The table is page aligned.
  }

  DPRINTF_LEGACY ("  Found IbvCompatibility16Table @ 0x%x.\n", IbvCompatibility16Table);
  DPRINTF_LEGACY ("  IbvBbsSegment = 0x%x.\n", IbvCompatibility16Table->IbvBbsSegment);
  DPRINTF_LEGACY ("  IbvBbsOffset  = 0x%x.\n", IbvCompatibility16Table->IbvBbsOffset);

  return (IBV_BBS_TABLE*)(UINTN) (
    (IbvCompatibility16Table->IbvBbsSegment<<4) +
     IbvCompatibility16Table->IbvBbsOffset);
} // LegacyGetIbvBbs

//
// FUNCTION NAME.
//      ConstructDeviceTypeOrder - Fill in one of the Device Types for DevOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called to fill in one BBS index to one entry of the
//      legacy device order.
//      The device that we are trying to boot will be placed at the beginning,
//      except the BBS_EMBED_NETWORK device. This is because there is no mapping
//      for pxe lan device between efi Boot Manager and CSM16.
//
// ENTRY PARAMETERS.
//      BbsTable        - the specific BBS table.
//      BbsCount        - the specific BBS entry number of the BBS table.
//      BbsType         - the specific BBS table type, one of fill
//                        condition.
//      BbsTableIndex   - the BBS Table index value for current boot device.
//
// EXIT PARAMETERS.
//      Function Return - pointer to the byte after the filled buffer.
//      Buffer          - the output legacy device order Buffer.
//

UINT16 *
ConstructDeviceTypeOrder (
  IN BBS_TABLE *BbsTable,
  IN UINT8 BbsType,
  IN UINTN BbsCount,
  IN UINT16 *Buffer,
  IN int BbsTableIndex
  )
{
  UINTN Index;
  UINTN Count;
  UINT16 Temp;

  Count = 0;
  for (Index = 0; Index < BbsCount; Index++) {
    if ((BbsTable [Index].BootPriority == BBS_IGNORE_ENTRY) ||
        (BbsTable [Index].BootPriority == BBS_DO_NOT_BOOT_FROM)) {
      continue;
    }

    if (BbsTable [Index].DeviceType != BbsType) {
      continue;
    }

    Buffer [Count] = (UINT16)(Index & 0xFF);

    if (BbsType == BBS_HARDDISK) {
      if (Index == (UINTN)BbsTableIndex) {
        Temp = Buffer [0];
        Buffer [0] = Buffer [Count];
        Buffer [Count] = Temp;
        mSwappedIndex = Count;            // Remember which one we swapped.
      }
    }

    Count++;
  }

#if OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER

  //
  // Sort device according to BootOrder.
  //

  ArrangeDevOrderAccordingToBootOrder (Buffer, Count);

#endif // OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER

  return &Buffer [Count];
} // ConstructDeviceTypeOrder


//
// FUNCTION NAME.
//      CreateDevOrder - Create DevOrder in memory according to specific BBS table.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called to create the memory structure that contains the
//      default drive ordering for the legacy BBS devices. The device that we are
//      trying to boot will be placed at the beginning.
//
//      This function does not save the variable.
//
// ENTRY PARAMETERS.
//      BbsTable        - the specific BBS table.
//      BbsCount        - total BBS entry number of the specific BBS table.
//      BbsTableIndex   - the BBS Table index value for current boot device.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      DevOrderVariable - Points to returned legacy device boot order contents.
//      DevOrderSize    - Points to size of DevOrderVariable.
//

EFI_STATUS
CreateDevOrder (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsCount,
  IN int BbsTableIndex,
  OUT PVOID *DevOrderVariable,
  OUT PUINTN DevOrderSize
  )
{
  UINTN Index;
  UINTN FDCount;
  UINTN HDCount;
  UINTN CDCount;
  UINTN NETCount;
  UINTN BEVCount;
  UINTN TotalSize;
  UINTN HeaderSize;
  UINT8 *DevOrder;
  UINT8 *Ptr;

  FDCount = 0;
  HDCount = 0;
  CDCount = 0;
  NETCount = 0;
  BEVCount = 0;
  TotalSize = 0;
  HeaderSize = sizeof (UINT32) + sizeof (UINT16);
  DevOrder = NULL;
  Ptr = NULL;

  for (Index = 0; Index < BbsCount; Index++) {
    if ((BbsTable [Index].BootPriority == BBS_IGNORE_ENTRY) ||
        (BbsTable [Index].BootPriority == BBS_DO_NOT_BOOT_FROM)) {
      continue;
    }

    switch (BbsTable [Index].DeviceType) {
      case BBS_FLOPPY:
        FDCount++;
        break;

      case BBS_HARDDISK:
        HDCount++;
        break;

      case BBS_CDROM:
        CDCount++;
        break;

      case BBS_EMBED_NETWORK:
        NETCount++;
        break;

      case BBS_BEV_DEVICE:
        BEVCount++;
        break;

      default:
        break;
    }
  }

  TotalSize += (HeaderSize + sizeof (UINT16) * FDCount);
  TotalSize += (HeaderSize + sizeof (UINT16) * HDCount);
  TotalSize += (HeaderSize + sizeof (UINT16) * CDCount);
  TotalSize += (HeaderSize + sizeof (UINT16) * NETCount);
  TotalSize += (HeaderSize + sizeof (UINT16) * BEVCount);

  DevOrder = AllocateZeroPool (TotalSize);
  if (NULL == DevOrder) {
    return EFI_OUT_OF_RESOURCES;
  }

  Ptr = DevOrder;

  *((UINT32 *)Ptr) = BBS_FLOPPY;
  Ptr += sizeof (UINT32);
  *((UINT16 *)Ptr) = (UINT16)(sizeof (UINT16) + FDCount * sizeof (UINT16));
  Ptr += sizeof (UINT16);
  if (FDCount) {
    Ptr = (UINT8 *)ConstructDeviceTypeOrder (BbsTable, BBS_FLOPPY, BbsCount, (UINT16 *)Ptr, BbsTableIndex);
  }

  *((UINT32 *)Ptr) = BBS_HARDDISK;
  Ptr += sizeof (UINT32);
  *((UINT16 *)Ptr) = (UINT16)(sizeof (UINT16) + HDCount * sizeof (UINT16));
  Ptr += sizeof (UINT16);
  if (HDCount) {
    Ptr = (UINT8 *)ConstructDeviceTypeOrder (BbsTable, BBS_HARDDISK, BbsCount, (UINT16 *)Ptr, BbsTableIndex);
  }

  *((UINT32 *)Ptr) = BBS_CDROM;
  Ptr += sizeof (UINT32);
  *((UINT16 *)Ptr) = (UINT16)(sizeof (UINT16) + CDCount * sizeof (UINT16));
  Ptr += sizeof (UINT16);
  if (CDCount) {
    Ptr = (UINT8 *)ConstructDeviceTypeOrder (BbsTable, BBS_CDROM, BbsCount, (UINT16 *)Ptr, BbsTableIndex);
  }

  *((UINT32 *)Ptr) = BBS_EMBED_NETWORK;
  Ptr += sizeof (UINT32);
  *((UINT16 *)Ptr) = (UINT16)(sizeof (UINT16) + NETCount * sizeof (UINT16));
  Ptr += sizeof (UINT16);
  if (NETCount) {
    Ptr = (UINT8 *)ConstructDeviceTypeOrder (BbsTable, BBS_EMBED_NETWORK, BbsCount, (UINT16 *)Ptr, BbsTableIndex);
  }

  *((UINT32 *)Ptr) = BBS_BEV_DEVICE;
  Ptr += sizeof (UINT32);
  *((UINT16 *)Ptr) = (UINT16)(sizeof (UINT16) + BEVCount * sizeof (UINT16));
  Ptr += sizeof (UINT16);
  if (BEVCount) {
    Ptr = (UINT8 *)ConstructDeviceTypeOrder (BbsTable, BBS_BEV_DEVICE, BbsCount, (UINT16 *)Ptr, BbsTableIndex);
  }

  *DevOrderVariable = DevOrder;
  *DevOrderSize = TotalSize;
  return SCT_STATUS_SUCCESS;
} // CreateDevOrder

//
// FUNCTION NAME.
//      ProcessFdd - Process the FDD Entries in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes the BbsTable per the BbsOrder to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsTable        - pointer to the BbsTable.
//      BbsOrder        - an array of indexes into the BbsTable.
//      NumberOfBbsOrder - the number of elements in the BbsOrder array.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessFdd (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsOrder [],
  IN UINT8 NumberOfBbsOrder,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  UINT8 i;
  USB_DISK_TYPE *UsbDiskType;

  UsbFloppyDeviceCount = 0;
  UsbZipDeviceCount = 0;

  DPRINTF_LEGACY ("ProcessFdd:0x%x:", NumberOfBbsOrder);
  DEBUG_LEGACY (DUMP_WORDS (BbsOrder, NumberOfBbsOrder););
  DPRINTF_LEGACY ("\n");

  //
  // Process each entry in the DevOrder array.
  //

  RemovableSdmem = SDMEM_FDD_BOOT_START_INDEX;
  for (i = 0; i < NumberOfBbsOrder; i++) {

    if (BbsTable [BbsOrder [i]].DeviceType != BBS_FLOPPY) {
      DPRINTF_LEGACY ("BbsTable [0x%x] is not BBS_FLOPPY, is 0x%x.\n",
        BbsOrder [i],
        BbsTable [BbsOrder [i]].DeviceType);
      continue;
    }

    if ( i >= MAX_REMOVABLE_DEVICE_COUNT) {
      DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", i);
      continue;
    }

    if (BbsOrder [i] < BBS_SDMEM_RESERVATION_START_INDEX) {

      //
      // The BBS Table Entry is for a normal FDD.
      //

      if (BbsOrder [i] == 0) {
        IbvBbs->Removable_BootOrder [i] = 0;
      } else {
        IbvBbs->Removable_BootOrder [i] = 2;
      }

      BbsTable [BbsOrder [i]].IBV1 = (UINT32)IbvBbs->Removable_BootOrder [i];

    } else if (BbsOrder [i] < BBS_USB_RESERVATION_START_INDEX) {

      //
      // The BBS Table entry is for a SD-MEM device.
      //

      if (RemovableSdmem > SDMEM_FDD_BOOT_END_INDEX) {
        DPRINTF_LEGACY ("Index out of range for SDMEM, 0x%x", RemovableSdmem);
        continue;
      }

      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceType = BBS_SDMEM_FDD_DEVICE_TYPE;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceOrderIndex = \
        RemovableSdmem;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.BusNumber = \
        (UINT16)(BbsTable [BbsOrder [i]].Bus);
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.DeviceNumber = \
        (UINT16)(BbsTable [BbsOrder [i]].Device);
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.FunctionNumber = \
        (UINT16)(BbsTable [BbsOrder [i]].Function);
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoLUN = 0xFF;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoParentHubIndex = 0xFF;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPhyIDPort = \
        (UINT8) (BbsOrder [i] & 0xFF) - BBS_SDMEM_RESERVATION_START_INDEX;

      IbvBbs->Removable_BootOrder [i] = RemovableSdmem;
      RemovableSdmem++;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)IbvBbs->Removable_BootOrder [i];

    } else {

      //
      // Check if this BBS Table entry is a USB Floppy device first.
      //


      UsbDiskType = (USB_DISK_TYPE *)&BbsTable [BbsOrder [i]].InitPerReserved;
      if (UsbDiskType->BbsType != BBS_USB) {
        continue;
      }

      if (UsbDiskType->DeviceType == BBS_USB_UFI_FDD_DEVICE_TYPE) {
        DPRINTF_LEGACY (" USB_UFI_FDD_DEVICE_TYPE \n");
        IbvBbs->Removable_BootOrder [i] = \
          USBFDD_BOOT_START_INDEX \
          + (UINT8) (BbsOrder [i] & 0xff) \
          - BBS_USB_FLOPPY_START_INDEX \
          - UsbZipDeviceCount;
        UsbFloppyDeviceCount += 1;

      } else if (UsbDiskType->DeviceType == BBS_USB_BULK_ZIP_FDD_DEVICE_TYPE) {
        DPRINTF_LEGACY (" USB_BULK_ZIP_FDD_DEVICE_TYPE \n");
        IbvBbs->Removable_BootOrder [i] = \
          USBZIP_BOOT_START_INDEX \
          + (UINT8) (BbsOrder [i] & 0xff) \
          - BBS_USB_FLOPPY_START_INDEX \
          - UsbFloppyDeviceCount;
        UsbZipDeviceCount += 1;

      }

      BbsTable [BbsOrder [i]].IBV1 = (UINT32)IbvBbs->Removable_BootOrder [i];
    }
  }

  return SCT_STATUS_SUCCESS;
} // ProcessFdd

//
// FUNCTION NAME.
//      ProcessHdd - Process the HDD Entries in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes the BbsTable per the BbsOrder to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsTable        - pointer to the BbsTable.
//      BbsOrder        - an array of indexes into the BbsTable.
//      NumberOfBbsOrder - the number of elements in the BbsOrder array.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessHdd (
  IN BBS_TABLE *BbsTable,
  IN HDD_INFO *HddInfo,
  IN UINT16 HddCount,
  IN UINT16 BbsOrder [],
  IN UINT8 NumberOfBbsOrder,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  UINTN i, a, b;
  UINT8 c, d;
  UINT32 IdeDiskInfoHddStartIndex;
  UINT32 Index;
  UINT32 Index2;
  UINT16 HddInfoIndex;
  DISK_INFORMATION TempDiskInfo;

  DPRINTF_LEGACY ("ProcessHdd:0x%x:", NumberOfBbsOrder);
  DEBUG_LEGACY (DUMP_WORDS (BbsOrder, NumberOfBbsOrder););
  DPRINTF_LEGACY ("\n");

  IdeDiskInfoHddStartIndex = IdeInfo;
  HardDiskIde = IDE_HDD_BOOT_START_INDEX;
  HardDiskScsi = SCSIHDD_BOOT_START_INDEX;
  HardDiskAhci = AHCIHDD_BOOT_START_INDEX;
  HardDiskNvme = NVMEHDD_BOOT_START_INDEX;

  for (i = 0; i < NumberOfBbsOrder; i++) {

    if (BbsTable [BbsOrder [i]].DeviceType != BBS_HARDDISK) {
      DPRINTF_LEGACY (
        "  BbsTable [0x%x] is not BBS_HARDDISK, is 0x%x.\n",
        BbsOrder [i],
        BbsTable [BbsOrder [i]].DeviceType);
      continue;
    }

    if ( i >= MAX_HDD_DEVICE_COUNT) {
      DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", i);
      continue;
    }

    if (BbsOrder [i] < BBS_SCSIHDD_START_INDEX) {
      DPRINTF_LEGACY ("  IDE HDD.\n");

      //
      // The BBS Table entry is for IDE HDD.
      //

      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceOrderIndex = HardDiskIde;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsTable [BbsOrder [i]].Bus);
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsTable [BbsOrder [i]].Device);
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.FunctionNumber =
        (UINT16)(BbsTable [BbsOrder [i]].Function);
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoLUN = 0xFF;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoParentHubIndex = 0xFF;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoReserved = (UINT8) (BbsOrder [i] & 0xFF);

      HddInfoIndex = (BbsOrder [i] - 1) / 2;
      if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsOrder [i] - 1) % 2 == 0)) {
        DPRINTF_LEGACY ("  Primary Master.\n");
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 0;
      } else if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsOrder [i] - 1) % 2 == 1)){
        DPRINTF_LEGACY ("  Primary Slave.\n");
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 1;
      } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsOrder [i] - 1) % 2 == 0)){
        DPRINTF_LEGACY ("  Secondary Master.\n");
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 2;
      } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsOrder [i] - 1) % 2 == 1)){
        DPRINTF_LEGACY ("  Secondary Slave.\n");
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 3;
      }

      IbvBbs->HardDisk_BootOrder [i] = HardDiskIde;
      HardDiskIde++;
      IdeInfo++;

    } else if (BbsOrder [i] < BBS_AHCI_HARDDISK_START_INDEX) {

      DPRINTF_LEGACY ("  SCSI HDD.\n");


      //
      // The BBS Table entry is for SCSI HDD.
      //

      IbvBbs->HardDisk_BootOrder [i] = HardDiskScsi;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)HardDiskScsi;
      HardDiskScsi++;

    } else if (BbsOrder [i] < BBS_NVME_HARDDISK_START_INDEX) {

      DPRINTF_LEGACY ("  AHCI HDD.\n");

      //
      // The BBS Table entry is for AHCI HDD.
      //

#if OPTION_SUPPORT_AHCI_NATIVE

      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceOrderIndex = HardDiskAhci;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsTable [BbsOrder [i]].Bus);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsTable [BbsOrder [i]].Device);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.FunctionNumber =
        (UINT16)(BbsTable [BbsOrder [i]].Function);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoLUN = 0xFF;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoParentHubIndex = 0xFF;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoReserved = (UINT8)(BbsOrder [i] & 0xFF);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPhyIDPort = (UINT8)(BbsTable [BbsOrder [i]].IBV2);

#endif // OPTION_SUPPORT_AHCI_NATIVE

      IbvBbs->HardDisk_BootOrder [i] = HardDiskAhci;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)HardDiskAhci;
      HardDiskAhci++;
      AhciInfo++;

    } else if (BbsOrder [i] < BBS_SDMEM_RESERVATION_START_INDEX) {

      DPRINTF_LEGACY ("  NVME HDD.\n");

      //
      // The BBS Table entry is for NVME HDD.
      //

//#if OPTION_SUPPORT_NVME_NATIVE

      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoDeviceOrderIndex = HardDiskNvme;
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsTable [BbsOrder [i]].Bus);
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsTable [BbsOrder [i]].Device);
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPFA.PFA.FunctionNumber =
        (UINT16)(BbsTable [BbsOrder [i]].Function);
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoLUN = 0xFF;
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoParentHubIndex = 0xFF;
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoReserved = (UINT8)(BbsOrder [i] & 0xFF);
      IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPhyIDPort = (UINT8)(BbsTable [BbsOrder [i]].IBV2);

//#endif // OPTION_SUPPORT_NVME_NATIVE

      IbvBbs->HardDisk_BootOrder [i] = HardDiskNvme;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)HardDiskNvme;
      HardDiskNvme++;
      NvmeInfo++;

    } else if (BbsOrder [i] < BBS_USB_RESERVATION_START_INDEX) {

      DPRINTF_LEGACY ("  SD-Memory HDD.\n");

      //
      // The BBS Table Entry is for SD-Memory HDD.
      //

      HardDiskSdmem = (UINT8)(SDMEM_HDD_BOOT_START_INDEX + (BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX));

      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceType = BBS_SDMEM_HDD_DEVICE_TYPE;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceOrderIndex = \
        HardDiskSdmem;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.BusNumber = \
        (UINT16)(BbsTable [BbsOrder [i]].Bus);
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.DeviceNumber = \
        (UINT16)(BbsTable [BbsOrder [i]].Device);
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.FunctionNumber = \
        (UINT16)(BbsTable [BbsOrder [i]].Function);
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoLUN = 0xFF;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoParentHubIndex = 0xFF;
      IbvBbs->SdmemDiskInfo [BbsOrder [i] - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPhyIDPort = HardDiskSdmem;
      IbvBbs->HardDisk_BootOrder [i] = HardDiskSdmem;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)HardDiskSdmem;

    } else {

      DPRINTF_LEGACY ("  USB HDD.\n");

      //
      // The BBS Table entry is for USB HDD.
      //

      IbvBbs->HardDisk_BootOrder [i] = USBHDD_BOOT_START_INDEX + (UINT8)(BbsOrder [i] & 0xFF) - BBS_USB_HARDDISK_START_INDEX;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)IbvBbs->HardDisk_BootOrder [i];
    }
  }

  //
  // Now re-parse all the IdeInfo entries that this function setup to make sure
  // that they are in the correct order.
  //    1. PFA (from small to large).
  //    2. Primary to Secondary.
  //    3. Master to Slave.
  //

  for (Index = IdeDiskInfoHddStartIndex;
       Index < HardDiskIde + IdeDiskInfoHddStartIndex; Index++) {
    for (Index2 = 0; Index2 < Index; Index2++) {
      if ((IbvBbs->IdeDiskInfo [Index2].DiskInfoPFA.PfaValue > IbvBbs->IdeDiskInfo [Index].DiskInfoPFA.PfaValue) ||
         ((IbvBbs->IdeDiskInfo [Index2].DiskInfoPFA.PfaValue == IbvBbs->IdeDiskInfo [Index].DiskInfoPFA.PfaValue) &&
         (IbvBbs->IdeDiskInfo [Index2].DiskInfoPhyIDPort > IbvBbs->IdeDiskInfo [Index].DiskInfoPhyIDPort))){
            DPRINTF_LEGACY ("  Swap IdeDiskInfo [%d] with IdeDiskInfo [%d].\n", Index, Index2);
            TempDiskInfo = IbvBbs->IdeDiskInfo [Index2];
            IbvBbs->IdeDiskInfo [Index2] = IbvBbs->IdeDiskInfo [Index];
            IbvBbs->IdeDiskInfo [Index] = TempDiskInfo;
      }
    }
  }

  for (Index = IdeDiskInfoHddStartIndex;
       Index < HardDiskIde + IdeDiskInfoHddStartIndex; Index++) {
    for (Index2 = 0; Index2 < MAX_HDD_DEVICE_COUNT; Index2++) {
      if ((IbvBbs->HardDisk_BootOrder [Index2] == IbvBbs->IdeDiskInfo [Index].DiskInfoDeviceOrderIndex)) {
        DPRINTF_LEGACY ("  IbvBbs->HardDisk_BootOrder [Index2] == IbvBbs->IdeDiskInfo [Index].DiskInfoDeviceOrderIndex.\n");
        DPRINTF_LEGACY ("  Index = 0x%x.\n", Index);
        DPRINTF_LEGACY ("  Index2 = 0x%x.\n", Index2);
        DPRINTF_LEGACY ("  IbvBbs->HardDisk_BootOrder [Index2] = 0x%x.\n", IbvBbs->HardDisk_BootOrder [Index2]);
        IbvBbs->IdeDiskInfo [Index].DiskInfoDeviceOrderIndex = (UINT8)Index;
        IbvBbs->HardDisk_BootOrder [Index2] = (UINT8)Index;
        BbsTable [IbvBbs->IdeDiskInfo [Index].DiskInfoReserved].IBV1 = (UINT32)IbvBbs->HardDisk_BootOrder [Index2];
      }
    }
  }

  //
  // If we swapped in CreateDevOrder, swap here to compensate.
  //

  if (mSwappedIndex != 0) {

      for (i = 0; i <= mSwappedIndex; i++ ) {

        //
        // Swapping only for serial SCSI HDDs.
        //

        if ((BbsOrder [i] < BBS_SCSIHDD_START_INDEX) ||
            (BbsOrder [i] >= BBS_AHCI_HARDDISK_START_INDEX)) {
          return SCT_STATUS_SUCCESS;
        }
      }

      a = BbsOrder [0];
      b = BbsOrder [mSwappedIndex];
      c = IbvBbs->HardDisk_BootOrder [0];
      d = IbvBbs->HardDisk_BootOrder [mSwappedIndex];

      //
      // Only swap if we are out of order.
      //
      if ( (a > b && c < d) || (a < b && c > d) ) {
          DPRINTF_LEGACY ("  Swapping IbvBbs->HardDisk_BootOrder [%d](%x) and [%d](%x) to match BbsOrder\n", 0, c, mSwappedIndex, d);
          IbvBbs->HardDisk_BootOrder [0] = d;
          IbvBbs->HardDisk_BootOrder [mSwappedIndex] = c;
          BbsTable [BbsOrder [0]].IBV1 = d;
          BbsTable [BbsOrder [mSwappedIndex]].IBV1 = c;
      } else {
          DPRINTF_LEGACY ("  Not swapping IbvBbs->HardDisk_BootOrder [%d](%x) and [%d](%x), already ok\n", 0, c, mSwappedIndex, d);
      }
    mSwappedIndex = 0;                   // Clear swap-flag since we consumed it.
  }

  return SCT_STATUS_SUCCESS;
} // ProcessHdd


//
// FUNCTION NAME.
//      ProcessCdrom - Process the CDROM Entries in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes the BbsTable per the BbsOrder to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsTable        - pointer to the BbsTable.
//      BbsOrder        - an array of indexes into the BbsTable.
//      NumberOfBbsOrder - the number of elements in the BbsOrder array.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessCdrom (
  IN BBS_TABLE *BbsTable,
  IN HDD_INFO *HddInfo,
  IN UINT16 HddCount,
  IN UINT16 BbsOrder [],
  IN UINT8 NumberOfBbsOrder,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  UINT8 i;
  UINT16 HddInfoIndex;

  UINT32 IdeDiskInfoCdromStartIndex;
  UINT32 Index;
  UINT32 Index2;
  DISK_INFORMATION TempDiskInfo;

  DPRINTF_LEGACY ("ProcessCdrom:0x%x:", NumberOfBbsOrder);
  DEBUG_LEGACY (DUMP_WORDS (BbsOrder, NumberOfBbsOrder););
  DPRINTF_LEGACY ("\n");

  IdeDiskInfoCdromStartIndex = IdeInfo;
  CdromIde = IDE_CDROM_BOOT_START_INDEX;
  CdromUsb = USBCDROM_BOOT_START_INDEX;
  CdromAhci = AHCICDROM_BOOT_START_INDEX;

  for (i = 0; i < NumberOfBbsOrder; i++) {

    if (BbsTable [BbsOrder [i]].DeviceType != BBS_CDROM) {
      DPRINTF_LEGACY (
        "  BbsTable [0x%x] is not BBS_CDROM, is 0x%x.\n",
        BbsOrder [i],
        BbsTable [BbsOrder [i]].DeviceType);
      continue;
    }

    if ( i >= MAX_CDROM_DEVICE_COUNT) {
      DPRINTF_LEGACY ("  Out of space in group, 0x%x is too large.\n",i);
      continue;
    }

    if (BbsOrder [i] < BBS_SCSIHDD_START_INDEX) {

      DPRINTF_LEGACY ("  IDE CDROM.\n");

      //
      // This BbsTable entry is for an IDE CDROM.
      //

      if (CdromIde > IDE_CDROM_BOOT_END_INDEX) {
        DPRINTF_LEGACY ("  Out of indexes for IDE CDROM drives.\n");
        continue;
      }

      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceType = BBS_IDE_CDROM_DEVICE_TYPE;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceOrderIndex = CdromIde;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsTable [BbsOrder [i]].Bus);
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsTable [BbsOrder [i]].Device);
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.FunctionNumber = (UINT16)(BbsTable [BbsOrder [i]].Function);
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoLUN = 0xFF;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoParentHubIndex = 0xFF;
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoReserved = (UINT8)(BbsOrder [i] & 0xFF);

      HddInfoIndex = (BbsOrder [i] - 1) / 2;
      if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsOrder [i] - 1) % 2 == 0)) {
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 0;
      } else if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsOrder [i] - 1) % 2 == 1)){
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 1;
      } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsOrder [i] - 1) % 2 == 0)){
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 2;
      } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsOrder [i] - 1) % 2 == 1)){
        IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 3;
      }

      IbvBbs->CDROM_BootOrder [i] = CdromIde;
      CdromIde++;
      IdeInfo++;

    } else if (BbsOrder [i] < BBS_SDMEM_RESERVATION_START_INDEX) {

      DPRINTF_LEGACY ("  AHCI CDROM.\n");

      //
      // The BBS Table entry is for AHCI CDROM.
      //

#if OPTION_SUPPORT_AHCI_NATIVE

      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceType = BBS_IDE_CDROM_DEVICE_TYPE;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceOrderIndex = CdromAhci;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsTable [BbsOrder [i]].Bus);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsTable [BbsOrder [i]].Device);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.FunctionNumber =
        (UINT16)(BbsTable [BbsOrder [i]].Function);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoLUN = 0xFF;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoParentHubIndex = 0xFF;
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoReserved = (UINT8)(BbsOrder [i] & 0xFF);
      IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPhyIDPort = (UINT8)(BbsTable [BbsOrder [i]].IBV2);

#endif // OPTION_SUPPORT_AHCI_NATIVE

      IbvBbs->CDROM_BootOrder [i] = CdromAhci;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)CdromAhci;
      CdromAhci++;
      AhciInfo++;

    } else if (BbsOrder [i] < BBS_USB_CDROM_START_INDEX) {

      DPRINTF_LEGACY (
        "  BbsTable [0x%x] says it is a CDROM but the index is out of range.\n",
        BbsOrder [i]);
      continue;

    } else {

      DPRINTF_LEGACY ("  USB CDROM.\n");

      //
      // This BbsTable entry is for a USB CDROM.
      //

      CdromUsb = USBCDROM_BOOT_START_INDEX + (UINT8) (BbsOrder [i] & 0xFF) - BBS_USB_CDROM_START_INDEX;
      if ((CdromUsb < USBCDROM_BOOT_START_INDEX) || (CdromUsb > USBCDROM_BOOT_END_INDEX)) {
        DPRINTF_LEGACY ("  USB CDROM INDEX is out of range, 0x%x.\n", CdromUsb);
        continue;
      }

      IbvBbs->CDROM_BootOrder [i] = CdromUsb;
      BbsTable [BbsOrder [i]].IBV1 = (UINT32)CdromUsb;
    }
  }

  //
  // Now re-parse all the IdeInfo entries that this function setup to make sure
  // that they are in the correct order.
  //    1. PFA (from small to large).
  //    2. Primary to Secondary
  //    3. Master to Slave.
  //

  for (Index = IdeDiskInfoCdromStartIndex;
       Index < CdromIde + IdeDiskInfoCdromStartIndex;
       Index++) {

    for (Index2 = IdeDiskInfoCdromStartIndex; Index2 < Index; Index2++) {
      if ((IbvBbs->IdeDiskInfo [Index2].DiskInfoPFA.PfaValue > IbvBbs->IdeDiskInfo [Index].DiskInfoPFA.PfaValue) ||
         ((IbvBbs->IdeDiskInfo [Index2].DiskInfoPFA.PfaValue == IbvBbs->IdeDiskInfo [Index].DiskInfoPFA.PfaValue) &&
         (IbvBbs->IdeDiskInfo [Index2].DiskInfoPhyIDPort > IbvBbs->IdeDiskInfo [Index].DiskInfoPhyIDPort))){
        TempDiskInfo = IbvBbs->IdeDiskInfo [Index2];
        IbvBbs->IdeDiskInfo [Index2] = IbvBbs->IdeDiskInfo [Index];
        IbvBbs->IdeDiskInfo [Index] = TempDiskInfo;
      }
    }
  }

  for (Index = IdeDiskInfoCdromStartIndex;
       Index < CdromIde + IdeDiskInfoCdromStartIndex; Index++) {

    for (Index2 = 0; Index2 < MAX_CDROM_DEVICE_COUNT; Index2++) {
      if ((IbvBbs->CDROM_BootOrder [Index2] == IbvBbs->IdeDiskInfo [Index].DiskInfoDeviceOrderIndex)) {
        IbvBbs->IdeDiskInfo [Index].DiskInfoDeviceOrderIndex = (UINT8)(Index - IdeDiskInfoCdromStartIndex);
        IbvBbs->CDROM_BootOrder [Index2] = (UINT8)(Index - IdeDiskInfoCdromStartIndex);
        BbsTable [IbvBbs->IdeDiskInfo [Index].DiskInfoReserved].IBV1 = (UINT32) IbvBbs->CDROM_BootOrder [Index2];
      }
    }
  }

  return SCT_STATUS_SUCCESS;
} // ProcessCdrom


//
// FUNCTION NAME.
//      ProcessNet - Process the NET Entries in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes the BbsTable per the BbsOrder to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsTable        - pointer to the BbsTable.
//      BbsOrder        - an array of indexes into the BbsTable.
//      NumberOfBbsOrder - the number of elements in the BbsOrder array.
//
// EXIT PARAMETERS.
//      IbvBbs          - pointer to the IbvBbs table that is updated.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
ProcessNet (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsOrder [],
  IN UINT8 NumberOfBbsOrder,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  UINT8 i;

  DPRINTF_LEGACY ("ProcessNet:0x%x:", NumberOfBbsOrder);
  DEBUG_LEGACY (DUMP_WORDS (BbsOrder, NumberOfBbsOrder););
  DPRINTF_LEGACY ("\n");

  for (i = 0; i < NumberOfBbsOrder; i++) {

    if (BbsTable [BbsOrder [i]].DeviceType != BBS_EMBED_NETWORK) {
      DPRINTF_LEGACY ("BbsTable [0x%x] is not BBS_EMBED_NETWORK, is 0x%x.\n",
        BbsOrder [i],
        BbsTable [BbsOrder [i]].DeviceType);
      continue;
    }

    if ( i >= MAX_LAN_COUNT) {
      DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", i);
      continue;
    }

    IbvBbs->LAN_BootOrder [i] = i + LAN_BOOT_START_INDEX;

  }

  return SCT_STATUS_SUCCESS;
} // ProcessNet


//
// FUNCTION NAME.
//      ProcessBev - Process the BEV Entries in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes the BbsTable per the BbsOrder to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsTable        - pointer to the BbsTable.
//      BbsOrder        - an array of indexes into the BbsTable.
//      NumberOfBbsOrder - the number of elements in the BbsOrder array.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessBev (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsOrder [],
  IN UINT8 NumberOfBbsOrder,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  UINT8 i;

  DPRINTF_LEGACY ("ProcessBev:0x%x:", NumberOfBbsOrder);
  DEBUG_LEGACY (DUMP_WORDS (BbsOrder, NumberOfBbsOrder););
  DPRINTF_LEGACY ("\n");

  for (i = 0; i < NumberOfBbsOrder; i++) {

    if (BbsTable [BbsOrder [i]].DeviceType != BBS_BEV_DEVICE) {
      DPRINTF_LEGACY (
        "  BbsTable [0x%x] is not BBS_BEV_DEVICE, is 0x%x.\n",
        BbsOrder [i],
        BbsTable [BbsOrder [i]].DeviceType);
      continue;
    }

    if ( i >= MAX_BEV_COUNT) {
      DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", i);
      continue;
    }

    IbvBbs->BEV_BootOrder [i] = i + BEV_BOOT_START_INDEX;
    BbsTable [BbsOrder [i]].IBV1 = (UINT32)IbvBbs->BEV_BootOrder [i] ;
  }

  return SCT_STATUS_SUCCESS;
} // ProcessBev

#if OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER

//
// FUNCTION NAME.
//      ProcessOneFdd - Process a FDD Entry in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes a FDD entry in the BbsTable to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsEntry        - A pointer to this FDD entry in the BbsTable.
//      BbsIndex        - A index value that this FDD entry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessOneFdd (
  IN BBS_TABLE *BbsEntry,
  IN UINT16 BbsIndex,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  USB_DISK_TYPE *UsbDiskType;

  DPRINTF_LEGACY ("ProcessOneFdd:0x%x:", RemovableDeviceCount);
  DPRINTF_LEGACY ("\n");

  //
  // Process each entry in the DevOrder array.
  //

  if ( RemovableDeviceCount >= MAX_REMOVABLE_DEVICE_COUNT) {
    DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", RemovableDeviceCount);
    return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
  }

  if (BbsIndex < BBS_SDMEM_RESERVATION_START_INDEX) {

    //
    // The BBS Table Entry is for a normal FDD.
    //

    if (BbsIndex == 0) {
      IbvBbs->Removable_BootOrder [RemovableDeviceCount] = 0;
    } else {
      IbvBbs->Removable_BootOrder [RemovableDeviceCount] = 2;
    }

    BbsEntry->IBV1 = (UINT32)IbvBbs->Removable_BootOrder [RemovableDeviceCount];

  } else if (BbsIndex < BBS_USB_RESERVATION_START_INDEX) {

    //
    // The BBS Table entry is for a SD-MEM device.
    //

    if (RemovableSdmem > SDMEM_FDD_BOOT_END_INDEX) {
      DPRINTF_LEGACY ("Index out of range for SDMEM, 0x%x", RemovableSdmem);
      return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
    }

    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceType = BBS_SDMEM_FDD_DEVICE_TYPE;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceOrderIndex = \
      RemovableSdmem;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.BusNumber = \
      (UINT16)(BbsEntry->Bus);
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.DeviceNumber = \
      (UINT16)(BbsEntry->Device);
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.FunctionNumber = \
      (UINT16)(BbsEntry->Function);
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoLUN = 0xFF;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoParentHubIndex = 0xFF;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPhyIDPort = \
      (UINT8) (BbsIndex & 0xFF) - BBS_SDMEM_RESERVATION_START_INDEX;

    IbvBbs->Removable_BootOrder [RemovableDeviceCount] = RemovableSdmem;
    RemovableSdmem++;
    BbsEntry->IBV1 = (UINT32)IbvBbs->Removable_BootOrder [RemovableDeviceCount];

  } else {

    //
    // Check if this BBS Table entry is a USB Floppy device first.
    //


    UsbDiskType = (USB_DISK_TYPE *)&BbsEntry->InitPerReserved;
    if (UsbDiskType->BbsType != BBS_USB) {
      return SCT_STATUS_INVALID_PARAMETER;
    }

    if (UsbDiskType->DeviceType == BBS_USB_UFI_FDD_DEVICE_TYPE) {

      DPRINTF_LEGACY (" USB_UFI_FDD_DEVICE_TYPE \n");
      IbvBbs->Removable_BootOrder [RemovableDeviceCount] = \
        USBFDD_BOOT_START_INDEX \
        + (UINT8) (BbsIndex & 0xff) \
        - BBS_USB_FLOPPY_START_INDEX \
        - UsbZipDeviceCount;
      UsbFloppyDeviceCount += 1;

    } else if (UsbDiskType->DeviceType == BBS_USB_BULK_ZIP_FDD_DEVICE_TYPE) {

      DPRINTF_LEGACY (" USB_BULK_ZIP_FDD_DEVICE_TYPE \n");
      IbvBbs->Removable_BootOrder [RemovableDeviceCount] = \
        USBZIP_BOOT_START_INDEX \
        + (UINT8) (BbsIndex & 0xff) \
        - BBS_USB_FLOPPY_START_INDEX \
        - UsbFloppyDeviceCount;
      UsbZipDeviceCount += 1;

    }

    BbsEntry->IBV1 = (UINT32)IbvBbs->Removable_BootOrder [RemovableDeviceCount];
  }

  RemovableDeviceCount += 1;

  return SCT_STATUS_SUCCESS;
} // ProcessOneFdd

//
// FUNCTION NAME.
//      ProcessOneHdd - Process a HDD Entry in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes a HDDD entry in the BbsTable to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsEntry        - A pointer to this HDD entry in the BbsTable.
//      BbsIndex        - A index value that this HDD entry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessOneHdd (
  IN BBS_TABLE *BbsEntry,
  IN UINT16 BbsIndex,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  UINT16 HddCount;
  UINT16 BbsCount;
  SCT_STATUS Status;
  HDD_INFO *HddInfo;
  BBS_TABLE *BbsTable;
  UINT16 HddInfoIndex;
  UINTN i;

  DPRINTF_LEGACY ("ProcessHdd:0x%x:", HardDiskDeviceCount);
  DPRINTF_LEGACY ("\n");

  if ( HardDiskDeviceCount >= MAX_HDD_DEVICE_COUNT) {
    DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", HardDiskDeviceCount);
    return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
  }

  BbsTable = NULL;
  Status = mLegacyBios->GetBbsInfo (
                          mLegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          &BbsTable);

  if (BbsIndex < BBS_SCSIHDD_START_INDEX) {
    DPRINTF_LEGACY ("  IDE HDD.\n");

    //
    // The BBS Table entry is for IDE HDD.
    //

    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceOrderIndex = HardDiskIde;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsEntry->Bus);
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsEntry->Device);
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.FunctionNumber = (UINT16)(BbsEntry->Function);
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoLUN = 0xFF;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoParentHubIndex = 0xFF;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoReserved = (UINT8) (BbsIndex & 0xFF);

    if (BbsTable == NULL) {
      DPRINTF_LEGACY ("  GetBbsInfo fail \n");
      return EFI_NOT_FOUND;
    }

    HddInfoIndex = (BbsIndex - 1) / 2;
    if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsIndex - 1) % 2 == 0)) {
      DPRINTF_LEGACY ("  Primary Master.\n");
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 0;
    } else if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsIndex - 1) % 2 == 1)){
      DPRINTF_LEGACY ("  Primary Slave.\n");
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 1;
    } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsIndex - 1) % 2 == 0)){
      DPRINTF_LEGACY ("  Secondary Master.\n");
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 2;
    } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsIndex - 1) % 2 == 1)){
      DPRINTF_LEGACY ("  Secondary Slave.\n");
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 3;
    }

    IbvBbs->HardDisk_BootOrder [HardDiskDeviceCount] = HardDiskIde;
    HardDiskIde++;
    IdeInfo++;

  } else if (BbsIndex < BBS_AHCI_HARDDISK_START_INDEX) {

    DPRINTF_LEGACY ("  SCSI HDD.\n");

    //
    // Calculate the order number of current SCSI HDD.
    //

    if (BbsTable == NULL) {
      DPRINTF_LEGACY ("  GetBbsInfo fail \n");
      return EFI_NOT_FOUND;
    }

    for (i = BBS_SCSIHDD_START_INDEX; i < BbsIndex; i++) {
      if (BbsTable [i].DeviceType == BBS_HARDDISK) {
        HardDiskScsi++;
      }
    }

    //
    // The BBS Table entry is for SCSI HDD.
    //

    IbvBbs->HardDisk_BootOrder [HardDiskDeviceCount] = HardDiskScsi;
    BbsEntry->IBV1 = (UINT32)HardDiskScsi;
    HardDiskScsi++;

  } else if (BbsIndex < BBS_NVME_HARDDISK_START_INDEX) {

    DPRINTF_LEGACY ("  AHCI HDD.\n");

    //
    // The BBS Table entry is for AHCI HDD.
    //

#if OPTION_SUPPORT_AHCI_NATIVE

    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceOrderIndex = HardDiskAhci;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsEntry->Bus);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsEntry->Device);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.FunctionNumber =
      (UINT16)(BbsEntry->Function);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoLUN = 0xFF;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoParentHubIndex = 0xFF;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoReserved = (UINT8)(BbsIndex & 0xFF);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPhyIDPort = (UINT8)(BbsEntry->IBV2);

#endif // OPTION_SUPPORT_AHCI_NATIVE

    IbvBbs->HardDisk_BootOrder [HardDiskDeviceCount] = HardDiskAhci;
    BbsEntry->IBV1 = (UINT32)HardDiskAhci;
    HardDiskAhci++;
    AhciInfo++;

  } else if (BbsIndex < BBS_SDMEM_RESERVATION_START_INDEX) {

    DPRINTF_LEGACY ("  NVME HDD.\n");

    //
    // The BBS Table entry is for NVME HDD.
    //

#if OPTION_SUPPORT_NVME_NATIVE

    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoDeviceType = BBS_IDE_HDD_DEVICE_TYPE;
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoDeviceOrderIndex = HardDiskNvme;
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsEntry->Bus);
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsEntry->Device);
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPFA.PFA.FunctionNumber =
      (UINT16)(BbsEntry->Function);
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoLUN = 0xFF;
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoParentHubIndex = 0xFF;
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoReserved = (UINT8)(BbsIndex & 0xFF);
    IbvBbs->NvmeDiskInfo [NvmeInfo].DiskInfoPhyIDPort = (UINT8)(BbsEntry->IBV2);

#endif // OPTION_SUPPORT_NVME_NATIVE

    IbvBbs->HardDisk_BootOrder [HardDiskDeviceCount] = HardDiskNvme;
    BbsEntry->IBV1 = (UINT32)HardDiskNvme;
    HardDiskNvme++;
    NvmeInfo++;
    DPRINTF_LEGACY ("  NVME HDD: end.\n");
  } else if (BbsIndex < BBS_USB_RESERVATION_START_INDEX) {

    DPRINTF_LEGACY ("  SD-Memory HDD.\n");

    //
    // The BBS Table Entry is for SD-Memory HDD.
    //

    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceType = BBS_SDMEM_HDD_DEVICE_TYPE;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoDeviceOrderIndex = \
      HardDiskSdmem;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.BusNumber = \
      (UINT16)(BbsEntry->Bus);
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.DeviceNumber = \
      (UINT16)(BbsEntry->Device);
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPFA.PFA.FunctionNumber = \
      (UINT16)(BbsEntry->Function);
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoLUN = 0xFF;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoParentHubIndex = 0xFF;
    IbvBbs->SdmemDiskInfo [BbsIndex - BBS_SDMEM_RESERVATION_START_INDEX].DiskInfoPhyIDPort = HardDiskSdmem;
    IbvBbs->HardDisk_BootOrder [HardDiskDeviceCount] = HardDiskSdmem;
    BbsEntry->IBV1 = (UINT32)HardDiskSdmem;
    HardDiskSdmem++;

  } else {

    DPRINTF_LEGACY ("  USB HDD.\n");

    //
    // The BBS Table entry is for USB HDD.
    //

    IbvBbs->HardDisk_BootOrder [HardDiskDeviceCount] = USBHDD_BOOT_START_INDEX + (UINT8)(BbsIndex & 0xFF) - BBS_USB_HARDDISK_START_INDEX;
    BbsEntry->IBV1 = (UINT32)IbvBbs->HardDisk_BootOrder [HardDiskDeviceCount];
  }

  HardDiskDeviceCount++;

  return SCT_STATUS_SUCCESS;
} // ProcessOneHdd


//
// FUNCTION NAME.
//      ProcessOneCdrom - Process a CDROM Entry in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes a CDROM entry in the BbsTable to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsEntry        - A pointer to this CDROM entry in the BbsTable.
//      BbsIndex        - A index value that this CDROM entry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessOneCdrom (
  IN BBS_TABLE *BbsEntry,
  IN UINT16 BbsIndex,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  UINT16 HddCount;
  UINT16 BbsCount;
  SCT_STATUS Status;
  HDD_INFO *HddInfo;
  UINT16 HddInfoIndex;
  BBS_TABLE *BbsTable;

  DPRINTF_LEGACY ("ProcessOneCdrom:0x%x:", CdromDeviceCount);
  DPRINTF_LEGACY ("\n");

  if ( CdromDeviceCount >= MAX_CDROM_DEVICE_COUNT) {
    DPRINTF_LEGACY ("  Out of space in group, 0x%x is too large.\n",CdromDeviceCount);
    return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
  }

  if (BbsIndex < BBS_SCSIHDD_START_INDEX) {

    DPRINTF_LEGACY ("  IDE CDROM.\n");

    //
    // This BbsTable entry is for an IDE CDROM.
    //

    if (CdromIde > IDE_CDROM_BOOT_END_INDEX) {
      DPRINTF_LEGACY ("  Out of indexes for IDE CDROM drives.\n");
      return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
    }

    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceType = BBS_IDE_CDROM_DEVICE_TYPE;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoDeviceOrderIndex = CdromIde;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsEntry->Bus);
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsEntry->Device);
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPFA.PFA.FunctionNumber = (UINT16)(BbsEntry->Function);
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoLUN = 0xFF;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoParentHubIndex = 0xFF;
    IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoReserved = (UINT8)(BbsIndex & 0xFF);

    Status = mLegacyBios->GetBbsInfo (
                            mLegacyBios,
                            &HddCount,
                            &HddInfo,
                            &BbsCount,
                            &BbsTable);

    if (EFI_ERROR (Status)) {
      DPRINTF_LEGACY ("  GetBbsInfo fail \n");
      return Status;
    }

    HddInfoIndex = (BbsIndex - 1) / 2;
    if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsIndex - 1) % 2 == 0)) {
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 0;
    } else if (((HddInfo [HddInfoIndex].Status & HDD_PRIMARY) != 0) && ((BbsIndex - 1) % 2 == 1)){
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 1;
    } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsIndex - 1) % 2 == 0)){
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 2;
    } else if (((HddInfo [HddInfoIndex].Status & HDD_SECONDARY) != 0) && ((BbsIndex - 1) % 2 == 1)){
      IbvBbs->IdeDiskInfo [IdeInfo].DiskInfoPhyIDPort = 3;
    }

    IbvBbs->CDROM_BootOrder [CdromDeviceCount] = CdromIde;
    CdromIde++;
    IdeInfo++;

  } else if (BbsIndex < BBS_SDMEM_RESERVATION_START_INDEX) {

    DPRINTF_LEGACY ("  AHCI CDROM.\n");

    //
    // The BBS Table entry is for AHCI CDROM.
    //

#if OPTION_SUPPORT_AHCI_NATIVE

    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceType = BBS_IDE_CDROM_DEVICE_TYPE;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoDeviceOrderIndex = CdromAhci;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.BusNumber = (UINT16)(BbsEntry->Bus);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.DeviceNumber = (UINT16)(BbsEntry->Device);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPFA.PFA.FunctionNumber =
      (UINT16)(BbsEntry->Function);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoLUN = 0xFF;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoParentHubIndex = 0xFF;
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoReserved = (UINT8)(BbsIndex & 0xFF);
    IbvBbs->AhciDiskInfo [AhciInfo].DiskInfoPhyIDPort = (UINT8)(BbsEntry->IBV2);

#endif // OPTION_SUPPORT_AHCI_NATIVE

    IbvBbs->CDROM_BootOrder [CdromDeviceCount] = CdromAhci;
    BbsEntry->IBV1 = (UINT32)CdromAhci;
    CdromAhci++;
    AhciInfo++;

  } else if (BbsIndex < BBS_USB_CDROM_START_INDEX) {

    DPRINTF_LEGACY (
      "  BbsTable [0x%x] says it is a CDROM but the index is out of range.\n",
      BbsIndex);
    return SCT_STATUS_INVALID_PARAMETER;

  } else {

    DPRINTF_LEGACY ("  USB CDROM.\n");

    //
    // This BbsTable entry is for a USB CDROM.
    //

    CdromUsb = USBCDROM_BOOT_START_INDEX + (UINT8) (BbsIndex & 0xFF) - BBS_USB_CDROM_START_INDEX;
    if ((CdromUsb < USBCDROM_BOOT_START_INDEX) || (CdromUsb > USBCDROM_BOOT_END_INDEX)) {
      DPRINTF_LEGACY ("  USB CDROM INDEX is out of range, 0x%x.\n", CdromUsb);
      return SCT_STATUS_INVALID_PARAMETER;
    }

    IbvBbs->CDROM_BootOrder [CdromDeviceCount] = CdromUsb;
    BbsEntry->IBV1 = (UINT32)CdromUsb;
  }

  CdromDeviceCount++;

  return SCT_STATUS_SUCCESS;
} // ProcessOneCdrom


//
// FUNCTION NAME.
//      ProcessOneNet - Process a NET Entry in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes a NET entry in the BbsTable to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsEntry        - A pointer to this NET entry in the BbsTable.
//      BbsIndex        - A index value that this NET entry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessOneNet (
  IN BBS_TABLE *BbsEntry,
  IN UINT16 BbsIndex,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  DPRINTF_LEGACY ("ProcessOneNet:0x%x:", LANDeviceCount);
  DPRINTF_LEGACY ("\n");

  if ( LANDeviceCount >= MAX_LAN_COUNT) {
    DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", LANDeviceCount);
    return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
  }

//
// Network boot order is equal to the specific IBV.
//

  IbvBbs->LAN_BootOrder [LANDeviceCount] = (UINT8)BbsEntry->IBV1;
  LANDeviceCount++;

  return SCT_STATUS_SUCCESS;
} // ProcessOneNet


//
// FUNCTION NAME.
//      ProcessOneBev - Process a BEV Entry in the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes a BEV entry in the BbsTable to setup the
//      IbvBbs structure.
//
// ENTRY PARAMETERS.
//      BbsEntry        - A pointer to this BEV entry in the BbsTable.
//      BbsIndex        - A index value that this BEV entry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
EFIAPI
ProcessOneBev (
  IN BBS_TABLE *BbsEntry,
  IN UINT16 BbsIndex,
  OUT IBV_BBS_TABLE *IbvBbs
  )
{
  DPRINTF_LEGACY ("ProcessOneBev:0x%x:", BEVDeviceCount);
  DPRINTF_LEGACY ("\n");

  if (BEVDeviceCount >= MAX_BEV_COUNT) {
    DPRINTF_LEGACY ("Out of space in group, 0x%x is too large.\n", BEVDeviceCount);
    return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
  }

  IbvBbs->BEV_BootOrder [BEVDeviceCount] = BEVDeviceCount + BEV_BOOT_START_INDEX;
  BbsEntry->IBV1 = (UINT32)IbvBbs->BEV_BootOrder [BEVDeviceCount] ;
  BEVDeviceCount++;

  return SCT_STATUS_SUCCESS;
} // ProcessOneBev


//
// FUNCTION NAME.
//      FillIbvBootSeqWithDevicePath - Fill the value of Ibv BootSeq_Item_Order.
//
// FUNCTIONAL DESCRIPTION.
//      This function fills the value of Ibv BootSeq_Item_Order for a given device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - A pointer to a device path.
//
// EXIT PARAMETERS.
//      Function Return - SCT Status Code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
FillIbvBootSeqWithDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN OUT PIBV_BBS_TABLE IbvBbs
  )
{
  UINTN i;
  BOOLEAN Found;
  UINT16 BbsIndex;
  SCT_STATUS Status;
  BBS_TABLE *BbsEntry;

  Status = GetBbsEntryByDevicePath (
             DevicePath,
             &BbsIndex,
             &BbsEntry);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // LegacyBios->GetBbsInfo locks the Legacy Region that has the IbvBbs Table.
  // Unlock it again.
  //

  Status = mLegacyRegion->UnLock (
                            mLegacyRegion,
                            EGROUP_START_ADDRESS,
                            LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                            NULL);
  DPRINTF_LEGACY ("  mLegacyRegion->UnLock returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Found = FALSE;
  for (i = 0; i < MAX_BOOT_DEVICE_TYPE; i++) {
    if (IbvBbs->BootSeq_Item_Order [i] == BBS_UNKNOWN) {
      break;
    }

    if (IbvBbs->BootSeq_Item_Order [i] == BbsEntry->DeviceType) {
      Found = TRUE;
      break;
    }
  }

  if (Found == FALSE) {
    IbvBbs->BootSeq_Item_Order [i] = (UINT8) BbsEntry->DeviceType;
  }

  return SCT_STATUS_SUCCESS;
} // FillIbvBootSeqWithDevicePath


//
// FUNCTION NAME.
//      FillIbvBootOrderWithDevicePath - Fill the value of Ibv BootOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function fills the Ibv BootOrder value that belongs to a specific group
//      for a given device path. It also constructs the Ibv DiskInfo structure.
//
// ENTRY PARAMETERS.
//      DevicePath      - A pointer to a device path.
//
// EXIT PARAMETERS.
//      Function Return - SCT Status Code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
FillIbvBootOrderWithDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN OUT PIBV_BBS_TABLE IbvBbs
  )
{
  UINT16 BbsIndex;
  SCT_STATUS Status;
  BBS_TABLE *BbsEntry;

  Status = GetBbsEntryByDevicePath (
             DevicePath,
             &BbsIndex,
             &BbsEntry);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // LegacyBios->GetBbsInfo locks the Legacy Region that has the IbvBbs Table.
  // Unlock it again.
  //

  Status = mLegacyRegion->UnLock (
                            mLegacyRegion,
                            EGROUP_START_ADDRESS,
                            LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                            NULL);
  DPRINTF_LEGACY ("  mLegacyRegion->UnLock returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  switch (BbsEntry->DeviceType) {
    case BBS_FLOPPY:
      ProcessOneFdd (BbsEntry, BbsIndex, IbvBbs);
      break;

    case BBS_HARDDISK:
      ProcessOneHdd (BbsEntry, BbsIndex, IbvBbs);
      break;

    case BBS_CDROM:
      ProcessOneCdrom (BbsEntry, BbsIndex, IbvBbs);
      break;

    case BBS_EMBED_NETWORK:
      ProcessOneNet (BbsEntry, BbsIndex, IbvBbs);
      break;

    case BBS_BEV_DEVICE:
      ProcessOneBev (BbsEntry, BbsIndex, IbvBbs);
      break;

    default:

      DPRINTF_LEGACY ("  Unknown BbsType 0x%x.\n", BbsEntry->DeviceType);
      break;
  }

  return SCT_STATUS_SUCCESS;
} // FillIbvBootOrderWithDevicePath


//
// FUNCTION NAME.
//      ConstructIbvViaDevicePath - Fill the value of Ibv BootSeq_Item_Order and BootOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function fills the BootSeq_Item_Order and BootOrder value for a given device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - A pointer to a device path.
//
// EXIT PARAMETERS.
//      Function Return - SCT Status Code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
ConstructIbvViaDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN OUT PIBV_BBS_TABLE IbvBbs
  )
{
  SCT_STATUS Status;

  Status = FillIbvBootSeqWithDevicePath (DevicePath, IbvBbs);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FillIbvBootOrderWithDevicePath (DevicePath, IbvBbs);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return SCT_STATUS_SUCCESS;
} // ConstructIbvViaDevicePath


//
// FUNCTION NAME.
//      ConstructIbvViaDevicePaths - Construct the Ibv for a given device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function fills the BootSeq_Item_Order and BootOrder value that belongs
//      to a specific group for a given device path. If this device path is boot
//      option protocol, it will construct the Ibv for this given boot option protocol
//      cascaded-ly.
//      If this device path is a normal boot device path, it will fill the BootSeq_Item_Order
//      and BootOrder directly.
//
// ENTRY PARAMETERS.
//      FilePathList    - A pointer to a device path.
//
// EXIT PARAMETERS.
//      Function Return - SCT Status Code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
ConstructIbvViaDevicePaths (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN OUT PIBV_BBS_TABLE IbvBbs
  )
{
  PVOID Context;
  UINTN ContextSize;
  SCT_STATUS Status;
  PSCT_BOOT_OPTION_NODE Children, p;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *BopDp;
  PSCT_BOOT_OPTION_PROTOCOL BootOptionProtocol;
  Status = EFI_SUCCESS;
  DPRINTF_LEGACY ("ConstructIbvViaDevicePaths:");

  if (IsDeviceNodeBootOptionProtocol (FilePathList)) {
    DPRINTF_LEGACY ("  Found a Boot Option Protocol device path.\n");

    BopDp = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *) FilePathList;

    if (DevicePathNodeLength (FilePathList)
        > sizeof (BOOT_OPTION_PROTOCOL_DEVICE_PATH)) {

      //
      // Get a pointer to the context data, and calculate the size of the
      // context data.
      //

      ContextSize = DevicePathNodeLength (FilePathList)
                  - sizeof (BOOT_OPTION_PROTOCOL_DEVICE_PATH);
      Context = BopDp + 1;
    } else {
      ContextSize = 0;
      Context = NULL;
    }
    DPRINTF_LEGACY ("  Found %d bytes of context.\n", ContextSize);

    Status = gBS->LocateProtocol (
                    &(BopDp->ProtocolGuid),
                    NULL,
                    (VOID **) &BootOptionProtocol);

    if (EFI_ERROR (Status)) {
      DPRINTF_LEGACY ("  Failed to LocateProtocol, %r.\n", Status);
      return SCT_STATUS_NOT_FOUND;
    }

    Children = NULL;
    Status = BootOptionProtocol->GetChildren (
                                   BootOptionProtocol,
                                   Context,
                                   ContextSize,
                                   &Children);
    DPRINTF_LEGACY (
      "  BootOptionProtocol->GetChildren returned %r.\n",
      Status);
    if (EFI_ERROR (Status)) {
      return SCT_STATUS_NOT_FOUND;
    }

    //
    // Walk through the child nodes and recurse into each.
    //

    p = Children;
    while (TRUE) {
      if (p == NULL) {
        break;
      }

      Status = ConstructIbvViaDevicePaths (p->FilePathList, IbvBbs);
      if (EFI_ERROR (Status)) {
        DestroyBopChildList (Children);
        return Status;
      }
      p = p->Next;
    }
    DestroyBopChildList (Children);
  } else {
    Status = ConstructIbvViaDevicePath (FilePathList, IbvBbs);

    if (Status == SCT_STATUS_SUCCESS) {
      if (CompareDevicePath (FilePathList, mCurrentBootDevicePath)) {
        mIsCurrentBootCreatedInIBV = TRUE;
      }
    }

    DPRINTF_LEGACY ("ConstructIbvViaDevicePaths.ConstructIbvViaDevicePath returned %r.\n", Status);
  }

  return Status;
} // ConstructIbvViaDevicePaths


//
// FUNCTION NAME.
//      SearchIbvBootSeqItemOrder - Search Ibv BootSeq_Item_Order for a given BbsEntry.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs the Ibv BootSeq_Item_Order array for a given BbsEntry,
//      and returns the index in BootSeq_Item_Order array.
//
// ENTRY PARAMETERS.
//      IbvBbs          - A pointer to the IbvBbs table that is searched.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that a BbsEntry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - An UINT8 value that is the index in BootSeq_Item_Order array.
//

UINT8
SearchIbvBootSeqItemOrder (
  IN PIBV_BBS_TABLE IbvBbs,
  IN BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
)
{
  UINT8 i;
  BOOLEAN FoundSelectedGroup;

  FoundSelectedGroup = FALSE;
  for (i = 0; i < MAX_BOOT_DEVICE_TYPE; i++) {
    if (IbvBbs->BootSeq_Item_Order [i] == BBS_UNKNOWN) {
      break;
    }

    if (IbvBbs->BootSeq_Item_Order [i] == BbsTable [BootDeviceBbsTableIndex].DeviceType) {
      FoundSelectedGroup = TRUE;
      break;
    }
  }

  if (FoundSelectedGroup) {
    return i;
  } else {
    return BBS_UNKNOWN;
  }
} // SearchIbvBootSeqItemOrder


//
// FUNCTION NAME.
//      SearchIbvRemovableBootOrder - Search Ibv Removable_BootOrder for a given BbsEntry.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs the Ibv Removable_BootOrder array for a given BbsEntry,
//      and returns the index in Removable_BootOrder array.
//
// ENTRY PARAMETERS.
//      IbvBbs          - A pointer to the IbvBbs table that is searched.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that a BbsEntry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - An UINT8 value that is the index in Removable_BootOrder array.
//

UINT8
SearchIbvRemovableBootOrder (
  IN PIBV_BBS_TABLE IbvBbs,
  IN BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
)
{
  UINT8 i;
  BOOLEAN FoundSelectedDevice;

  FoundSelectedDevice = FALSE;
  for (i = 0; i < MAX_REMOVABLE_DEVICE_COUNT; i++) {
    if (IbvBbs->Removable_BootOrder [i] == BBS_UNKNOWN) {
      break;
    }

    if (IbvBbs->Removable_BootOrder [i] == BbsTable [BootDeviceBbsTableIndex].IBV1) {
      FoundSelectedDevice = TRUE;
      break;
    }
  }

  if (FoundSelectedDevice) {
    return i;
  } else {
    return BBS_UNKNOWN;
  }
} // SearchIbvRemovableBootOrder


//
// FUNCTION NAME.
//      SearchIbvHardDiskBootOrder - Search Ibv HardDisk_BootOrder for a given BbsEntry.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs the Ibv HardDisk_BootOrder array for a given BbsEntry,
//      and returns the index in HardDisk_BootOrder array.
//
// ENTRY PARAMETERS.
//      IbvBbs          - A pointer to the IbvBbs table that is searched.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that a BbsEntry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - An UINT8 value that is the index in HardDisk_BootOrder array.
//

UINT8
SearchIbvHardDiskBootOrder (
  IN PIBV_BBS_TABLE IbvBbs,
  IN BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
)
{
  UINT8 i;
  BOOLEAN FoundSelectedDevice;

  FoundSelectedDevice = FALSE;
  for (i = 0; i < MAX_HDD_DEVICE_COUNT; i++) {
    if (IbvBbs->HardDisk_BootOrder [i] == BBS_UNKNOWN) {
      break;
    }

    if (IbvBbs->HardDisk_BootOrder [i] == BbsTable [BootDeviceBbsTableIndex].IBV1) {
      FoundSelectedDevice = TRUE;
      break;
    }
  }

  if (FoundSelectedDevice) {
    return i;
  } else {
    return BBS_UNKNOWN;
  }
} // SearchIbvHardDiskBootOrder


//
// FUNCTION NAME.
//      SearchIbvCDROMBootOrder - Search Ibv CDROM_BootOrder for a given BbsEntry.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs the Ibv CDROM_BootOrder array for a given BbsEntry,
//      and returns the index in CDROM_BootOrder array.
//
// ENTRY PARAMETERS.
//      IbvBbs          - A pointer to the IbvBbs table that is searched.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that a BbsEntry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - An UINT8 value that is the index in CDROM_BootOrder array.
//

UINT8
SearchIbvCDROMBootOrder (
  IN PIBV_BBS_TABLE IbvBbs,
  IN BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
)
{
  UINT8 i;
  BOOLEAN FoundSelectedDevice;

  DPRINTF_LEGACY ("SearchIbvCDROMBootOrder: BbsTable [0x%x].IBV1 is 0x%x.\n", BootDeviceBbsTableIndex, BbsTable [BootDeviceBbsTableIndex].IBV1);
  FoundSelectedDevice = FALSE;
  for (i = 0; i < MAX_CDROM_DEVICE_COUNT; i++) {
    DPRINTF_LEGACY ("SearchIbvCDROMBootOrder: IbvBbs->CDROM_BootOrder [0x%x] is 0x%x.\n", i, IbvBbs->CDROM_BootOrder [i]);
    if (IbvBbs->CDROM_BootOrder [i] == BBS_UNKNOWN) {
      break;
    }

    if (IbvBbs->CDROM_BootOrder [i] == BbsTable [BootDeviceBbsTableIndex].IBV1) {
      FoundSelectedDevice = TRUE;
      break;
    }
  }

  if (FoundSelectedDevice) {
    return i;
  } else {
    return BBS_UNKNOWN;
  }
} // SearchIbvCDROMBootOrder


//
// FUNCTION NAME.
//      SearchIbvLANBootOrder - Search Ibv LAN_BootOrder for a given BbsEntry.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs the Ibv LAN_BootOrder array for a given BbsEntry,
//      and returns the index in LAN_BootOrder array.
//
// ENTRY PARAMETERS.
//      IbvBbs          - A pointer to the IbvBbs table that is searched.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that a BbsEntry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - An UINT8 value that is the index in LAN_BootOrder array.
//

UINT8
SearchIbvLANBootOrder (
  IN PIBV_BBS_TABLE IbvBbs,
  IN BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
)
{
  UINT8 i;
  BOOLEAN FoundSelectedDevice;

  FoundSelectedDevice = FALSE;
  for (i = 0; i < MAX_LAN_COUNT; i++) {
    if (IbvBbs->LAN_BootOrder [i] == BBS_UNKNOWN) {
      break;
    }

    if (IbvBbs->LAN_BootOrder [i] == BbsTable [BootDeviceBbsTableIndex].IBV1) {
      FoundSelectedDevice = TRUE;
      break;
    }
  }

  if (FoundSelectedDevice) {
    return i;
  } else {
    return BBS_UNKNOWN;
  }
} // SearchIbvLANBootOrder

//
// FUNCTION NAME.
//      SearchIbvBEVBootOrder - Search Ibv BEV_BootOrder for a given BbsEntry.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs the Ibv BEV_BootOrder array for a given BbsEntry,
//      and returns the index in LAN_BootOrder array.
//
// ENTRY PARAMETERS.
//      IbvBbs          - A pointer to the IbvBbs table that is searched.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that a BbsEntry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - An UINT8 value that is the index in BEV_BootOrder array.
//

UINT8
SearchIbvBEVBootOrder (
  IN PIBV_BBS_TABLE IbvBbs,
  IN BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
)
{
  UINT8 i;
  BOOLEAN FoundSelectedDevice;

  FoundSelectedDevice = FALSE;
  for (i = 0; i < MAX_BEV_COUNT; i++) {
    if (IbvBbs->BEV_BootOrder [i] == BBS_UNKNOWN) {
      break;
    }

    if (IbvBbs->BEV_BootOrder [i] == BbsTable [BootDeviceBbsTableIndex].IBV1) {
      FoundSelectedDevice = TRUE;
      break;
    }
  }

  if (FoundSelectedDevice) {
    return i;
  } else {
    return BBS_UNKNOWN;
  }
} // SearchIbvBEVBootOrder


//
// FUNCTION NAME.
//      FillIbvBootMgrSelectedBootDevice - Fill selected boot device in Ibv table.
//
// FUNCTIONAL DESCRIPTION.
//      This function fills Ibv BootMgr_Selected_Group and BootMgr_Selected_Device
//      for a given BbsEntry. This BbsEntry is the boot device.
//
// ENTRY PARAMETERS.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that a BbsEntry is located in the BbsTable.
//
// EXIT PARAMETERS.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

VOID
FillIbvBootMgrSelectedBootDevice (
  IN OUT PIBV_BBS_TABLE IbvBbs,
  IN BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
)
{
  UINT8 BootOrderIndex;
  UINT8 BootGroupIndex;

  BootGroupIndex = SearchIbvBootSeqItemOrder (IbvBbs, BbsTable, BootDeviceBbsTableIndex);

  IbvBbs->BootMgr_Selected_Group = BootGroupIndex;

  switch (IbvBbs->BootSeq_Item_Order [IbvBbs->BootMgr_Selected_Group]) {
    case BBS_FLOPPY:
      BootOrderIndex = SearchIbvRemovableBootOrder (IbvBbs, BbsTable, BootDeviceBbsTableIndex);
      break;

    case BBS_HARDDISK:
      BootOrderIndex = SearchIbvHardDiskBootOrder (IbvBbs, BbsTable, BootDeviceBbsTableIndex);
      break;

    case BBS_CDROM:
      BootOrderIndex = SearchIbvCDROMBootOrder (IbvBbs, BbsTable, BootDeviceBbsTableIndex);
      break;

    case BBS_EMBED_NETWORK:
      BootOrderIndex = SearchIbvLANBootOrder (IbvBbs, BbsTable, BootDeviceBbsTableIndex);
      break;

    case BBS_BEV_DEVICE:
      BootOrderIndex = SearchIbvBEVBootOrder (IbvBbs, BbsTable, BootDeviceBbsTableIndex);
      break;

    default:
      BootOrderIndex = BBS_UNKNOWN;
      DPRINTF_LEGACY ("  Unknown BbsType 0x%x.\n", IbvBbs->BootSeq_Item_Order [IbvBbs->BootMgr_Selected_Group]);
      break;
  }

  IbvBbs->BootMgr_Selected_Device = BootOrderIndex;
} // FillIbvBootMgrSelectedBootDevice


//
// FUNCTION NAME.
//      ConstructIbvByBootOrder - Construct the Ibv table by Efi BootOrder variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function constructs the Ibv table. It reads every boot option from Efi
//      BootOrder variable, expands every boot option, and adds every boot device
//      into the Ibv table for each boot option. Finally, it searchs the location of
//      current boot device in Ibv, and fills the BootMgr_Selected_Group and
//      BootMgr_Selected_Device fields.
//
// ENTRY PARAMETERS.
//      BbsTable        - A pointer to the BbsTable.
//      BootDeviceBbsTableIndex - An index that the BbsEntry of boot device is
//                                located in the BbsTable.
//
// EXIT PARAMETERS.
//      Function Return - SCT Status Code.
//      IbvBbs          - A pointer to the IbvBbs table that is updated.
//

SCT_STATUS
ConstructIbvByBootOrder (
  IN OUT PIBV_BBS_TABLE IbvBbs,
  BBS_TABLE *BbsTable,
  IN int BootDeviceBbsTableIndex
  )
{
  UINTN i;
  UINTN StartIndex;
  SCT_STATUS Status;
  PUINT16 BootOrder;
  UINTN BootOrderSize;
  UINTN BootOrderIndex;
  PLOAD_OPTION_OBJECT Option;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *p;
  UINT16 BbsDeviceType;

  RemovableSdmem = SDMEM_FDD_BOOT_START_INDEX;
  RemovableDeviceCount = 0;
  UsbFloppyDeviceCount = 0;
  UsbZipDeviceCount = 0;

  IdeInfo = 0;
  AhciInfo = 0;

  HardDiskDeviceCount = 0;
  HardDiskIde = IDE_HDD_BOOT_START_INDEX;
  HardDiskScsi = SCSIHDD_BOOT_START_INDEX;
  HardDiskSdmem = SDMEM_HDD_BOOT_START_INDEX;
  HardDiskAhci = AHCIHDD_BOOT_START_INDEX;
  HardDiskNvme = NVMEHDD_BOOT_START_INDEX;

  CdromDeviceCount = 0;
  CdromIde = IDE_CDROM_BOOT_START_INDEX;
  CdromAhci = AHCICDROM_BOOT_START_INDEX;

  LANDeviceCount = 0;
  BEVDeviceCount = 0;

  p = NULL;

  //
  // Set the default value of BootSeq_Item_Order array to BBS_UNKNOWN.
  //

  for (i = 0; i < MAX_BOOT_DEVICE_TYPE; i++) {
    IbvBbs->BootSeq_Item_Order [i] = BBS_UNKNOWN;
  }
  BbsDeviceType = BbsTable [BootDeviceBbsTableIndex].DeviceType;
  BootOrder = NULL;
  BootOrderSize = 0;

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,
             &BootOrderSize,
             (VOID **) &BootOrder);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  StartIndex = 0;
  for (BootOrderIndex = 0; BootOrderIndex < BootOrderSize / sizeof (UINT16); BootOrderIndex++) {

    //
    // Get Boot Option.
    //

    Option = NULL;
    Status = GetBootOption (BootOrder [BootOrderIndex], &Option);
    if (EFI_ERROR(Status) || Option == NULL) {
      continue;
    }

    //
    // Check if the BootOption is active.
    //

    if ((Option->Attributes & LOAD_OPTION_ACTIVE) != LOAD_OPTION_ACTIVE) {
      continue;
    }

    //
    // If SystemConfiguration.OpromLoadType == Ondemand, skip LAN BootOption.
    //

    if (!LoadAllOprom ()) {
      if (IsDeviceNodeBootOptionProtocol (Option->FilePathList)) {

        //
        // If this is an OEM Expansion Node, ignore the LAN BOP.
        //

        p = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *)Option->FilePathList;

        if (CompareGuid (&(p->ProtocolGuid), &gPciLanBootOptionProtocolGuid) &&
          BbsDeviceType != BBS_EMBED_NETWORK) {
          continue;
        }
      }
    }

    ConstructIbvViaDevicePaths (
      Option->FilePathList,
      IbvBbs);
  }

  if (mIsCurrentBootCreatedInIBV == FALSE) {
    DPRINTF_LEGACY ("  current boot device is still not created in IBV.\n");

    DEBUG_LEGACY ({
      CHAR16* Str = NULL;
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (mCurrentBootDevicePath, FALSE, TRUE);
      DPRINTF_LEGACY (" mCurrentBootDevicePath=%s.\n", Str);
      SafeFreePool (Str);
    });

    ConstructIbvViaDevicePath (mCurrentBootDevicePath, IbvBbs);
  }

  //
  // Free the resources.
  //

  SafeFreePool (BootOrder);

  FillIbvBootMgrSelectedBootDevice (IbvBbs, BbsTable, BootDeviceBbsTableIndex);

  return SCT_STATUS_SUCCESS;
} // ConstructIbvByBootOrder
#endif // OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER


//
// FUNCTION NAME.
//      CreateIbvTableFromBbsTable - Create IBV table from BBS Table.
//
// FUNCTIONAL DESCRIPTION.
//      This function creates the IBV table from the BBS table.
//
//      The IBV Table is CSM-defined table which contains the relative order of
//      each of the BBS-defined device classes. Each of the device is assigned
//      a class-specific index and that index is patched into the BBS table in
//      the IBV1 field. The class-specific index is directly tied to the CSM's
//      physical driver number.
//
// ENTRY PARAMETERS.
//      DevOrder        - Points to the legacy device boot order.
//      DevOrderSize    - Size of DevOrder, in bytes.
//      BbsTable        - Points to the BBS device table.
//      HddCount        - Number of entries in HddInfo.
//      HddInfo         - Points to array of hard drive data entries.
//      IbvBbs          - Points to the IBV BBS Table.
//
// EXIT PARAMETERS.
//      Function Return - SCT Status Code.
//      IbvBbs          - Points to the updated IBV BBS Table.
//

SCT_STATUS
CreateIbvTableFromBbsTable (
  IN UINT8 *DevOrder,
  IN UINTN DevOrderSize,
  IN BBS_TABLE *BbsTable,
  IN UINT16 HddCount,
  IN HDD_INFO *HddInfo,
  IN OUT PIBV_BBS_TABLE IbvBbs
  )
{
  UINT32 BbsType;                       // current BBS group type.
  UINT8 NumberOfBbsOrder;               // number of BBS table entries for current group.
  PUINT16 BbsOrder;                     // points to BBS table index.
  MEMORY_POINTER p;
  UINTN DevOrderEnd;

  p.puint8 = DevOrder;
  DevOrderEnd = DevOrderSize + p.address;    // Calculate the ending address.
  DPRINTF_LEGACY ("DevOrder starting address 0x%x, ending address 0x%x.\n",
    DevOrder,
    DevOrderEnd);

  //
  // Use the BBS table to create the IBV table, which sets the priority of each
  // device within its device class for the CSM to use for INT 0x19 and INT 0x13.
  //

  IdeInfo = 0;
  AhciInfo = 0;
  NvmeInfo = 0;

  while (p.address < DevOrderEnd) {
    BbsType = *p.puint32;
    p.puint32++;

    NumberOfBbsOrder = (UINT8)((*p.puint16 - sizeof (UINT16)) / sizeof (UINT16)) & 0xFF;
    BbsOrder = p.puint16 + 1;

    switch (BbsType) {
      case BBS_FLOPPY:
        ProcessFdd (BbsTable, BbsOrder, NumberOfBbsOrder, IbvBbs);
        break;

      case BBS_HARDDISK:
        ProcessHdd (
          BbsTable,
          HddInfo,
          HddCount,
          BbsOrder,
          NumberOfBbsOrder,
          IbvBbs);
        break;

      case BBS_CDROM:
        ProcessCdrom (
          BbsTable,
          HddInfo,
          HddCount,
          BbsOrder,
          NumberOfBbsOrder,
          IbvBbs);
        break;

      case BBS_EMBED_NETWORK:
        ProcessNet (BbsTable, BbsOrder, NumberOfBbsOrder, IbvBbs);
        break;

      case BBS_BEV_DEVICE:
        ProcessBev (BbsTable, BbsOrder, NumberOfBbsOrder, IbvBbs);
        break;

      default:

        DPRINTF_LEGACY ("  Unknown BbsType 0x%x.\n", BbsType);
        break;
    }
    p.address += *p.puint16;
  }

  DPRINTF_LEGACY ("  Total IDE  devices : %d\n", IdeInfo);
  DPRINTF_LEGACY ("  Total AHCI devices : %d\n", AhciInfo);

  return SCT_STATUS_SUCCESS;
} // CreateIbvTableFromBbsTable

//
// FUNCTION NAME.
//      SetIbvBbsEntry - Set the boot order within specified device type.
//
// FUNCTIONAL DESCRIPTION.
//      This function sets the boot order within specified device type in IBV
//      table.
//
// ENTRY PARAMETERS.
//      IbvBbs          - pointer to the Ibv table.
//      DeviceType      - device type of the boot order.
//      DeviceTypeEntry - the priority of boot order.
//      IbvBbsIndex     - the new Ibv Bbs index.
//
// EXIT PARAMETERS.
//      Function Return - TRUE or False.
//

BOOLEAN
SetIbvBbsEntry (
  IN OUT PIBV_BBS_TABLE IbvBbs,
  IN UINT16 DeviceType,
  IN UINT16 DeviceTypeEntry,
  IN UINT8 IbvBbsIndex
  )
{
  switch (DeviceType) {
    case BBS_FLOPPY:
      if (DeviceTypeEntry >= MAX_REMOVABLE_DEVICE_COUNT) {
        return FALSE;
      }
      IbvBbs->Removable_BootOrder [DeviceTypeEntry] = IbvBbsIndex;
      break;

    case BBS_HARDDISK:
      if (DeviceTypeEntry >= MAX_HDD_DEVICE_COUNT) {
        return FALSE;
      }
      IbvBbs->HardDisk_BootOrder [DeviceTypeEntry] = IbvBbsIndex;
      break;

    case BBS_CDROM:
      if (DeviceTypeEntry >= MAX_CDROM_DEVICE_COUNT) {
        return FALSE;
      }
      IbvBbs->CDROM_BootOrder [DeviceTypeEntry] = IbvBbsIndex;
      break;

    case BBS_EMBED_NETWORK:
      if (DeviceTypeEntry >= MAX_LAN_COUNT) {
        return FALSE;
      }
      IbvBbs->LAN_BootOrder [DeviceTypeEntry] = IbvBbsIndex;
      break;

    case BBS_BEV_DEVICE:
      if (DeviceTypeEntry >= MAX_BEV_COUNT) {
        return FALSE;
      }
      IbvBbs->BEV_BootOrder [DeviceTypeEntry] = IbvBbsIndex;
      break;

    default:
      DPRINTF_LEGACY ("Unknown BBS Device Type in IBV BBS Table %d\n", DeviceType);
      return FALSE;
  }

  return TRUE;
} // SetIbvBbsEntry


//
// FUNCTION NAME.
//      GetIbvBbsEntry - Get the Ibv Bbs index within boot order.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets the Ibv Bbs index within boot order.
//
// ENTRY PARAMETERS.
//      IbvBbs          - pointer to the Ibv table.
//      DeviceType      - device type of the boot order.
//      DeviceTypeEntry - the priority of boot order.
//
// EXIT PARAMETERS.
//      Function Return - Ibv Bbs index.
//

UINT8
GetIbvBbsEntry (
  IN OUT PIBV_BBS_TABLE IbvBbs,
  IN UINT16 DeviceType,
  IN UINT16 DeviceTypeEntry
  )
{
  switch (DeviceType) {
    case BBS_FLOPPY:
      if (DeviceTypeEntry >= MAX_REMOVABLE_DEVICE_COUNT) {
        return 0xff;
      }
      return IbvBbs->Removable_BootOrder [DeviceTypeEntry];

    case BBS_HARDDISK:
      if (DeviceTypeEntry >= MAX_HDD_DEVICE_COUNT) {
        return 0xff;
      }
      return IbvBbs->HardDisk_BootOrder [DeviceTypeEntry];

    case BBS_CDROM:
      if (DeviceTypeEntry >= MAX_CDROM_DEVICE_COUNT) {
        return 0xff;
      }
      return IbvBbs->CDROM_BootOrder [DeviceTypeEntry];

    case BBS_EMBED_NETWORK:
      if (DeviceTypeEntry >= MAX_LAN_COUNT) {
        return 0xff;
      }
      return IbvBbs->LAN_BootOrder [DeviceTypeEntry];

    case BBS_BEV_DEVICE:
      if (DeviceTypeEntry >= MAX_BEV_COUNT) {
        return 0xff;
      }
      return IbvBbs->BEV_BootOrder [DeviceTypeEntry];

    default:
      break;
  }

  DPRINTF_LEGACY ("Unknown BBS Device Type in IBV BBS Table %d\n", DeviceType);
  return 0xff;

} // GetIbvBbsEntry


//
// FUNCTION NAME.
//      LegacyUpdateBbsTables - Update the Legacy IBV BBS Table and the BbsTable.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates the IbvBbs table per the BbsTable from the Legacy
//      BIOS Protocol function GetBbsTable.
//
//      Then this function updates the priority in the BbsTable per the ordering.
//
//      If FilePathList is not NULL it is expected to be a BBS Device Path. If
//      the path is not a BBS Device Path this function will return an error.
//      The type of DeviceType of the BBS Device Path will be used as the first
//      item in the BootSeq_Item_Order array in the Ibv table.
//      If FilePathList is NULL no special handling will be performed on the
//      BbsInfo table.
//
//      If BootListName is not NULL this function will search for a variable
//      with this name. If no such variable exists this function will return
//      with an error. The value of the variable is expected to be an array
//      of UINT16 values. Each value corresponds to a boot option, per the
//      UEFI Specification Chapter 3, see the discussions relating to the
//      BootOrder variable. Each device path associated with a Boot Option
//      will be expanded and the resulting paths searched for BBS Device
//      Paths. The DeviceType of each BBS Device Path will be used to
//      determine the next entry in the BootSeq_Item_Order array in the Ibv
//      table.
//
//      If FilePathList and BootListName are both NULL the BootSeq_Item_Order
//      array will be cleared, each entry set to BBS_UNKNOWN.
//
//      This function calls CreateDevOrder which creates the default legacy
//      boot order. This structure is then processed to create the IBV BBS table
//      which controls drive lettering and prioritization within each BBS group
//      for oot.
//
// ENTRY PARAMETERS.
//      FilePathList    - the Device Path for the Device Type that is to be
//                        primary.
//      BootListName    - A pointer to a CHAR16 NUL terminated string.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
LegacyUpdateBbsTables (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN CONST PCHAR16 BootListName
  )
{
  UINTN Index;
  UINT16 DeviceType;
  int BbsTableIndex;                    // BBS Table index of device to boot.
  SCT_STATUS Status;
  PIBV_BBS_TABLE IbvBbs;                // points to CSM boot priority table.
  UINT16 HddCount;                      // number of entries in HddInfo.
  HDD_INFO *HddInfo;                    // points to Hard Drive information.
  UINT16 BbsCount;                      // number of entries in BBS Table.
  BBS_TABLE *BbsTable;                  // points to BBS Table.
  EFI_DEVICE_PATH_PROTOCOL ** BbsTableDevicePaths;

#if !OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER
  UINTN i;
  UINTN j;
  UINT8 Type;
  int PtrSize;
  BOOLEAN Done;
  UINT32 Offset;
  UINT16 Priority;                      // current drive order priority.
  UINT8 *DevOrder;                      // points to structure describing boot priority by boot group.
  UINT16 *IndexPtr;
  UINT16 IndexCount;
  UINTN DevOrderSize;                   // size of DevOrder, in bytes.
  UINTN BootSeqItemOrderIndex;          // current Boot Group index.
  LEGACY_DEV_ORDER_HEADER *Ptr;

#if OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER
  INTN k;
#endif // OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER

#endif // !OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER

  DPRINTF_LEGACY ("Entry:\n");
  DEBUG_LEGACY ({
    PCHAR16 Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (FilePathList, FALSE, TRUE);
    DPRINTF_LEGACY (" FilePathList=%s, BootListName=%s.\n", Str, BootListName);
    SafeFreePool (Str);
  });

  Index = 0;
  IbvBbs = LegacyGetIbvBbs ();
  if (IbvBbs == NULL) {
    DPRINTF_LEGACY ("Could not find IBV BBS Table\n");
    return SCT_STATUS_NOT_FOUND;
  }

  //
  // Open the legacy region for writing.
  //

  DPRINTF_LEGACY ("mLegacyRegion = 0x%x\n", mLegacyRegion);

  Status = mLegacyRegion->UnLock (
             mLegacyRegion,
             EGROUP_START_ADDRESS,
             LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
             NULL);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("Could not unlock legacy region.\n");
    return Status;
  }

  //
  // Get the BBS Table from the LegacyBios driver.
  //

  DPRINTF_LEGACY ("mLegacyBios = 0x%x\n", mLegacyBios);

  Status = mLegacyBios->GetBbsInfo (
                          mLegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          &BbsTable);
  DPRINTF_LEGACY ("  GetBbsInfo returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // LegacyBios->GetBbsInfo locks the Legacy Region that has the IbvBbs Table.
  // Unlock it again.
  //

  Status = mLegacyRegion->UnLock (
                            mLegacyRegion,
                            EGROUP_START_ADDRESS,
                            LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                            NULL);
  DPRINTF_LEGACY ("  mLegacyRegion->UnLock returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Take the device path that was passed in and compare it against the list of
  // device paths that was created when the BBS table was created in order to
  // find a match.
  //

  Status = gBS->LocateProtocol (
                  &gBbsTableDevicePathsTableGuid,
                  NULL,
                  (VOID **) &BbsTableDevicePaths);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  Can't locate BBS device path table\n");
    goto Exit;
  }

  //
  // Update BBStable for those USB MSD that have not yet been added into table.
  //

  Status = UpdateLegacyUsbToBbsTable (
             BbsTable,
             BbsCount,
             BbsTableDevicePaths,
             NULL,
             NULL);

  for (BbsTableIndex = 0; BbsTableIndex < BbsCount; BbsTableIndex++) {
    if (BbsTableDevicePaths [BbsTableIndex] != NULL) {
      DEBUG_LEGACY ({
        PCHAR16 Str = NULL;
        Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (BbsTableDevicePaths [BbsTableIndex], FALSE, TRUE);
        DPRINTF_LEGACY ("Found Device Path for BBS Table index %d='%s'.\n", BbsTableIndex, Str);
        SafeFreePool (Str);
      });
      if (CompareDevicePath (FilePathList, BbsTableDevicePaths [BbsTableIndex])) {
        DPRINTF_LEGACY ("Match for boot device path at BBS Table index #%d\n", BbsTableIndex);
        break;
      }
    }
  }

  DeviceType = BbsTable [BbsTableIndex].DeviceType;  // save device type of our boot device.
  DPRINTF_LEGACY ("Boot from Device type : 0x%x\n", DeviceType);

  mCurrentBootDevicePath = FilePathList;

#if OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER

  //
  // Fill the UsbDiskInfo buffer in IBV table.
  //

  FillIbvUsbDiskInfo (
    IbvBbs,
    BbsCount,
    BbsTable,
    BbsTableDevicePaths);

  for ( Index = 0; Index < BbsCount; Index ++ ) {
    if ( Index == BbsTableIndex ) {
      BbsTable [Index].BootPriority = 0;
    } else {
      if ((BbsTable [Index].BootPriority != BBS_DO_NOT_BOOT_FROM) &&
          (BbsTable [Index].BootPriority != BBS_UNPRIORITIZED_ENTRY) &&
          (BbsTable [Index].BootPriority != BBS_IGNORE_ENTRY)) {
        BbsTable [Index].BootPriority = BBS_UNPRIORITIZED_ENTRY;
      }
    }
  }

  Status = ConstructIbvByBootOrder (IbvBbs, BbsTable, BbsTableIndex);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  Failed to construct Ibv by BootOrder.\n");
    goto Exit;
  }

#else

  //
  // Initialize BootSequence as 0xff first.
  //

  SetMem (
    IbvBbs->BootSeq_Item_Order,
    sizeof (IbvBbs->BootSeq_Item_Order),
    BBS_UNKNOWN);

  //
  // Create the legacy device order. This creates the data structure which
  // lists the BBS table index in default priority order, by device class.
  //

  DPRINTF_LEGACY ("CreateDevOrder\n");
  Status = CreateDevOrder (BbsTable, BbsCount, BbsTableIndex, &DevOrder, &DevOrderSize);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("CreateDevOrder returned %r.\n", Status);
    goto Exit;
  }
  DISPLAY_LEGACY_DEV_ORDER(DevOrder,DevOrderSize,L"");

  //
  // Make sure the legacy region is accessible.
  //

  Status = mLegacyRegion->UnLock (
                            mLegacyRegion,
                            EGROUP_START_ADDRESS,
                            LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                            NULL);
  DPRINTF_LEGACY ("  mLegacyRegion->UnLock returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Now walk through all of the device classes to find the BBS table index and
  // move it to the front, if it is not already there.
  //

  Done = FALSE;
  Offset = 0;
  Ptr = (LEGACY_DEV_ORDER_HEADER *) DevOrder;
  BootSeqItemOrderIndex = 0;
  while (!Done && Offset < DevOrderSize) {
    IndexPtr = (UINT16 *) (Ptr + 1);    // ptr to first index.
    IndexCount = (Ptr->Count - sizeof (UINT16))/sizeof (UINT16);

    PtrSize = (int) (sizeof (LEGACY_DEV_ORDER_HEADER) + IndexCount * sizeof (UINT16));

    for (i = 0; i < IndexCount; i++) {
      if (IndexPtr [i] == BbsTableIndex) {
        DPRINTF_LEGACY ("Found matching BBS table index in type %d, index %d\n", Ptr->Type, i);

        DPRINTF_LEGACY ("Boot Sequence Group %d = %d\n", BootSeqItemOrderIndex, Ptr->Type);
        IbvBbs->BootSeq_Item_Order [BootSeqItemOrderIndex++] = (UINT8) Ptr->Type;
        Done = TRUE;
        break;
      }
    }

    Ptr = (LEGACY_DEV_ORDER_HEADER *)((UINT8 *)Ptr + PtrSize);
    Offset += PtrSize;
  }

  if (!Done) {
    DPRINTF_LEGACY ("Could not find BBS table index %d in device order. Default boot order unchanged!\n", BbsTableIndex);
    Status = SCT_STATUS_INVALID_PARAMETER;
    goto Exit;
  }

  Offset = 0;
  Ptr = (LEGACY_DEV_ORDER_HEADER *) DevOrder;
  while (Offset < DevOrderSize) {
    IndexPtr = (UINT16 *)(Ptr + 1);    // ptr to first index.
    IndexCount = (Ptr->Count - sizeof (UINT16)) / sizeof (UINT16);

    PtrSize = (int)(sizeof (LEGACY_DEV_ORDER_HEADER) + IndexCount * sizeof (UINT16));

    if (Ptr->Type != IbvBbs->BootSeq_Item_Order [0] && IndexCount != 0) {
      DPRINTF_LEGACY ("Boot Sequence Group %d = %d\n", BootSeqItemOrderIndex, Ptr->Type);
      IbvBbs->BootSeq_Item_Order [BootSeqItemOrderIndex++] = (UINT8)Ptr->Type;
    }

    Ptr = (LEGACY_DEV_ORDER_HEADER *)((UINT8 *)Ptr + PtrSize);
    Offset += PtrSize;
  }

  //
  // Now loop through and set the boot priority, first for the group we care
  // about and then all of the other groups.
  //

  Priority = 1;
  Offset = 0;
  Ptr = (LEGACY_DEV_ORDER_HEADER *) DevOrder;
  DPRINTF_LEGACY ("Assigned BBS Table Priority To Highest Priority Group\n");
  while (Offset < DevOrderSize) {
    IndexPtr = (UINT16 *)(Ptr + 1);    // ptr to first index.
    IndexCount = (Ptr->Count - sizeof (UINT16)) / sizeof (UINT16);

    PtrSize = (int) (sizeof (LEGACY_DEV_ORDER_HEADER) + IndexCount * sizeof (UINT16));
    if (Ptr->Type == IbvBbs->BootSeq_Item_Order [0]) {
      DPRINTF_LEGACY ("Found device order for BBS class %d. Assigning priorities\n", Ptr->Type);
      for (i = 0; i < IndexCount; i++) {
        if (IndexPtr [i] == BbsTableIndex) {
          DPRINTF_LEGACY ("BBS Table %d Assigned Priority %d\n", IndexPtr [i], 0);
          BbsTable [IndexPtr [i]].BootPriority = 0; // highest priority for item we are actually booting.
        } else {
          DPRINTF_LEGACY ("BBS Table %d Assigned Priority %d\n", IndexPtr [i], Priority);
          BbsTable [IndexPtr [i]].BootPriority = Priority++;
        }
      }
    }

    Ptr = (LEGACY_DEV_ORDER_HEADER *)((UINT8 *) Ptr + PtrSize);
    Offset += PtrSize;
  }

  Offset = 0;
  Ptr = (LEGACY_DEV_ORDER_HEADER *) DevOrder;
  DPRINTF_LEGACY ("Assigned BBS Table Priority To Other Groups\n");
  while (Offset < DevOrderSize) {
    IndexPtr = (UINT16 *)(Ptr + 1);    // ptr to first index.
    IndexCount = (Ptr->Count - sizeof (UINT16)) / sizeof (UINT16);

    PtrSize = (int)(sizeof (LEGACY_DEV_ORDER_HEADER) + IndexCount * sizeof (UINT16));
    if (Ptr->Type != IbvBbs->BootSeq_Item_Order [0]) {
      DPRINTF_LEGACY ("Found device order for BBS class %d. Assigning priorities\n", Ptr->Type);
      for (i = 0; i < IndexCount; i++) {
        DPRINTF_LEGACY ("BBS Table %d Assigned Priority %d\n", IndexPtr [i], Priority);
        BbsTable [IndexPtr [i]].BootPriority = Priority++;
      }
    }

    Ptr = (LEGACY_DEV_ORDER_HEADER *)((UINT8 *)Ptr + PtrSize);
    Offset += PtrSize;
  }

  //
  // Fill the UsbDiskInfo buffer in IBV table.
  //

  FillIbvUsbDiskInfo (
    IbvBbs,
    BbsCount,
    BbsTable,
    BbsTableDevicePaths);

  Status = CreateIbvTableFromBbsTable (
             DevOrder,
             DevOrderSize,
             BbsTable,
             HddCount,
             HddInfo,
             IbvBbs);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("Unable to create IBV BBS Table from BBS Table (%r)\n", Status);
    goto Exit;
  }

  //
  // Update the IBV BBS Table so that the device that we are trying to boot is
  // at the beginning of its device class by swapping it to the front.
  //

  for (i = 0; i < MAX_BOOT_DEVICE_TYPE; i++) {
    if (IbvBbs->BootSeq_Item_Order [i] == BBS_UNKNOWN) {
      break;
    }

    Done = FALSE;
    if (IbvBbs->BootSeq_Item_Order [i] == DeviceType) {
      for (j = 0; (Type = GetIbvBbsEntry (IbvBbs, DeviceType, (UINT16)j)) != 0xff; j++) {
        if (Type == BbsTable [BbsTableIndex].IBV1) {
          DPRINTF_LEGACY ("Type %d, Index %d = Match For BBS Table Entry %d\n",
            Type,
            j,
            BbsTableIndex);

#if !OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER
          Type = GetIbvBbsEntry (IbvBbs, DeviceType, 0);
          SetIbvBbsEntry (
            IbvBbs,
            DeviceType,
            0,
            GetIbvBbsEntry (IbvBbs, DeviceType, (UINT16)j));
          SetIbvBbsEntry (IbvBbs, DeviceType, (UINT16)j, Type);
#else
          for (k = (INTN)j; k > 0; k--) {
            Type = GetIbvBbsEntry (IbvBbs, DeviceType, (UINT16)k-1);
            SetIbvBbsEntry (
              IbvBbs,
              DeviceType,
              (UINT16)k-1,
              GetIbvBbsEntry (IbvBbs, DeviceType, (UINT16)k));
            SetIbvBbsEntry (IbvBbs, DeviceType, (UINT16)k, Type);
          }
#endif // OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER
          Done = TRUE;
          break;
        }
      }
    }

    if (Done) {
      break;
    }
  }

  UpdateBbsDriveNumber (BbsTable, BbsCount, IbvBbs);

#endif // OPTION_SYSTEM_BOOT_MANAGER_CREATE_IBV_BY_BOOT_ORDER

  DISPLAY_IBV_BBS_TABLE (IbvBbs);
  DISPLAY_LEGACY_BIOS_BBS_INFO (HddCount, HddInfo, BbsCount, BbsTable);

Exit:

  mLegacyRegion->Lock (
                   mLegacyRegion,
                   EGROUP_START_ADDRESS,
                   LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                   NULL);

  return Status;
} // LegacyUpdateBbsTables

//
// FUNCTION NAME.
//      UpdateBdaKeyboardFlag - Update BDA Keyboard Flags for NumLock.
//
// FUNCTIONAL DESCRIPTION.
//      Update BIOS Data Area (BDA) Keyboard Flags for NumLock.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function return - EFI status code.
//

EFI_STATUS
UpdateBdaKeyboardFlag (VOID)
{
  EFI_STATUS Status;
  UINT8 *KeyboardFlag = 0;
  UINTN Addr = 0x417;
  UINTN BufferSize;
  SCT_SYSTEM_CONFIGURATION *SctSystemConfig;
  EFI_GUID SctSystemConfigurationGuid = SCT_SYSTEM_CONFIGURATION_GUID;

  //
  // Get variable SctSystemConfiguration.NumLock.
  //

  BufferSize = 0;
  Status = gRT->GetVariable (
                  SYSTEM_CONFIGURATION_VARIABLE_NAME,
                  &SctSystemConfigurationGuid,
                  (UINT32 *) NULL,
                  &BufferSize,
                  NULL);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    BufferSize,
                    (VOID **) &SctSystemConfig
                    );
    if (SctSystemConfig == NULL) {
      return Status;
    }

    Status = gRT->GetVariable (
                    SYSTEM_CONFIGURATION_VARIABLE_NAME,
                    &SctSystemConfigurationGuid,
                    (UINT32 *) NULL,
                    &BufferSize,
                    SctSystemConfig);
    if (!EFI_ERROR (Status)) {

      //
      //        40:17  Keyboard Flags Byte 0
      //        bit5 - num-lock is active
      //

      KeyboardFlag += Addr;

      if (SctSystemConfig->NumLock == 1) {
                        *KeyboardFlag |= 0x20;
          } else {
                        *KeyboardFlag &= 0xdf;
      }
    }
    gBS->FreePool (SctSystemConfig);
  }

  return EFI_SUCCESS;

} // UpdateBdaKeyboardFlag

//
// FUNCTION NAME.
//      PrepareToBootLegacy - Do last minute preparation for boot.
//
// FUNCTIONAL DESCRIPTION.
//      This function does all the last minute setup for a boot event including
//      setting the BootCurrent variable and signaling ReadyToBoot.
//
// ENTRY PARAMETERS.
//      OptionNumber    - the Boot Option Number that we are about to boot.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
PrepareToBootLegacy (IN UINT16 OptionNumber)
{
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  SCT_ERROR_SCREEN_TEXT_PROTOCOL *ErrorInfoScreen;

  SCT_BDS_MILESTONE_TIMEOUT_DATA MilestoneAfterReadyToBoot;

  DPRINTF_LEGACY ("PrepareToBootLegacy:0x%x.\n", OptionNumber);

  //
  //          UpdateBdaKeyboardFlag - Update BDA Keyboard Flags for NumLock.
  //

  UpdateBdaKeyboardFlag ();

  //
  // Set Boot Current variable.
  //

  SetEfiGlobalVariable (
    EFI_BOOT_CURRENT_VARIABLE_NAME,
    EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS,
    sizeof (UINT16),
    &OptionNumber);

  gRT->SetVariable (
         L"LastBootCurrent",
         &gSctBdsServicesProtocolGuid,
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS |
         EFI_VARIABLE_NON_VOLATILE,
         sizeof (UINT16),
         &OptionNumber);

  //
  // Show Error Log Message Screen
  //

  if (!EFI_ERROR (
        gBS->LocateProtocol (
               &gSctErrorScreenTextProtocolGuid,
               NULL,
               (VOID **)&ErrorInfoScreen))) {
    SctSignalProtocolEvent(&gSctErrLogEnterProtocolGuid, NULL);
    ErrorInfoScreen->ShowAllErrorMessage (ErrorInfoScreen);
    SctSignalProtocolEvent(&gSctErrLogExitProtocolGuid, NULL);
  }

  if (mDxeSmmReadyToLockProtocol == FALSE) {
    Handle = NULL;
    DEBUG ((DEBUG_ERROR, "Install  gEfiDxeSmmReadyToLockProtocol\n"));
    Status = gBS->InstallProtocolInterface (
                    &Handle,
                    &gEfiDxeSmmReadyToLockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    NULL);
    mDxeSmmReadyToLockProtocol = TRUE;
  }

  PERF_START (0, "PrepareToBootLegacy", "SignalEventReadyToBoot", 0);
  //
  // Signal ready to boot.
  //
  EfiSignalEventReadyToBoot();

  //
  // Report Status Code to indicate ReadyToBoot was signalled
  //
  REPORT_STATUS_CODE (EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT));
  PRINT_REPORT_STATUS("(EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT))\n");

  PERF_END (0, "PrepareToBootLegacy", "SignalEventReadyToBoot", 0);

  //
  // Save Memory Map.
  //

  SaveMemoryMap ();

  //
  // Signal AFTER ready to boot.
  //

  PERF_START (0, "PrepareToBootLegacy", "MsTaskAfterReadyToBoot", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_AFTER_READY_TO_BOOT, MsTaskAfterReadyToBoot, &MilestoneAfterReadyToBoot, sizeof (MilestoneAfterReadyToBoot));
  PERF_END (0, "PrepareToBootLegacy", "MsTaskAfterReadyToBoot", 0);

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // PrepareToBootLegacy

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
//
// FUNCTION NAME.
//      CreateUsbIrqSwSmiTable - Create Usb Irq Software SMI table for Legacy BIOS.
//
// FUNCTIONAL DESCRIPTION.
//      Create CSM Software SMI table for Legacy BIOS.
//
// ENTRY PARAMETERS.
//      EfiToLegacy16BootTable - pointer to Legacy16 boot table.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
CreateUsbIrqSwSmiTable (IN EFI_TO_COMPATIBILITY16_BOOT_TABLE *EfiToLegacy16BootTable)
{
  EFI_STATUS Status;
  CSM_SMM_TABLE *SoftIntData;
  CSM_SMM_ENTRY *SmmEntry;
  UINTN TableSize;
  SCT_SMM_SW_SMI_PROTOCOL *SwSmiAllocator;
  UINTN CsmSwSmiInputValue;

  //
  //  Count value minus extra NULL GUID terminator leaves the real value.
  //

  TableSize = sizeof (CSM_SMM_TABLE);
  Status = gBS->AllocatePool (EfiBootServicesData, TableSize, (VOID **) &SoftIntData);
  DPRINTF_LEGACY ("  Allocate memory pool:%r.\n", Status);

  ZeroMem (SoftIntData, TableSize);
  ((EFI_TO_COMPATIBILITY16_BOOT_TABLE *)EfiToLegacy16BootTable)->SmmTable  =
    (UINT32)(UINTN)SoftIntData;

  //
  // Locate the SCT_SMM_SW_SMI_PROTOCOL and construct the CSM SMM table.
  //

  Status = gBS->LocateProtocol (&gSctSmmSwSmiProtocolGuid, NULL, (VOID **) &SwSmiAllocator);
  DPRINTF_LEGACY ("  Locate software SMI allocator protocol:%r.\n", Status);

  SwSmiAllocator->SwSmiCommandPort = CONFIG_SYSTEM_SW_SMI_PORT;
  SmmEntry = &SoftIntData->SmmEntry [0];
  SoftIntData->NumSmmEntries = 0;

  //
  // Build the SCT_CSM_SW_SMI entries. If we support software SMI reservation,
  // we just call SwSmiAllocator->QuerySwSmi to get the correct SMI value.
  //

  Status = SwSmiAllocator->QuerySwSmi (
                             &mCsmSwSmiGuidArray [SCT_CSM_LEGACY_USB_BY_IRQ],
                             &CsmSwSmiInputValue);

  if (!EFI_ERROR (Status)) { // means the SMI value has been allocated.
    SmmEntry->SmmAttributes.Type = 0;
    SmmEntry->SmmAttributes.DataGranularity = DATA_SIZE_8;
    SmmEntry->SmmFunction.Function = SCT_CSM_LEGACY_USB_BY_IRQ;
    SmmEntry->SmmFunction.Owner = STANDARD_OWNER;
#if CONFIG_CSM_SMMENTRY_PORT_SIZE == PORT_SIZE_16
    SmmEntry->SmmAttributes.PortGranularity = PORT_SIZE_16;
    SmmEntry->SmmPort = (UINT16)SwSmiAllocator->SwSmiCommandPort;
#elif CONFIG_CSM_SMMENTRY_PORT_SIZE == PORT_SIZE_8
    SmmEntry->SmmAttributes.PortGranularity = PORT_SIZE_8;
    SmmEntry->SmmPort = (UINT8)SwSmiAllocator->SwSmiCommandPort;
#else
    SmmEntry->SmmAttributes.PortGranularity = PORT_SIZE_8;
    SmmEntry->SmmPort = (UINT8)SwSmiAllocator->SwSmiCommandPort;
#endif // CONFIG_CSM_SMMENTRY_PORT_SIZE == PORT_SIZE_16
    SmmEntry->SmmData = (UINT8)CsmSwSmiInputValue;
    SoftIntData->NumSmmEntries = 1;
  }

  return Status;
} // CreateUsbIrqSwSmiTable
#endif //OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

//
// FUNCTION NAME.
//      BackupBbsTable - Backup BBS_Table for restoration.
//
// FUNCTIONAL DESCRIPTION.
//      Backup the original BBS_TABLE for restoration after booting fail.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function return - EFI status code.
//

EFI_STATUS
BackupBbsTable (VOID)
{
  SCT_STATUS Status;
  UINT16 HddCount;                      // number of entries in HddInfo.
  HDD_INFO *HddInfo;                    // points to Hard Drive information.
  UINT16 BbsCount;                      // number of entries in BBS Table.
  BBS_TABLE *BbsTable;                  // points to BBS Table.

  DPRINTF_LEGACY ("BackupBbsTable\n");

  Status = mLegacyBios->GetBbsInfo (
                          mLegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          &BbsTable);
  if (!EFI_ERROR (Status)) {

    if (mBackupBbsTable == NULL) {

      //
      // Allocate memory for backup BBS_TABLE.
      //

      mBackupBbsTable = AllocateZeroPool (BbsCount * sizeof (BBS_TABLE));
    }

    if (mBackupBbsTable == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    //
    // Backup whole BBS_Table.
    //

    CopyMem (
      mBackupBbsTable,
      BbsTable,
      BbsCount * sizeof (BBS_TABLE));
  }

  return Status;
} // BackupBbsTable


//
// FUNCTION NAME.
//      RestoreBbsTable - Restore BBS_Table from backup.
//
// FUNCTIONAL DESCRIPTION.
//      Restore the original BBS_TABLE from backup one.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function return - EFI status code.
//

EFI_STATUS
RestoreBbsTable (VOID)
{
  SCT_STATUS Status;
  UINT16 HddCount;                      // number of entries in HddInfo.
  HDD_INFO *HddInfo;                    // points to Hard Drive information.
  UINT16 BbsCount;                      // number of entries in BBS Table.
  BBS_TABLE *BbsTable;                  // points to BBS Table.

  DPRINTF_LEGACY ("RestoreBbsTable\n");

  if (mBackupBbsTable == NULL) {
    return EFI_NOT_READY;
  }

  Status = mLegacyBios->GetBbsInfo (
                          mLegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          &BbsTable);
  if (!EFI_ERROR (Status)) {

    //
    // Unlock legacyRegion first.
    //

    Status = mLegacyRegion->UnLock (
                              mLegacyRegion,
                              EGROUP_START_ADDRESS,
                              LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                              NULL);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    //
    // Restore whole BBS_Table.
    //

    CopyMem (
      BbsTable,
      mBackupBbsTable,
      BbsCount * sizeof (BBS_TABLE));

    //
    // Lock legacyRegion to protect memory.
    //

    mLegacyRegion->Lock (
                     mLegacyRegion,
                     EGROUP_START_ADDRESS,
                     LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                     NULL);
  }

  return Status;

} // RestoreBbsTable


//
// FUNCTION NAME.
//      LoadLegacyOptionRom - Load Legacy Boot Option ROM
//
// FUNCTIONAL DESCRIPTION.
//      This function load image to conventional memory area.
//
// ENTRY PARAMETERS.
//      RomGuid         - GUID of image binary.
//
// EXIT PARAMETERS.
//      Function Return - EFI_STATUS
//      Handler         - The entry (segment:offset) of OPROM.
//

EFI_STATUS
LoadLegacyOptionRom (
  IN EFI_GUID RomGuid,
  OUT UINT32 *Handler
  )
{
  EFI_STATUS Status;
  UINTN Index;
  UINTN ImageSize;
  UINT32 TmpDword;
  UINTN HandleCount;
  VOID *LocalRomImage;
  UINTN LocalRomSize;
  UINTN InitAddress;
  EFI_HANDLE *HandleBuffer;
  UINT32 AuthenticationStatus;
  EFI_PHYSICAL_ADDRESS PhysicalAddress;
  EFI_FIRMWARE_VOLUME2_PROTOCOL *FirmwareVolume;

  DPRINTF_LEGACY ("LoadLegacyOptionRom.\n");

  if (mLegacyBios == NULL) {
    return EFI_NOT_FOUND;
  }

  *Handler = 0;

  //
  // Get the list of available firmware volumes.
  //

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiFirmwareVolume2ProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  if (EFI_ERROR (Status) || HandleCount == 0) {
    return EFI_NOT_FOUND;
  }

  LocalRomImage = NULL;
  LocalRomSize  = 0;

  //
  // Loop through the Firmware Volumes looking for the specified image.
  //

  for (Index = 0; Index < HandleCount && LocalRomImage == NULL; Index++) {

    //
    // Get the Firmware Volume Protocol.
    //

    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiFirmwareVolume2ProtocolGuid,
                    (VOID **) &FirmwareVolume);
    if (EFI_ERROR (Status)) {
      continue;
    }

    //
    // See if we get the 16-bit service rom code from this Firmware Volume.
    //

    Status = FirmwareVolume->ReadSection (
                               FirmwareVolume,
                               &RomGuid,
                               EFI_SECTION_RAW,
                               0,
                               &LocalRomImage,
                               &LocalRomSize,
                               &AuthenticationStatus);

    if ((LocalRomImage != NULL) && (LocalRomSize != 0)) {

      DPRINTF_LEGACY ("  ROM image found.\n");

      ImageSize = ((EFI_LEGACY_EXPANSION_ROM_HEADER *)((UINT8 *)LocalRomImage))->Size512 * 512;

      PhysicalAddress = CONVENTIONAL_MEMORY_TOP;
      Status = (gBS->AllocatePages) (
                       AllocateMaxAddress,
                       EfiBootServicesCode,
                       EFI_SIZE_TO_PAGES (ImageSize),
                       &PhysicalAddress);

      if (EFI_ERROR (Status)) {

        //
        // Free the resource.
        //

        FreePool (HandleBuffer);
        return EFI_OUT_OF_RESOURCES;
      }

      InitAddress = (UINTN)PhysicalAddress;
      CopyMem ((VOID *)InitAddress, LocalRomImage, ImageSize);

      TmpDword = (UINT32)InitAddress;
      TmpDword = TmpDword << 12 | 0x0003;
      *Handler = TmpDword;
      break;
    }
  }

  //
  // Free the resource.
  //

  FreePool (HandleBuffer);
  return Status;

} // LoadLegacyOptionRom

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT_INT18

//
// FUNCTION NAME.
//      LegacyInt18Boot - Jump into INT18 directly.
//
// FUNCTIONAL DESCRIPTION.
//      This function use the input OptionalData as the FvFile device path to
//      find the OPROM image.
//      After the image found, it will be loaded into memory and also retrieve
//      the initialization entry handler (offset 3) as INT18 address.
//
//      The INT18 handler will also be filled in BbsTable at index
//      BBS_INT18_HOOK_BOOT_INDEX so that the legacy boot module (CSM) can be
//      aware that and hook the INT18 to jump directly.
//
// ENTRY PARAMETERS.
//      FilePathList    - The Device Path for the Device Type to boot.
//      OptionNumber    - The Option Number for this Device Path.
//      OptionalData    - The Data to pass to the boot.
//      OptionalDataLength - The number of byte of data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
LegacyInt18Boot (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN UINT16 OptionNumber,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  )
{
  EFI_TPL Tpl;
  EFI_STATUS Status, rc;
  UINT16 HddCount;                      // number of entries in HddInfo.
  HDD_INFO *HddInfo;                    // points to Hard Drive information.
  UINT16 BbsCount;                      // number of entries in BBS Table.
  BBS_TABLE *BbsTable;                  // points to BBS Table.
  UINT32 Irq18Handler;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *FvFileDevicePath;
  BBS_BBS_DEVICE_PATH BbsDevicePathNode;

  DPRINTF_LEGACY ("LegacyInt18Boot\n");

  Irq18Handler = 0;

  //
  // OptionalData must be a MEDIA_FW_VOL_DEVICE_PATH devicePath string.
  //

  if (OptionalData == NULL) {

    DPRINTF_LEGACY ("  EFI_INVALID_PARAMETER\n");
    return EFI_INVALID_PARAMETER;
  }

  //
  // Since the OptionalData will be a string, we should check if it has a
  // terminator.
  //

  if (((PCHAR16)OptionalData) [OptionalDataLength / sizeof (CHAR16) - 1] != L'\0') {
    DPRINTF_LEGACY ("  The format is not correct\n");
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get the GUID of FVFile.
  //

  DevicePath = NULL;
  DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH ((PCHAR16)OptionalData);
  if (DevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!(DevicePath->Type == MEDIA_DEVICE_PATH &&
    DevicePath->SubType == MEDIA_PIWG_FW_FILE_DP)) {
    SafeFreePool (DevicePath);
    return EFI_INVALID_PARAMETER;
  }

  FvFileDevicePath = (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)DevicePath;
  Status = LoadLegacyOptionRom (FvFileDevicePath->FvFileName, &Irq18Handler);
  SafeFreePool (DevicePath);
  if (EFI_ERROR (Status) || Irq18Handler == 0) {
    return EFI_NOT_FOUND;
  }

  DPRINTF_LEGACY ("  Irq18Handler 0x%x.\n", Irq18Handler);

  //
  // Initialize Legacy first.
  //

  Status = InitializeLegacy ();
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  Failed to initialize legacy.\n");
    return Status;
  }

  //
  // Create a BBS device path for INT18 legacy boot.
  //

  BbsDevicePathNode.DeviceType = BBS_TYPE_UNKNOWN;
  BbsDevicePathNode.Header.Type = BBS_DEVICE_PATH;
  BbsDevicePathNode.Header.SubType = BBS_BBS_DP;
  SetDevicePathNodeLength (&BbsDevicePathNode.Header, sizeof (BBS_BBS_DEVICE_PATH));
  BbsDevicePathNode.StatusFlag = 0;
  BbsDevicePathNode.String [0] = 0;

  //
  // Get the BBS Table from the LegacyBios driver.
  //

  Status = mLegacyBios->GetBbsInfo (
                          mLegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          &BbsTable);
  DPRINTF_LEGACY ("  GetBbsInfo returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // LegacyBios->GetBbsInfo locks the Legacy Region that has the IbvBbs Table.
  // Unlock it again.
  //

  Status = mLegacyRegion->UnLock (
                            mLegacyRegion,
                            EGROUP_START_ADDRESS,
                            LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                            NULL);
  DPRINTF_LEGACY ("  mLegacyRegion->UnLock returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Fill the BBS_INT18_HOOK_BOOT_INDEX Bbs entry so that the CSM can be aware
  // that and jump into INT18 handler directly.
  //

  ZeroMem (
    &(BbsTable [BBS_INT18_HOOK_BOOT_INDEX]),
    sizeof (BBS_TABLE));

  BbsTable [BBS_INT18_HOOK_BOOT_INDEX].DeviceType = BBS_TYPE_UNKNOWN;
  BbsTable [BBS_INT18_HOOK_BOOT_INDEX].AdditionalIrq18Handler = Irq18Handler;

  mLegacyRegion->Lock (
                   mLegacyRegion,
                   EGROUP_START_ADDRESS,
                   LEGACY_REGION_TOP - EGROUP_START_ADDRESS,
                   NULL);

  PERF_START (0, "LegacyInt18Boot", "PrepareToBootLegacy", 0);
  Status = PrepareToBootLegacy (OptionNumber);
  PERF_END (0, "LegacyInt18Boot", "PrepareToBootLegacy", 0);

  Tpl = SetTpl (TPL_APPLICATION);

  rc = mLegacyBios->LegacyBoot (
                      mLegacyBios,
                      &BbsDevicePathNode,
                      OptionalDataLength,
                      OptionalData);

  SetTpl (Tpl);

  DPRINTF_LEGACY ("  LegacyBoot returned %r, Signal Boot Fail\n", rc);
  Status = SignalBootFail (SCT_BDS_LEGACY_BOOT_FAIL);
  DPRINTF_LEGACY ("  SignalBootFail returned %r\n", Status);

  return rc;

} // LegacyInt18Boot
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT_INT18


//
// FUNCTION NAME.
//      FillIbvUsbDiskInfo - Fill USB disk information.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called to create USB disk informations.
//      The USB information will be retrieved from each BbsTable entry which
//      created by CSM32.
//
// ENTRY PARAMETERS.
//      IbvBbs          - Point to IBV specific table.
//      BbsCount        - Number of BBS entry.
//      BbsTable        - Point to BbsTable.
//      BbsTableDevicePaths - Buffer that stores bootable device path.
//
// EXIT PARAMETERS.
//      None.
//

VOID
FillIbvUsbDiskInfo (
  IN OUT PIBV_BBS_TABLE IbvBbs,
  IN UINT16 BbsCount,
  IN BBS_TABLE *BbsTable,
  IN EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths
  )
{
  UINT8 Index;
  UINT8 LunNum;
  UINT16 BbsEntryIndex;
  UINT16 DeviceCount;
  UINT8 FddNumber;
  UINT8 ZipNumber;
  UINT8 FunctionNumber;
  UINT8 DeviceNumber;
  UINT8 BusNumber;
  USB_DISK_INFO *UsbDiskInfo;
  USB_DISK_TYPE *UsbDiskType;
  UINT8 UsbDiskInfoIndex;
  UINT8 UsbParentHubIndex;
  USB_DEVICE_PATH *Usb;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;

  Index = 0;
  LunNum = 0;
  DeviceCount = 0;
  FddNumber = 0;
  ZipNumber= 0;
  FunctionNumber = 0;
  DeviceNumber = 0;
  BusNumber = 0;
  UsbParentHubIndex = 0xff;
  UsbDiskInfoIndex = 0;

  DPRINTF_LEGACY ("FillIbvUsbDiskInfo \n");

  for (BbsEntryIndex = 0; BbsEntryIndex < BbsCount; BbsEntryIndex++) {

    //
    // Filter out the entry which is not USB device.
    //

    if ((BbsTable [BbsEntryIndex].BootPriority == BBS_IGNORE_ENTRY) ||
        (BbsTable [BbsEntryIndex].BootPriority == BBS_DO_NOT_BOOT_FROM) ||
        (BbsEntryIndex < BBS_USB_RESERVATION_START_INDEX)) {
      continue;
    }

    UsbDiskType = (USB_DISK_TYPE *)&BbsTable [BbsEntryIndex].InitPerReserved;
    if (UsbDiskType->BbsType != BBS_USB) {
      continue;
    }

    DPRINTF_LEGACY ("  BBS Entry 0x%x \n", BbsEntryIndex);

    //
    // Retrieve Pci address from BBS table entry.
    //

    FunctionNumber = (UINT8)BbsTable [BbsEntryIndex].Function;
    DeviceNumber = (UINT8)BbsTable [BbsEntryIndex].Device;
    BusNumber = (UINT8)BbsTable [BbsEntryIndex].Bus;

    UsbDiskInfo = (USB_DISK_INFO *)&BbsTable [BbsEntryIndex].IBV1;

    //
    // Retrieve corresponding device path from BbsTableDevicePaths.
    //

    TempDevicePath = BbsTableDevicePaths [BbsEntryIndex];

    DEBUG_LEGACY ({
      CHAR16* Str = NULL;
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (TempDevicePath, FALSE, TRUE);
      DPRINTF_LEGACY (" Device path :%s.\n", Str);
      SafeFreePool (Str);
    });

    //
    // Walks through each device node and creates the diskInfo.
    //

    UsbParentHubIndex = 0xff;
    while (!IsDevicePathEndType (TempDevicePath)) {
      LunNum = 0xff;

      if (MESSAGING_DEVICE_PATH == DevicePathType (TempDevicePath)) {
        switch (DevicePathSubType (TempDevicePath)) {

          case MSG_DEVICE_LOGICAL_UNIT_DP:
            LunNum = ((DEVICE_LOGICAL_UNIT_DEVICE_PATH *)TempDevicePath)->Lun;

          case MSG_USB_DP:
            Usb = (USB_DEVICE_PATH *)TempDevicePath;
            IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoPFA.PFA.BusNumber = BusNumber;
            IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoPFA.PFA.DeviceNumber = DeviceNumber;
            IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoPFA.PFA.FunctionNumber = FunctionNumber;

            if (!IsDevicePathEndType (NextDevicePathNode (TempDevicePath))) {

              DPRINTF_LEGACY ("  USB hub node - ");

              //
              // This node is USB hub.
              //

              for (Index = 0; Index < UsbDiskInfoIndex; Index++) {
                if (IbvBbs->UsbDiskInfo [Index].DiskInfoPFA.PFA.BusNumber == BusNumber &&
                    IbvBbs->UsbDiskInfo [Index].DiskInfoPFA.PFA.DeviceNumber == DeviceNumber &&
                    IbvBbs->UsbDiskInfo [Index].DiskInfoPFA.PFA.FunctionNumber == FunctionNumber &&
                    IbvBbs->UsbDiskInfo [Index].DiskInfoPhyIDPort == Usb->ParentPortNumber &&
                    IbvBbs->UsbDiskInfo [Index].DiskInfoParentHubIndex == UsbParentHubIndex) {
                  break;
                }
              }

              if (Index != UsbDiskInfoIndex) {
                UsbParentHubIndex = Index;
                TempDevicePath = NextDevicePathNode (TempDevicePath);
                DPRINTF_LEGACY ("  duplicated. \n");
                continue;

              } else {
                IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceType = BBS_USB_BULK_HUB_DEVICE_TYPE;
                IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceOrderIndex = 0xff;
                IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoParentHubIndex = UsbParentHubIndex;
                IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoPhyIDPort = Usb->ParentPortNumber;
                IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoInterfaceNumber = Usb->InterfaceNumber;
                IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoLUN = 0xff;
                UsbParentHubIndex = UsbDiskInfoIndex;
                DPRINTF_LEGACY ("  created. \n");

              }

            } else {

              //
              // USB Block IO device, should be the last device path node before "end node".
              //

              DPRINTF_LEGACY ("  USB device with BlockIo - Type: ");

              IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceType = UsbDiskType->DeviceType;
              IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoParentHubIndex = UsbParentHubIndex;
              IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoPhyIDPort = Usb->ParentPortNumber;
              IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoInterfaceNumber = Usb->InterfaceNumber;
              IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoLUN = LunNum;

              switch (UsbDiskType->DeviceType) {
                case BBS_USB_UFI_FDD_DEVICE_TYPE:
                  DPRINTF_LEGACY ("BBS_USB_UFI_FDD_DEVICE_TYPE");
                  IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceOrderIndex = \
                    (UINT8)BbsEntryIndex - BBS_USB_FLOPPY_START_INDEX + USBFDD_BOOT_START_INDEX - ZipNumber;
                  FddNumber++;
                  break;

                case BBS_USB_BULK_ZIP_FDD_DEVICE_TYPE:
                  DPRINTF_LEGACY ("BBS_USB_BULK_ZIP_FDD_DEVICE_TYPE");
                  IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceOrderIndex = \
                    (UINT8)BbsEntryIndex - BBS_USB_FLOPPY_START_INDEX + USBZIP_BOOT_START_INDEX - FddNumber;
                  ZipNumber++;
                  break;

                case BBS_USB_HDD_DEVICE_TYPE:
                  DPRINTF_LEGACY ("BBS_USB_HDD_DEVICE_TYPE");
                  IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceOrderIndex = \
                    (UINT8)BbsEntryIndex - BBS_USB_HARDDISK_START_INDEX + USBHDD_BOOT_START_INDEX;
                  break;

                case BBS_USB_BULK_CDROM_DEVICE_TYPE:
                  DPRINTF_LEGACY ("BBS_USB_BULK_CDROM_DEVICE_TYPE");
                  IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceOrderIndex = \
                    (UINT8)BbsEntryIndex - BBS_USB_CDROM_START_INDEX + USBCDROM_BOOT_START_INDEX;
                  break;

                default:
                  IbvBbs->UsbDiskInfo [UsbDiskInfoIndex].DiskInfoDeviceOrderIndex = 0xFF;
                  break;
              }
              DPRINTF_LEGACY ("  created. \n");
            }

            UsbDiskInfoIndex++;

            if (UsbDiskInfoIndex >= MAX_USB_DEVICE_NUM) {
              return;
            }
            break;

          default:
            break;
        }
      }

      //
      // Walks to the next device path node.
      //

      TempDevicePath = NextDevicePathNode (TempDevicePath);
    }
  }

} // FillIbvUsbDiskInfo

//
// FUNCTION NAME.
//      GetBbsEntryByIndex - Get Bbs entry according to index.
//
// FUNCTIONAL DESCRIPTION.
//      This function will finds the BbsTable entry according to the index.
//
// ENTRY PARAMETERS.
//      BbsIndex        - Index of BbsTable entry.
//
// EXIT PARAMETERS.
//      BbsEntry        - Pointer points to the BbsTable entry.
//      Function Return - EFI status code.
//

SCT_STATUS
GetBbsEntryByIndex (
  IN UINT16 BbsIndex,
  OUT BBS_TABLE **BbsEntry
  )
{
  UINT16 HddCount;
  UINT16 BbsCount;
  HDD_INFO *HddInfo;
  SCT_STATUS Status;
  BBS_TABLE *BbsTable;

  HddCount = 0;
  BbsCount = 0;

  DPRINTF_LEGACY (":\n");

  if (BbsEntry == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get the BBS Table from the LegacyBios driver.
  //

  if (mLegacyBios == NULL) {
    return SCT_STATUS_NOT_READY;
  }

  Status = mLegacyBios->GetBbsInfo (
                          mLegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          &BbsTable);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *BbsEntry = &BbsTable [BbsIndex];
  return SCT_STATUS_SUCCESS;

} // GetBbsEntryByIndex


//
// FUNCTION NAME.
//      GetBbsTableDevicePathByIndex - Get Bbs entry according to index.
//
// FUNCTIONAL DESCRIPTION.
//      This function will finds the BbsTable DevicePath according to the
//      BbsTable index.
//
// ENTRY PARAMETERS.
//      BbsIndex        - Index of BbsTable entry.
//
// EXIT PARAMETERS.
//      DevicePath      - Pointer points to pointer to BbsTable DevicePath table.
//      Function Return - EFI status code.
//

SCT_STATUS
GetBbsTableDevicePathByIndex (
  IN UINT16 BbsIndex,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath
  )
{
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths;

  Status = gBS->LocateProtocol (
                  &gBbsTableDevicePathsTableGuid,
                  NULL,
                  (VOID **)&BbsTableDevicePaths);
  if (EFI_ERROR (Status)) {
    DPRINTF_LEGACY ("  LocateProtocol fail \n");
    *DevicePath = NULL;
    return Status;
  }

  if (BbsTableDevicePaths [BbsIndex] == NULL) {
    *DevicePath = NULL;
    return EFI_NOT_FOUND;
  }

  *DevicePath = BbsTableDevicePaths [BbsIndex];

  return EFI_SUCCESS;

} // GetBbsTableDevicePathByIndex


//
// FUNCTION NAME.
//      BuildDescriptionFromBbsEntry - Get BBS description from BbsTable entry.
//
// FUNCTIONAL DESCRIPTION.
//      This function will build the description string from the BbsTable entry.
//
// ENTRY PARAMETERS.
//      BbsEntry        - BbsTable entry.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to pointer to device description string.
//      Function Return - EFI status code.
//

SCT_STATUS
BuildDescriptionFromBbsEntry (
  IN BBS_TABLE *BbsEntry,
  OUT PCHAR16 *Description
  )
{
  UINT8 i;
  PCHAR8 Temp;
  UINT16 Offset;
  UINT16 Segment;
  UINTN BufferSize;
  CHAR8 AsciiDesc [CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH + 1];

  if (BbsEntry == NULL || Description == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  *Description = NULL;
  Segment = BbsEntry->DescStringSegment;
  Offset = BbsEntry->DescStringOffset;
  Temp = (CHAR8 *)(UINTN)((Segment << 4) + Offset);

  //
  // According to BBS Spec. 3.1.2, the max length of visible string is
  // 32 bytes. Plus the additional NULL terminator, we allocate 33 bytes.
  //

  BufferSize = CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH + 1;

  ZeroMem (AsciiDesc, BufferSize);
  CopyMem (
    AsciiDesc,
    Temp,
    BufferSize);

  //
  // Check if Product Name string length exceed the maximum visible range.
  //

  for (i = 0; i < BufferSize; i++) {
    if (*(AsciiDesc + i) == 0) {
      break;
    }
  }

  //
  // If no terminated character found, truncate string length to 32.
  //

  if (i == BufferSize) {
    *(AsciiDesc + CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH) = 0;
  }

  //
  // Transfer to Unicode string.
  //

  BufferSize = (AsciiStrLen (AsciiDesc) + 1) * sizeof (CHAR16);
  *Description = (CHAR16 *)AllocateZeroPool (BufferSize);

  if (*Description == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  BopLibAsciiToUnicode (AsciiDesc, *Description);
  SctStrTrim (*Description, L' ');

  return SCT_STATUS_SUCCESS;
} // BuildDescriptionFromBbsEntry


//
// FUNCTION NAME.
//      UpdateLegacyUsbToBbsTable - Update BbsTable for USB devices.
//
// FUNCTIONAL DESCRIPTION.
//      This function will retrieve all USB devices in system and record the
//      information into BbsTable if those devices have not yet been filled.
//
//      This function will return SCT_STATUS_SUCCESS when both UsbDevicePath and
//      BbsTableIndex are passed and the matched information have been filled
//      in BbsTable.
//
// ENTRY PARAMETERS.
//      BbsTable        - Pointer points to BbsTable.
//      BbsCount        - Total number of BbsTable entry.
//      BbsTableDevicePaths - Pointer points to BbsTableDevicePaths.
//      UsbDevicePath   - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      BbsTableIndex   - Index of the BbsTable for UsbDevicePath.
//      Function Return - EFI status code.
//

SCT_STATUS
UpdateLegacyUsbToBbsTable (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsCount,
  IN EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths,
  IN EFI_DEVICE_PATH_PROTOCOL *UsbDevicePath OPTIONAL,
  OUT int *BbsTableIndex OPTIONAL
  )
{
  UINT16 i;
  UINTN Index;
  SCT_STATUS Status;
  SCT_STATUS ReturnStatus;
  UINT8 UsbPortIndex;
  UINT8 UsbType;
  UINTN NumberBlockIoHandles;
  EFI_HANDLE *BlockIoHandles;
  EFI_BLOCK_IO_PROTOCOL *BlkIo;
  UINTN DevicePathBootType;
  UINT8 BbsDeviceType;
  UINT8 DeviceIndexStart;
  UINT8 MaxDeviceSupport;
  USB_DISK_INFO *UsbDiskInfo;
  USB_DISK_TYPE *UsbDiskType;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;
  EFI_HANDLE PciHandle;
  EFI_HANDLE ParentDevice;
  EFI_PCI_IO_PROTOCOL *PciIo;
  EFI_USB_IO_PROTOCOL *UsbIo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_USB_INTERFACE_DESCRIPTOR UsbInterfaceDesc;
  UINTN SegmentNumber, BusNumber, DeviceNumber, FunctionNumber;

  DPRINTF_LEGACY ("UpdateLegacyUsbToBbsTable:\n");

  //
  // Check input parameters first.
  //

  if (BbsTable == NULL || BbsTableDevicePaths == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  if ((UsbDevicePath == NULL && BbsTableIndex != NULL) ||
      (UsbDevicePath != NULL && BbsTableIndex == NULL)) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  DeviceIndexStart = 0;
  MaxDeviceSupport = 0;
  NumberBlockIoHandles = 0;
  BlockIoHandles = NULL;

  if (UsbDevicePath != NULL && BbsTableIndex != NULL) {
    ReturnStatus = SCT_STATUS_NOT_FOUND;
  } else {
    ReturnStatus = SCT_STATUS_SUCCESS;
  }

  gBS->LocateHandleBuffer (
         ByProtocol,
         &gEfiBlockIoProtocolGuid,
         NULL,
         &NumberBlockIoHandles,
         &BlockIoHandles);

  if (NumberBlockIoHandles == 0) {
    return SCT_STATUS_NOT_FOUND;
  }

  for (Index = 0; Index < NumberBlockIoHandles; Index++) {
    Status = gBS->HandleProtocol (
                    BlockIoHandles [Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **)&BlkIo);
    if (EFI_ERROR (Status)) {
      DPRINTF_LEGACY ("  Unexpected error opening BlockIo, %r.\n", Status);
      continue;
    }

    UsbPortIndex = 0;
    DevicePath = DevicePathFromHandle (BlockIoHandles [Index]);
    DevicePathBootType = GetBootTypeFromDevicePath (DevicePath);

    if (DevicePathBootType != BDS_EFI_MESSAGE_USB_DEVICE_BOOT) {
      DPRINTF_LEGACY ("  BlockIo %d is not a USB Boot Device\n", Index);
      continue;
    }

    DPRINTF_LEGACY ("  BlockIo %d is a USB Boot Device\n", Index);


    //
    // If DevicePath is already existing in BbsTableDevicePaths, ignore it.
    //

    for (i = BBS_USB_RESERVATION_START_INDEX; i < BbsCount; i++) {
      if (BbsTableDevicePaths [i] != NULL) {
        if (CompareDevicePath (DevicePath, BbsTableDevicePaths [i])) {
          break;
        }
      }
    }

    if (i != BbsCount) {
      continue;
    }

    DPRINTF_LEGACY ("  Add new USB MSD to BBS Table\n");

    //
    // Get USB device type and corresponding BBS_TYPE.
    //

    BbsDeviceType = GetUsbBbsDeviceType (BlkIo);
    DPRINTF_LEGACY ("GetUsbBbsDeviceType BbsDeviceType = 0x%x\n", BbsDeviceType);

    if (BbsDeviceType == BBS_UNKNOWN) {
      continue;
    }

    //
    // Determine USB Type by BBS Type.
    //

    if (BbsDeviceType == BBS_FLOPPY) {
      UsbType = BBS_USB_UFI_FDD_DEVICE_TYPE;
    } else if (BbsDeviceType == BBS_CDROM) {
      UsbType = BBS_USB_BULK_CDROM_DEVICE_TYPE;
    } else {
      UsbType = BBS_USB_HDD_DEVICE_TYPE;
    }

    //
    // Overwrite USB Type by interface subclass.
    //

    Status = gBS->HandleProtocol (
                    BlockIoHandles [Index],
                    &gEfiUsbIoProtocolGuid,
                    (VOID **)&UsbIo);

    //
    // If this handle has no USB_IO, try to get from its parent.
    //

    if (EFI_ERROR (Status)) {

      ParentDevice = NULL;
      RemainingDevicePath = DevicePath;
      Status = gBS->LocateDevicePath (
                      &gEfiUsbIoProtocolGuid,
                      &RemainingDevicePath,
                      &ParentDevice);

      if (!EFI_ERROR (Status)) {
        Status = gBS->HandleProtocol (
                        ParentDevice,
                        &gEfiUsbIoProtocolGuid,
                       (VOID **)&UsbIo);
      }
    }

    if (!EFI_ERROR (Status)) {
      Status = UsbIo->UsbGetInterfaceDescriptor (UsbIo, &UsbInterfaceDesc);
      if (!EFI_ERROR (Status)) {
        if (UsbInterfaceDesc.InterfaceSubClass == USB_MASS_STORE_UFI) {
          UsbType = BBS_USB_UFI_FDD_DEVICE_TYPE;
        } else if (UsbInterfaceDesc.InterfaceSubClass == USB_MASS_STORE_8070I) {
          UsbType = BBS_USB_BULK_ZIP_FDD_DEVICE_TYPE;
        }
      }
    }

    if (IsDeviceInFddEmulationMode (BlkIo)) {
      UsbType = BBS_USB_BULK_ZIP_FDD_DEVICE_TYPE;
    }

    //
    // Ignore the USB devcie which belongs to HARDDISK type but
    // no media presented.
    //

    if ((BbsDeviceType == BBS_HARDDISK) && (!BlkIo->Media->MediaPresent)) {
      DPRINTF_LEGACY ("  Ignore the USB HDD Device w/o any media \n");
      continue;
    }

    switch (BbsDeviceType) {
      case BBS_FLOPPY:
        DeviceIndexStart = BBS_USB_FLOPPY_START_INDEX;
        MaxDeviceSupport = USBFDD_BOOT_END_INDEX - USBFDD_BOOT_START_INDEX + 1;
      break;

      case BBS_HARDDISK:
        DeviceIndexStart = BBS_USB_HARDDISK_START_INDEX;
        MaxDeviceSupport = USBHDD_BOOT_END_INDEX - USBHDD_BOOT_START_INDEX + 1;
      break;

      case BBS_CDROM:
        DeviceIndexStart = BBS_USB_CDROM_START_INDEX;
        MaxDeviceSupport = USBCDROM_BOOT_END_INDEX - USBCDROM_BOOT_START_INDEX + 1;
      break;
    }

    for (i = DeviceIndexStart; i < DeviceIndexStart + MaxDeviceSupport; i++) {
      if (BbsTableDevicePaths [i] == NULL) {
        break;
      }
    }

    if (i == DeviceIndexStart + MaxDeviceSupport) {
      continue;
    }

    //
    // Initialize legacy device context.
    //

    DPRINTF_LEGACY ("  Add new entry in BBS Table Index = 0x%x \n", i);


    BbsTableDevicePaths [i] = DuplicateDevicePath (DevicePath);

    BbsTable [i].BootPriority = BBS_UNPRIORITIZED_ENTRY;
    BbsTable [i].DeviceType = BbsDeviceType;
    BbsTable [i].Bus = 0xff;
    BbsTable [i].Device = 0xff;
    BbsTable [i].Function = 0xff;
    BbsTable [i].Class = 01;
    BbsTable [i].SubClass = 01;
    BbsTable [i].IBV1 = 0xffffffff;
    BbsTable [i].IBV2 = 0xffffffff;

    UsbDiskInfo = (USB_DISK_INFO *)&BbsTable [i].IBV1;
    UsbDiskType = (USB_DISK_TYPE *)&BbsTable [i].InitPerReserved;
    UsbDiskType->BbsType = BBS_USB;
    UsbDiskType->InterfaceSubClass = 0;
    UsbDiskType->DeviceType = UsbType;
    UsbDiskInfo->BbsIndex = (UINT8)i;

    //
    // Get the USB host controller PFA.
    //

    TempDevicePath = DevicePath;
    Status = gBS->LocateDevicePath (
                    &gEfiPciIoProtocolGuid,
                    &TempDevicePath,
                    &PciHandle);

    if (!EFI_ERROR (Status)) {
      Status = gBS->HandleProtocol (
                      PciHandle,
                      &gEfiPciIoProtocolGuid,
                      &PciIo);

      if (!EFI_ERROR (Status)) {

        Status = PciIo->GetLocation (
                          PciIo,
                          &SegmentNumber,
                          &BusNumber,
                          &DeviceNumber,
                          &FunctionNumber);
        if (!EFI_ERROR (Status)) {
          BbsTable [i].Bus = (UINT8)BusNumber;
          BbsTable [i].Device = (UINT8)DeviceNumber;
          BbsTable [i].Function = (UINT8)FunctionNumber;
        }
      }
    }

    while (!IsDevicePathEndType (TempDevicePath)) {
      switch (DevicePathType (TempDevicePath)) {

        case MESSAGING_DEVICE_PATH:
          if (IsDevicePathEndType (NextDevicePathNode (TempDevicePath))) {
            if (DevicePathSubType (TempDevicePath) == MSG_DEVICE_LOGICAL_UNIT_DP) {
              UsbDiskInfo->DiskInfoLUN = ((DEVICE_LOGICAL_UNIT_DEVICE_PATH *)TempDevicePath)->Lun;
            }
          }
          if (DevicePathSubType (TempDevicePath) == MSG_USB_DP) {
            for (UsbPortIndex = 0; UsbPortIndex < MAX_USB_HUB_DEPTH_NUMBER; UsbPortIndex++) {
              if (UsbDiskInfo->DiskPortInfo [UsbPortIndex] == 0xff) {
                UsbDiskInfo->DiskPortInfo [UsbPortIndex] = ((USB_DEVICE_PATH *)TempDevicePath)->ParentPortNumber;
                break;
              }
            }
          }
          break;

        default:
          break;
      }
      TempDevicePath = NextDevicePathNode (TempDevicePath);
    }

    if (UsbDevicePath != NULL && BbsTableIndex != NULL) {
      if (CompareDevicePath (DevicePath, UsbDevicePath)) {
        *BbsTableIndex = i;
        ReturnStatus = SCT_STATUS_SUCCESS;
      }
    }

  }

  //
  // Freed the resource.
  //

  SafeFreePool (BlockIoHandles);
  return ReturnStatus;

} // UpdateLegacyUsbToBbsTable

#if OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER


//
// FUNCTION NAME.
//      CompareDevOrderDevicePath - Determine device path presence in BbsTableDevicePaths.
//
// FUNCTIONAL DESCRIPTION.
//      This function will search in the BbsTableDevicePaths for a specific
//      device path.
//
// ENTRY PARAMETERS.
//      Buffer          - DeviceOrder buffer.
//      StartIndex      - Starting index of DeviceOrder.
//      Count           - Total number of DeviceOrder of specific device type.
//      FilePathList    - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//      FoundIndex      - The matched index in DeviceOrder.
//
// EXIT PARAMETERS.
//      BOOLEAN         - True, the specific device path is found.
//                        False, otherwise.
//

BOOLEAN
EFIAPI
CompareDevOrderDevicePath (
  IN UINT16 *Buffer,
  IN UINTN StartIndex,
  IN UINTN Count,
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  OUT UINTN *FoundIndex
  )
{
  UINTN Index;
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths;

  DEBUG_DN ({
    CHAR16* Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (FilePathList, FALSE, TRUE);
    DPRINTF_DN ("S: %S\n", Str);
    SafeFreePool (Str);
  });

  Status = gBS->LocateProtocol (
                  &gBbsTableDevicePathsTableGuid,
                  NULL,
                  (VOID **)&BbsTableDevicePaths);
  if (EFI_ERROR (Status)) {
    DPRINTF_DN("Error get BbsTableDevicePathsTable\n");
    return FALSE;
  }

  for (Index = StartIndex; Index < Count; Index++) {
    if (BbsTableDevicePaths [Buffer [Index]] != NULL) {

      DEBUG_DN ({
        CHAR16* Str = NULL;
        Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (BbsTableDevicePaths [Buffer [Index]], FALSE, TRUE);
        DPRINTF_DN ("T: %S\n", Str);
        SafeFreePool (Str);
      });

      if (CompareDevicePath (FilePathList, BbsTableDevicePaths [Buffer [Index]])) {
        DPRINTF_DN ("*****Match*****\n");
        *FoundIndex = Index;
        return TRUE;
      }
    }
  }

  return FALSE;
} // CompareDevOrderDevicePath


//
// FUNCTION NAME.
//      SearchBootOptionInDevOrder - Determine device path presence in DeviceOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function will search in DeviceORder for a specific device path.
//
// ENTRY PARAMETERS.
//      FilePathList     - Pointer points EFI_DEVICE_PATH_PROTOCOL.
//      NumberOfFilePaths - Number of EFI_DEVICE_PATH_PROTOCOL instance.
//      Buffer          - DeviceOrder buffer.
//      StartIndex      - Starting index of DeviceOrder.
//      Count           - Total number of DeviceOrder of specific device type.
//      FoundIndex      - The matched index in DeviceOrder.
//
// EXIT PARAMETERS.
//      BOOLEAN         - True, if specific device path is found.
//                        False, otherwise.
//

BOOLEAN
EFIAPI
SearchBootOptionInDevOrder (
  IN  EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN  UINTN NumberOfFilePaths,
  IN  UINT16 *Buffer,
  IN  UINTN StartIndex,
  IN  UINTN Count,
  OUT UINTN *FoundIndex
  )
{
  UINTN Index;
  BOOLEAN Found;
  SCT_STATUS Status;
  UINTN NumberOfDevicePaths;
  EFI_DEVICE_PATH_PROTOCOL *TmpFilePathList;
  EFI_DEVICE_PATH_PROTOCOL *ExpandedDevicePaths;

  Found = FALSE;
  DPRINTF_DN ("SearchBootOptionInDevOrder:\n");

  if ((FilePathList == NULL) || (NumberOfFilePaths == 0)) {
    DPRINTF_DN (" No path to launch!\n");
    return FALSE;
  }

  TmpFilePathList = FilePathList;
  for (Index = 0; Index < NumberOfFilePaths; Index++, TmpFilePathList = NextDevicePath (TmpFilePathList)) {
    NumberOfDevicePaths = 0;
    ExpandedDevicePaths = NULL;

    Status = EFI_ABORTED;
#if !OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

    Status = ExpandDevicePath (
               TmpFilePathList,
               &ExpandedDevicePaths,
               &NumberOfDevicePaths);
#else
   Status = BootOptionProtocolDevicePathExpansion (
              TmpFilePathList,
              &ExpandedDevicePaths,
              &NumberOfDevicePaths);
   DPRINTF_DN ("Bop Status =%r\n", Status);

#endif // !OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
    if (EFI_ERROR (Status)) {

      Found = CompareDevOrderDevicePath (
                Buffer,
                StartIndex,
                Count,
                TmpFilePathList,
                FoundIndex);

    } else {

      Found = SearchBootOptionInDevOrder (
                ExpandedDevicePaths,
                NumberOfDevicePaths,
                Buffer,
                StartIndex,
                Count,
                FoundIndex);

    }

    SafeFreePool (ExpandedDevicePaths);

    if (Found) {
      break;
    }
  }

  DPRINTF_DN ("Return Found=0x%x\n", Found);
  return Found;
} // SearchBootOptionInDevOrder

//
//
// FUNCTION NAME.
//      FindLegacyBoot - Find the Legacy device order according to BootOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function find the legacy boot devices according to
//      the value of the BootOrder variable.
//
// ENTRY PARAMETERS.
//      Buffer          - DeviceOrder order buffer.
//      Count           - Total number of DeviceOrder of specific device type.
//      Option          - a pointer to BootOption.
//      FindIndex       - a pointer to FoundIndex.
//

BOOLEAN
EFIAPI
FindLegacyBoot(
  IN UINT16 *Buffer,
  IN UINTN Count,
  IN PLOAD_OPTION_OBJECT Option,
  IN  UINTN StartIndex,
  UINTN *FoundIndex
  )
{
  UINT8 *Ptr;

  BOOLEAN Found;
  UINTN TempSize;

  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePaths;

  DPRINTF_LO (" FindLegacyBoot, Count=0x%x\n", Count);
  Found = FALSE;

  if ( Count <= 1 ) {
    return FALSE;
  }

  //
  // Retrieve the last node from the input devicePath.
  //

  LastNode = GetLastDeviceNode (Option->FilePathList);
  if (LastNode != NULL) {
    DPRINTF_LO ("DataLength=0x%x\n", LastNode->Type, LastNode->SubType);
    if (LastNode->Type != BBS_DEVICE_PATH ) {
      DPRINTF_LO ("Not BBS\n");
      return FALSE;
    } // if (LastNode->Type != BBS_DEVICE_PATH )
  } else {

    DPRINTF_LO ("LastNode=NULL\n");
    return FALSE;
  } // if (LastNode != NULL) {
  if (Option->OptionalDataLength == 0) {
    return FALSE;
  }

  DPRINTF_LO ("OptionalDataLength=0x%x\n", Option->OptionalDataLength);

  Ptr = Option->OptionalData;
  TempSize = Option->OptionalDataLength;
  DPRINTF_LO ("DataLength=0x%x\n", TempSize);
  TempSize = sizeof (BBS_TABLE) + sizeof (UINT16);

  DPRINTF_LO ("BBSLength=0x%x\n", TempSize);
  if (Option->OptionalDataLength > TempSize) {
    Ptr = Ptr + TempSize;
    TempDevicePaths = (EFI_DEVICE_PATH_PROTOCOL *)Ptr;

    Found = CompareDevOrderDevicePath (
              Buffer,
              StartIndex,
              Count,
              TempDevicePaths,
              FoundIndex);
    return Found;

  } else {

    DPRINTF_LO ("No BBS\n");
    return FALSE;
  }
}


//
// FUNCTION NAME.
//      ArrangeDevOrderAccordingToBootOrder - Sort device order according to BootOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function arranges the boot devices by sorting them according to
//      the value of the BootOrder variable.
//
// ENTRY PARAMETERS.
//      Buffer          - DeviceOrder order buffer.
//      Count           - Total number of DeviceOrder of specific device type.
//

VOID
EFIAPI
ArrangeDevOrderAccordingToBootOrder (
  IN UINT16 *Buffer,
  IN UINTN Count
  )
{
  UINTN Index;
  BOOLEAN Found;
  UINT16 TmpUINT16;
  UINTN StartIndex;
  UINTN FoundIndex;
  UINTN FoundCount;
  SCT_STATUS Status;
  PUINT16 BootOrder;
  BOOLEAN LegacyFlag;
  UINTN BootOrderSize;
  UINTN BootOrderIndex;
  PLOAD_OPTION_OBJECT Option;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *p;

  FoundCount = 0;

  //
  // Get the "BootOrder" variable.
  //

  if ( Count <= 1 ) {
    return;
  }

  BootOrder = NULL;
  BootOrderSize = 0;

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,
             &BootOrderSize,
             (VOID **) &BootOrder);
  if (EFI_ERROR(Status)) {
    return;
  }

  StartIndex = 0;
  for (BootOrderIndex = 0; BootOrderIndex < BootOrderSize / sizeof (UINT16); BootOrderIndex++) {

    //
    // Get Boot Option.
    //

    Option = NULL;
    LegacyFlag = FALSE;
    Status = GetBootOption (BootOrder [BootOrderIndex], &Option);
    if (EFI_ERROR(Status) || Option == NULL) {
      continue;
    }

    //
    // Check if the BootOption is active.
    //

    if ((Option->Attributes & LOAD_OPTION_ACTIVE) != LOAD_OPTION_ACTIVE ) {
      continue;
    }

    //
    // Skip LAN BootOption.
    //

    if (IsDeviceNodeBootOptionProtocol (Option->FilePathList)) {

      //
      // If this is an OEM Expansion Node, ignore the LAN BOP.
      //

      p = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *)Option->FilePathList;

      if (CompareGuid (&(p->ProtocolGuid), &gPciLanBootOptionProtocolGuid)) {
        continue;
      }
    }

    //
    // Search installed device for this Boot Order.
    //

    LastNode = GetLastDeviceNode (Option->FilePathList);
    if ((LastNode != NULL) && (LastNode->Type == BBS_DEVICE_PATH )) {
      LegacyFlag = TRUE;
    }

    if (LegacyFlag) {
      Found = FindLegacyBoot (Buffer,Count, Option, StartIndex, &FoundIndex);
    } else {
      Found = SearchBootOptionInDevOrder (
                Option->FilePathList,
                Option->NumberOfFilePaths,
                Buffer,
                StartIndex,
                Count,
                &FoundIndex);
    }

    //
    // If found, fill DevOrder according "BootOption".
    //

    if (Found) {
      FoundCount++;
      for (Index = FoundIndex; (INTN)Index > (INTN)StartIndex; (INTN)Index--) {
        TmpUINT16 = Buffer [Index-1];
        Buffer [Index-1] = Buffer [Index];
        Buffer [Index] = TmpUINT16;
      }
      StartIndex++;
    }

    if ( FoundCount >= Count ) {
      break;
    }
  }

  //
  // Free the resources.
  //

  SafeFreePool (BootOrder);

} // ArrangeDevOrderAccordingToBootOrder
#endif // OPTION_SYSTEM_BOOT_MANAGER_DRIVE_NUMBER_BY_BOOT_ORDER

//
// FUNCTION NAME.
//      UpdateBbsDriveNumber - Update the drive number in BBS table.
//
// FUNCTIONAL DESCRIPTION.
//      Update the drive number according to HDD boot order.
//
// ENTRY PARAMETERS.
//      BbsTable        - Pointer points to BBS_TABLE.
//      BbsCount        - The number of BBS_TABLE entry.
//      IbvBbs          - Pointer points to IBV_TABLE.
//
// EXIT PARAMETERS.
//      Function return - EFI status code.
//

EFI_STATUS
UpdateBbsDriveNumber (
  IN BBS_TABLE *BbsTable,
  IN UINT16 BbsCount,
  IN PIBV_BBS_TABLE IbvBbs
  )
{
  UINT8 HddIndex;
  UINT16 Index;
  UINT16 MaxSearchIndex;

  MaxSearchIndex = BBS_SCSIHDD_START_INDEX + MAX_HDD_DEVICE_COUNT;
  for (HddIndex = 0; HddIndex < MAX_HDD_DEVICE_COUNT; HddIndex++) {
    if (IbvBbs->HardDisk_BootOrder [HddIndex] == 0xff) {
      continue;
    }
    for (Index = BBS_SCSIHDD_START_INDEX; Index < MaxSearchIndex; Index++) {
      if (IbvBbs->HardDisk_BootOrder [HddIndex] == BbsTable [Index].IBV1) {
        BbsTable [Index].AssignedDriveNumber = (UINT8)(0x80 + HddIndex);
        break;
      }
    }
  }

  return EFI_SUCCESS;
} // UpdateBbsDriveNumber

//
// FUNCTION NAME.
//      PrepareBbsBootOption - Prepare the necessary data for BBS BootOption.
//
// FUNCTIONAL DESCRIPTION.
//      This will construct the necessary data for a BBS BootOption.
//      A BBS Boot Option contains an entire BBS Table entry, BbsTableIndex (UINT16)
//      and an instance of EFI_DEVICE_PATH_PROTOCOL in its optional data.
//
// ENTRY PARAMETERS.
//      Description     - Description string for BBS DevicePath.
//      DevicePath      - Pointer points to a pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      OptionalDataLength - The size of optional data.
//      OptionalData    - Buffer for optional data.
//      Function Return - EFI status code.
//

SCT_STATUS
PrepareBbsBootOption (
  IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath,
  IN CHAR16 *Description,
  OUT PUINT32 OptionalDataLength,
  OUT PUINT8 *OptionalData
  )
{
  UINT8 *Ptr;
  UINT16 BbsIndex;
  SCT_STATUS Status;
  BBS_TABLE *BbsEntry;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;

  DPRINTF_LO_ENUM ("PrepareBbsBootOption\n");

  if (DevicePath == NULL ||
      OptionalDataLength == NULL ||
      OptionalData == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  Status = GetBbsEntryByDevicePath (
             *DevicePath,
             &BbsIndex,
             &BbsEntry);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  SafeFreePool (*OptionalData);

  //
  // Optional data contains one BbsTable entry, an UINT16 data for
  // BbsTableIndex and one extra device path for identification.
  //

  *OptionalDataLength = sizeof (BBS_TABLE) + sizeof (UINT16);
  *OptionalDataLength += (UINT32)GetDevicePathSize (*DevicePath);
  *OptionalData = AllocateZeroPool (*OptionalDataLength);
  if (*OptionalData == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  Ptr = (PUINT8)*OptionalData;
  CopyMem (Ptr, BbsEntry, sizeof (BBS_TABLE));

  Ptr += sizeof (BBS_TABLE);
  *((UINT16 *)Ptr) = BbsIndex;

  Ptr += sizeof (UINT16);
  CopyMem (
    Ptr,
    *DevicePath,
    GetDevicePathSize (*DevicePath));

  //
  // Create one BBS Device Path for this boot device.
  //

  TempDevicePath = *DevicePath;
  *DevicePath = CreateBbsDevicePath (
                  BbsEntry->DeviceType,
                  0,
                  Description);

  if (*DevicePath == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  DPRINTF_LO_ENUM ("   TempDevicePath Size  = 0x%x\n",
    GetDevicePathSize (TempDevicePath));

  DPRINTF_LO_ENUM ("   DevicePath Size      = 0x%x\n",
    GetDevicePathSize (*DevicePath));

  return SCT_STATUS_SUCCESS;

} // PrepareBbsBootOption

#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

