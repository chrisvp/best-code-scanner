//
// FILENAME.
//      BopFixedDisk.c - SecureCore Technology(TM) Boot Option Protocol for Fixed Disk.
//
// FUNCTIONAL DESCRIPTION.
//      This file implements MultiBootIII style boot option support for Fixed
//      Disks.
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
// All predefined possible last node device path of fixed disks.
//

static PCHAR16 mHddEndNodeDevicePaths[] = {
    L"Ata(Primary,Master,0x0)",
    L"Ata(Primary,Slave,0x0)",
    L"Ata(Secondary,Master,0x0)",
    L"Ata(Secondary,Slave,0x0)",
    L"Scsi(0xffff,0xffff)",
    L"NVMe(0xFF,FF-FF-FF-FF-FF-FF-FF-FF)",
};

static UINTN mHddEndNodeDevicePathsSize = sizeof (mHddEndNodeDevicePaths) / sizeof (mHddEndNodeDevicePaths[0]);

//
// Length of the template.
//

#define BOP_SATA_DEVICE_LENGTH 20

static PCHAR16 SataDevicePathTemplates[] = {
    L"Sata(%x,0,0)",
    L"Sata(%x,0x8000,0)"
};

static UINTN SataDevicePathTemplatesSize = sizeof (SataDevicePathTemplates) / sizeof (SataDevicePathTemplates[0]);

//
// Sata port list of the platform.
//

static UINTN mSataPortListArray[] = {
  CONFIG_Mb3SataPortIndex
};

static UINTN mSataPortListArraySize = sizeof (mSataPortListArray) / sizeof (mSataPortListArray[0]);

//
// Connect list of the platform.
//

static BOOT_MANAGER_CONNECTION_DEVICE mHddConnectListArray[] = {
  CONFIG_Mb3HddConnectList
};

static UINTN mHddConnectListArraySize =
  sizeof (mHddConnectListArray) / sizeof (mHddConnectListArray[0]) - 1;

//
// Keep note of connected devices to save time.
//

static BOOLEAN *gConnectedList = NULL;

//
// Generated last node array.
//

static PCHAR16 *SearchNodeDevicePathArray = NULL;
static UINTN SearchNodeDevicePathArraySize = 0;

//
// Stores the first ten matched pair of (ConnectList, SearchNode).
// Because GetChildren() will be called once by BdsServices->GetBootList(),
// it's able to build a cache of matched pairs to speed up further
// processing and handles GetDevicePaths with specific index.
//

static PMB3_DEVICE_RECORD DeviceRecordCache = NULL;
static UINT8 DeviceRecordCacheSize = 0;

//
// If a full scan of device paths is already performed in the system.
//

static BOOLEAN mFullScanPerformed = FALSE;

//
// Matched Pair Cache saved in variable.
//

static MB3_DEVICE_RECORD *SavedDeviceRecordCache = NULL;
static UINT8 SavedDeviceRecordCacheSize = 0;

//
// Prototypes for functions in other modules that are a part of this component.
//

EFI_STATUS
Mb3HddXSearchDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  OUT OPTIONAL EFI_DEVICE_PATH_PROTOCOL **dp,
  OUT OPTIONAL UINTN *n
  );


//
// Data shared with other modules *within* this component.
//

//
// Data defined in other modules and used by this module.
//

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

VOID
Mb3HddSaveDeviceRecord (
  VOID
  );

VOID
Mb3HddFullScanPerformed (
  VOID
  );

EFI_STATUS
Mb3HddXInsertDeviceRecord (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

EFI_STATUS
Mb3HddXGetDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN PMB3_DEVICE_RECORD Record OPTIONAL,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePaths,
  OUT PUINTN NumberOfDevicePaths
  );

EFI_STATUS
Mb3HddXGetChildren (
  IN PMB3_DEVICE_RECORD Record,
  OUT PSCT_BOOT_OPTION_NODE *ChildListHead
  );

PCHAR16
Mb3HddCreateDeviceDescription (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

BOOLEAN
Mb3HddIsDevicePathFixedDisk (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

PCHAR16
Mb3HddConstructDefaultDeviceName (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      Mb3HddGetDevicePaths - Execute the policy for Mb3Hdd Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function performs boot option policy associated with the Device
//      Node that included the GUID for this instance and context of the
//      SctBootOptionProtocol.
//
//      If the Device Node associated with this instance and context of the
//      SctBootOptionProtocol has child nodes they are returned in the pointer
//      whose address is provided in the DevicePaths parameter.
//
//      Memory is allocated by this function from Pool for the array of device
//      paths. It is the caller's responsibility to free this memory.
//
// ENTRY PARAMETERS.
//      This            - Pointer to the callers instance of the protocol.
//      Context         - Pointer to the Device Node's Context data.
//
// EXIT PARAMETERS.
//      DevicePaths     - The address of a device path pointer in which to
//                        return the pointer to the array of device paths.
//      NumberOfDevicePaths - The number of device paths in the array.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
Mb3HddGetDevicePaths (
  IN SCT_BOOT_OPTION_PROTOCOL *This,
  IN PVOID Context,
  IN UINTN ContextSize,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePaths,
  OUT PUINTN NumberOfDevicePaths
  )
{
  UINT8 i;
  UINT8 j;
  UINTN n;
  UINTN k;
  UINT8 Count;
  EFI_STATUS Status;
  PMB3_DEVICE_RECORD Record;
  EFI_DEVICE_PATH_PROTOCOL *p;
  EFI_DEVICE_PATH_PROTOCOL *dp;
  UINTN DeviceRecordsCount;
  PMB3_DEVICE_RECORD DeviceRecords;
  MB3_DEVICE_RECORD TempRecord;

  i = 0;
  j = 0;
  DeviceRecords = NULL;
  DeviceRecordsCount = 0;

  DPRINTF_MB3 ("Context @ 0x%x, ContextSize = %d\n", Context, ContextSize);
  DUMP_BYTES_MB3 (Context, ContextSize);
  DPRINTF_MB3 ("\n");

  if ((DevicePaths == NULL) || (NumberOfDevicePaths == NULL)) {
    DPRINTF_MB3 ("Bad parameters, NULL pointers.\n");
    return EFI_INVALID_PARAMETER;
  }

  *DevicePaths = NULL;
  *NumberOfDevicePaths = 0;

  if ((DeviceRecordCacheSize != 0) || (SavedDeviceRecordCacheSize > 0)) {
    DPRINTF_MB3 ("Use old data\n");

    //
    // If there is scanned data, it's used now.
    //

    if (DeviceRecordCacheSize == 0) {
      DPRINTF_MB3 ("Use old data in variable\n");
      DeviceRecords = SavedDeviceRecordCache;
      DeviceRecordsCount = SavedDeviceRecordCacheSize;
    } else {
      DPRINTF_MB3 ("Use latest data\n");
      DeviceRecords = DeviceRecordCache;
      DeviceRecordsCount = DeviceRecordCacheSize;
    }

    for (Count = 0; Count < DeviceRecordsCount; ++Count) {
      Record = (DeviceRecords + Count);
      if ((Record->Attr & MB3_ATTR_DISABLED) == MB3_ATTR_DISABLED) {
        continue;
      }

      i = Record->ControllerIndex;
      j = Record->SearchNodeIndex;

      dp = NULL;
      n = 0;
      Status = Mb3HddXGetDevicePaths (i, j, Record, &dp, &n);
      DPRINTF_MB3 ("Mb3HddXGetDevicePaths returned %r, %d\n", Status, n);
      if ((EFI_ERROR (Status)) || (n == 0)) {
        DPRINTF_MB3 ("Continue.\n");
        continue;
      }

      DISPLAY_DEVICE_PATH_ARRAY (dp, n, L"Mb3HddX:");

      //
      // Return only the first device found.
      //

      if (n > 1) {
        ASSERT_MB3 (n == 1);
        n = 1;
      }

      *NumberOfDevicePaths = n;
      *DevicePaths = dp;
      return EFI_SUCCESS;
    }
  }

  if (mFullScanPerformed) {
    //
    // If there was a Full Scan, we don't have to scan
    // furthermore.
    //
    return EFI_NOT_FOUND;
  }

  //
  // Perform a full scan and see if anything bootable left.
  //

  for (i = 0; i < mHddConnectListArraySize; i++) {
    for (j = 0; j < SearchNodeDevicePathArraySize; ++j) {
      dp = NULL;
      n = 0;
      Status = Mb3HddXGetDevicePaths (i, j, NULL, &dp, &n);
      DPRINTF_MB3 ("Mb3HddXGetDevicePaths returned %r, %d\n", Status, n);
      if ((EFI_ERROR (Status)) || (n == 0)) {
        DPRINTF_MB3 ("Continue.\n");
        continue;
      }

      DISPLAY_DEVICE_PATH_ARRAY (dp, n, L"Mb3HddX:");

      p = dp;
      for (k = 0; k < n; ++k, p = NextDevicePath (p)) {
        Mb3SetRecord (i, j, p, &TempRecord);
        for (Count = 0; Count < DeviceRecordsCount; ++Count) {
          Record = (DeviceRecords + Count);
          if (Mb3CompareDeviceRecords (Record, &TempRecord)) {

            //
            // Because every entry in DeviceRecords is already checked, if any
            // device is in DeviceRecords it can be skipped.
            //

            DPRINTF_MB3 ("Skip old data\n");
            break;
          }
        }

        if (Count == DeviceRecordsCount) {
          *NumberOfDevicePaths = 1;
          *DevicePaths = DuplicateDevicePath (p);
          DPRINTF_MB3 ("Found new device path\n");
          return Status;
        }
      }
    }
  }

  return EFI_SUCCESS;
} // Mb3HddGetDevicePaths

VOID
Mb3HddPerformFullScan (
  VOID
  )
{
  UINTN k, n;
  UINT8 i;
  UINT8 j;
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *p, *dp;

  for (i = 0; i < mHddConnectListArraySize; i++) {
    if (mHddConnectListArray[i].TextDevicePath == NULL) {
      continue;
    }

    for (j = 0; j < SearchNodeDevicePathArraySize; ++j) {
      dp = NULL;
      n = 0;
      Status = Mb3HddXGetDevicePaths (i, j, NULL, &dp, &n);
      if (!EFI_ERROR (Status)) {
        p = dp;
        for (k = 0; k < n; ++k) {
          Mb3HddXInsertDeviceRecord (i, j, p);
          p = NextDevicePath (p);
        }
      }
      SafeFreePool (dp);
    }
  }

  Mb3HddFullScanPerformed ();
  return;
} // Mb3HddPerformFullScan

//
// FUNCTION NAME.
//      Mb3CdGetChildren - Get the list of child nodes associated with this node.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets the list of child Device Paths associated with this
//      instance and context of the SctBootOptionProtocol.
//
//      Memory is allocated by this function from Pool for each
//      SCT_BOOT_OPTION_NODE. It is the caller's responsibility to free the
//      node as well as the memory pointed to by fields in the node. The list
//      of pointers to free is:
//              SCT_BOOT_OPTION_NODE
//              SCT_BOOT_OPTION_NODE.Description
//              SCT_BOOT_OPTION_NODE.DevicePath
//
// ENTRY PARAMETERS.
//      This            - Pointer to the callers instance of the protocol.
//      Context         - Pointer to the Device Node's Context data.
//
// EXIT PARAMETERS.
//      ChildListHead   - The address of a pointer to the first node in the
//                        child list.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
Mb3HddGetChildren (
  IN SCT_BOOT_OPTION_PROTOCOL *This,
  IN PVOID Context,
  IN UINTN ContextSize,
  OUT PSCT_BOOT_OPTION_NODE *ChildListHead
  )
{
  UINT8 i;
  EFI_STATUS Status;

  DPRINTF_MB3 ("Context @ 0x%x, ContextSize = %d\n", Context, ContextSize);
  DUMP_BYTES_MB3 (Context, ContextSize);
  DPRINTF_MB3 ("\n");

  if (ChildListHead == NULL) {
    DPRINTF_MB3 ("ChildListHead is NULL.\n");
    return EFI_INVALID_PARAMETER;
  }

  *ChildListHead = NULL;

  if (!mFullScanPerformed) {
    Mb3HddPerformFullScan ();
  }

  //
  // Insert Children according to the order.
  //
  DPRINTF_MB3 ("DeviceRecordCacheSize = 0x%x.\n", DeviceRecordCacheSize);

  for (i = 0; i < DeviceRecordCacheSize; ++i) {
    DPRINTF_MB3 ("Mb3HddXGetChildren loop 0x%x.\n", i);
    Status = Mb3HddXGetChildren (&(DeviceRecordCache[i]), ChildListHead);
    DPRINTF_MB3 ("Mb3HddXGetChildren returned %r.\n", Status);
  }

  if (*ChildListHead == NULL) {
    DPRINTF_MB3 ("Didn't find any Children.\n");
    return EFI_NOT_FOUND;
  }

  DPRINTF_MB3 ("Done, ChildListHead=0x%x.\n", ChildListHead);
  return EFI_SUCCESS;
} // Mb3HddGetChildren

SCT_BOOT_OPTION_PROTOCOL mMb3HddBootOptionProtocol = {
  sizeof (SCT_BOOT_OPTION_PROTOCOL),
  Mb3HddGetDevicePaths,
  Mb3HddGetChildren
};

//
// FUNCTION NAME.
//      Mb3HddSaveDeviceRecord - Save DeviceRecordCache to variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function saves the current DeviceRecordCache to variable. It first
//      merges the saved DeviceRecordCache with current ones then save the
//      merged result.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
Mb3HddSaveDeviceRecord (
  VOID
  )
{
  EFI_STATUS Status;
  PMB3_DEVICE_RECORD MergedDeviceRecordCache;
  UINT8 MergedDeviceRecordCacheSize;

  DPRINTF_MB3 ("Current Matched Pair: Size = %d\n", DeviceRecordCacheSize);
  DPRINTF_MB3 ("Saved Matched Pair: Size = %d\n", SavedDeviceRecordCacheSize);
  Status = MergeMb3DeviceRecord (
             SavedDeviceRecordCache,
             SavedDeviceRecordCacheSize,
             DeviceRecordCache,
             DeviceRecordCacheSize,
             &MergedDeviceRecordCache,
             &MergedDeviceRecordCacheSize
             );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("Merge Matched Pair Cache returned %r\n", Status);
    return;
  }

  DPRINTF_MB3 ("Merge Matched Pair: Size = %d\n", MergedDeviceRecordCacheSize);
  DUMP_BYTES_MB3 ((UINT8 *)DeviceRecordCache, DeviceRecordCacheSize * sizeof (MB3_DEVICE_RECORD));
  DPRINTF_MB3 ("\n");

  //
  // Save Current.
  //

  Status = gRT->SetVariable (
                  SCT_MB3_VARIABLE_NAME,
                  &gMb3FixedDiskBootOptionProtocolGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  MergedDeviceRecordCacheSize * sizeof (MB3_DEVICE_RECORD),
                  (VOID*)MergedDeviceRecordCache
                  );

  DPRINTF_MB3 ("Save Matched Pair returned %r\n", Status);

  SafeFreePool (SavedDeviceRecordCache);
  SafeFreePool (DeviceRecordCache);

  DeviceRecordCache = MergedDeviceRecordCache;
  DeviceRecordCacheSize = MergedDeviceRecordCacheSize;
  SavedDeviceRecordCache = DeviceRecordCache;
  SavedDeviceRecordCacheSize = DeviceRecordCacheSize;

  return;
} // Mb3HddSaveDeviceRecord

//
// FUNCTION NAME.
//      Mb3HddFullScanPerformed - Callback when a full scan has been performed.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called when a full scan of the system has been performed.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
Mb3HddFullScanPerformed (
  VOID
  )
{
  //
  // Full scan performed, save the data we got.
  // Connected devices changed. Need to update the variable as well
  // as the device path in boot options.
  //
  DPRINTF_MB3 ("Full Scan Performed, update variable\n");
  Mb3HddSaveDeviceRecord ();
  mFullScanPerformed = TRUE;
  return;
} // Mb3CdFullScanPerformed

//
// FUNCTION NAME.
//      InitializeInternalData - Initialize internal data used by this BOP
//      driver.
//
// FUNCTIONAL DESCRIPTION.
//      This function initialize all internal data structures used by this
//      BOP driver.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

STATIC
EFI_STATUS
InitializeInternalData (
  VOID
  )
{
  UINTN i;
  UINTN j;
  UINTN k;
  UINTN VarSize;
  EFI_STATUS Status;
  PCHAR16 SataSearchNodeDevicePath;
  UINTN SataSearchNodeDevicePathSize;

  SataSearchNodeDevicePath = NULL;
  SataSearchNodeDevicePathSize = 0;

  //
  // Initialize gConnectedList.
  //

  DPRINTF_MB3 ("Initialize gConnectedList of size 0x%x.\n", mHddConnectListArraySize);

  gConnectedList = AllocateZeroPool (mHddConnectListArraySize * sizeof (BOOLEAN));
  DPRINTF_MB3 (
    "Allocated gConnectedList of size 0x%x @0x%x.\n",
    mHddConnectListArraySize * sizeof (BOOLEAN),
    gConnectedList
    );

  if (gConnectedList == NULL) {
    DPRINTF_MB3 ("Failed to allocate memory for gConnectedList.\n");
    return EFI_OUT_OF_RESOURCES;
  } else {
    for (i = 0; i < mHddConnectListArraySize; ++i) {
      gConnectedList[i] = FALSE;
    }
  }

  //
  // Initialize Sata Device Paths
  //

  SataSearchNodeDevicePathSize = mSataPortListArraySize * SataDevicePathTemplatesSize;
  SearchNodeDevicePathArraySize = SataSearchNodeDevicePathSize + mHddEndNodeDevicePathsSize;

  DPRINTF_MB3 ("Initialize SataSearchNodeDevicePath array, size=0x%x.\n", SataSearchNodeDevicePathSize);
  SataSearchNodeDevicePath = AllocateZeroPool (SataSearchNodeDevicePathSize * BOP_SATA_DEVICE_LENGTH * sizeof (CHAR16));
  if (SataSearchNodeDevicePath == NULL) {
    DPRINTF_MB3 ("Failed to allocate memory for Sata DevicePaths.\n");
    SafeFreePool (SataSearchNodeDevicePath);
    return EFI_OUT_OF_RESOURCES;
  }

  DPRINTF_MB3 ("Initialize SearchNode array, size=0x%x.\n", SearchNodeDevicePathArraySize);
  SearchNodeDevicePathArray = AllocateZeroPool (SearchNodeDevicePathArraySize * sizeof (PCHAR16));
  if (SearchNodeDevicePathArray == NULL) {
    DPRINTF_MB3 ("Failed to allocate memory for Last node DevicePaths.\n");
    SafeFreePool (SearchNodeDevicePathArray);
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Initialize the SataLastnode array.
  //

  k = 0;
  for (i = 0; i < SataDevicePathTemplatesSize; ++i) {
    for (j = 0; j < mSataPortListArraySize; ++j) {
      UnicodeSPrint (
        SataSearchNodeDevicePath + (k * BOP_SATA_DEVICE_LENGTH),
        BOP_SATA_DEVICE_LENGTH * sizeof (CHAR16),
        SataDevicePathTemplates[i],
        mSataPortListArray[j]);
      k++;
    }
  }

  //
  // Points the SearchNode device array to initialized arrays.
  //

  for (i = 0; i < SataSearchNodeDevicePathSize; ++i) {
    SearchNodeDevicePathArray[i] = SataSearchNodeDevicePath + (i * BOP_SATA_DEVICE_LENGTH);
    DPRINTF_MB3 ("Initialize SearchNode array[0x%x], value=[%s].\n", i, SearchNodeDevicePathArray[i]);
  }

  for (i = 0; i < mHddEndNodeDevicePathsSize; ++i) {
    // SearchNodeDevicePathArray[i + SataSearchNodeDevicePathSize] = mHddEndNodeDevicePaths[i];
    CopyMem (
      &SearchNodeDevicePathArray[i + SataSearchNodeDevicePathSize],
      &mHddEndNodeDevicePaths[i],
      sizeof (PCHAR16)
      );
    DPRINTF_MB3 ("Initialize SearchNode array[0x%x], value=[%s].\n", i + SataSearchNodeDevicePathSize, SearchNodeDevicePathArray[i + SataSearchNodeDevicePathSize]);
  }

  DeviceRecordCache = AllocateZeroPool (CONFIG_SYSTEM_MULTI_BOOT_III_MATCHED_CACHE_SIZE * sizeof (MB3_DEVICE_RECORD));
  if (DeviceRecordCache == NULL) {
    DPRINTF_MB3 ("Failed to allocate memory for DeviceRecordCache\n");
    SafeFreePool (DeviceRecordCache);
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (DeviceRecordCache, CONFIG_SYSTEM_MULTI_BOOT_III_MATCHED_CACHE_SIZE * sizeof (MB3_DEVICE_RECORD));
  for (i = 0; i < CONFIG_SYSTEM_MULTI_BOOT_III_MATCHED_CACHE_SIZE; ++i) {
    DeviceRecordCache[i].ControllerIndex = MB3_DEVICE_RECORD_INDEX_OUT_OF_BOUND;
    DeviceRecordCache[i].SearchNodeIndex = MB3_DEVICE_RECORD_INDEX_OUT_OF_BOUND;
  }

  //
  // Get saved variable.
  //

  Status = GetVariable2 (
             SCT_MB3_VARIABLE_NAME,
             &gMb3FixedDiskBootOptionProtocolGuid,
             (VOID **) &SavedDeviceRecordCache,
             &VarSize
             );
  if (!EFI_ERROR (Status)) {
    SavedDeviceRecordCacheSize = (UINT8)VarSize;
    DUMP_BYTES_MB3 ((UINT8 *)SavedDeviceRecordCache, SavedDeviceRecordCacheSize);
    DPRINTF_MB3 ("\n");
    SavedDeviceRecordCacheSize /= sizeof (MB3_DEVICE_RECORD);
  } else {
    SavedDeviceRecordCacheSize = 0;
    SavedDeviceRecordCache = NULL;
  }

  return EFI_SUCCESS;
} // InitializeInternalData

//
// FUNCTION NAME.
//      InitializeBopFixedDiskMb3 - Initialize the BopMb3Hdd module.
//
// FUNCTIONAL DESCRIPTION.
//      This function installs the Boot Option Protocol.
//
// ENTRY PARAMETERS.
//      ImageHandle     - The handle to install protocol on.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

EFI_STATUS
EFIAPI
InitializeBopFixedDiskMb3 (
  IN EFI_HANDLE ImageHandle
  )
{

  EFI_STATUS Status;

  Status = InitializeInternalData ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ImageHandle,
                  &gMb3FixedDiskBootOptionProtocolGuid,
                  &mMb3HddBootOptionProtocol,
                  NULL
                  );
  return Status;
} // InitializeBopFixedDiskMb3

//
// Private (static) routines used by this component.
//

//
// FUNCTION NAME.
//      Mb3HddXInsertDeviceRecord - Insert a DeviceRecord into cache.
//
// FUNCTIONAL DESCRIPTION.
//      This function inserts a matched pair into the cache.
//
// ENTRY PARAMETERS.
//      ControllerIndex        - Index in the ConnectList.
//      SearchNodeIndex - Index in the SearchNodeDevicePathArray.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

EFI_STATUS
Mb3HddXInsertDeviceRecord (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  UINTN i;
  EFI_STATUS Status;
  MB3_DEVICE_RECORD Temp;

  DPRINTF_MB3 (
    "ControllerIndex: 0x%x, SearchNodeIndex: 0x%x\n",
    ControllerIndex,
    SearchNodeIndex
    );

  if (DeviceRecordCacheSize == CONFIG_SYSTEM_MULTI_BOOT_III_MATCHED_CACHE_SIZE) {
    DPRINTF_MB3 ("Full\n");
    return EFI_OUT_OF_RESOURCES;
  }

  Status = Mb3SetRecord (
             ControllerIndex,
             SearchNodeIndex,
             DevicePath,
             &Temp
             );

  DPRINTF_MB3 ("Attr=0x%x, (0x%x, 0x%x)\n",
    Temp.Attr,
    Temp.ControllerIndex,
    Temp.SearchNodeIndex
    );
  DPRINTF_MB3 ("UsbPortNumber\n");
  DUMP_BYTES_MB3 ((UINT8 *)(Temp.UsbPortNumber), sizeof (UINT8) * MB3_USB_MAX_LAYER);
  DPRINTF_MB3 ("\n");

  //
  // Find duplicate entries.
  //

  for (i = 0; i < DeviceRecordCacheSize; ++i) {
    if (Mb3CompareDeviceRecords (&Temp, (DeviceRecordCache + DeviceRecordCacheSize))) {
      DPRINTF_MB3 ("skip existing entry\n", DeviceRecordCacheSize);
      return EFI_SUCCESS;
    }
  }

  CopyMem (&(DeviceRecordCache[DeviceRecordCacheSize]), &Temp, sizeof (MB3_DEVICE_RECORD));
  DeviceRecordCacheSize++;
  DPRINTF_MB3 ("Current Size = 0x%x\n", DeviceRecordCacheSize);
  return EFI_SUCCESS;
} // Mb3HddXInsertDeviceRecord

//
// FUNCTION NAME.
//      Mb3HddXGetDevicePaths - Get device path from give device path pair.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs for all device paths to find an applicable matching given device pair and points to a fixed disk device.
//
// ENTRY PARAMETERS.
//      ControllerIndex - The index of the parent device path.
//      SearchNodeIndex - The index of the search node device path.
//      Record          - Optional paramater. Provide extra search criteria.
//
// EXIT PARAMETERS.
//      DevicePaths     - The address of a device path pointer in which to
//                        return the pointer to the array of device paths.
//      NumberOfDevicePaths - The number of device paths in the array.
//      Function Return - SCT status code.
//

EFI_STATUS
Mb3HddXGetDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN PMB3_DEVICE_RECORD Record OPTIONAL,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePaths,
  OUT PUINTN NumberOfDevicePaths
  )
{
  EFI_STATUS Status;
  MB3_DEVICE_RECORD TempRecord;
  EFI_DEVICE_PATH_PROTOCOL *p, *dp, *q;
  EFI_DEVICE_PATH_PROTOCOL *FinalDevicePaths;
  UINTN i, n, Size;
  UINTN TotalDevicePathsSize;

  DPRINTF_MB3 (
    "ControllerIndex: 0x%x, SearchNodeIndex: 0x%x\n",
    ControllerIndex,
    SearchNodeIndex
    );

  if ((DevicePaths == NULL) || (NumberOfDevicePaths == NULL)) {
    DPRINTF_MB3 ("Either DevicePaths or NumberOfDevicePaths is NULL.\n");
    return EFI_INVALID_PARAMETER;
  }

  //
  // Connect all the device paths associated with this Mb3Hdd Device.
  //

  Status = Mb3HddXSearchDevicePaths (ControllerIndex, SearchNodeIndex, &dp, &n);
  DPRINTF_MB3 ("Mb3HddXSearchDevicePaths returned %r, %d device paths.\n", Status, n);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DISPLAY_DEVICE_PATH_ARRAY (dp, n, L"Mb3HddXSearchDevicePaths:");

  //
  // Scan the device paths to calculate the total size of the output buffer.
  //

  *NumberOfDevicePaths = 0;
  FinalDevicePaths = NULL;
  TotalDevicePathsSize = 0;
  Size = 0;
  p = dp;
  for (i = 0; i < n; i++, p = NextDevicePath (p)) {
    //
    // Filter for HDD, no removeable media.
    //

    if (!Mb3HddIsDevicePathFixedDisk (p)) {
      continue;
    }

    if (Record != NULL) {

      //
      // Given specified record (with full usb port number), only equal device path
      // are returned.
      //

      Mb3SetRecord (ControllerIndex, SearchNodeIndex, p, &TempRecord);
      if (!Mb3CompareDeviceRecords (&TempRecord, Record)) {
        continue;
      }
    }

    Size = GetDevicePathSize (p);

    //
    // Allocate new memory buffer for appending newly discovered device path.
    //

    if (TotalDevicePathsSize != 0) {
      q = FinalDevicePaths;
      FinalDevicePaths = AllocatePool (TotalDevicePathsSize + Size);
      if (FinalDevicePaths == NULL) {
        SafeFreePool (dp);
        SafeFreePool (q);
        DPRINTF_MB3 ("Memory out of resources!\n");
        return EFI_OUT_OF_RESOURCES;
      }
      // Keep previous data
      CopyMem (FinalDevicePaths, q, TotalDevicePathsSize);
      SafeFreePool (q);

      // Append new data
      q = (EFI_DEVICE_PATH_PROTOCOL *)(((UINT8 *)FinalDevicePaths) + TotalDevicePathsSize);
      CopyMem (q, p, Size);
    }
    else {
      FinalDevicePaths = DuplicateDevicePath (p);
      if (FinalDevicePaths == NULL) {
        SafeFreePool (dp);
        DPRINTF_MB3 ("Memory out of resources!\n");
        return EFI_OUT_OF_RESOURCES;
      }
    }
    TotalDevicePathsSize += Size;
    (*NumberOfDevicePaths)++;

    //
    // For multi-port card, we only handle the first one.
    //

    break;
  }

  SafeFreePool (dp);

  DPRINTF_MB3 ("FinalDevicePaths buffer @ 0x%x.\n", (UINTN)FinalDevicePaths);
  DPRINTF_MB3 ("NumberOfDevicePaths = 0x%x.\n", *NumberOfDevicePaths);
  DPRINTF_MB3 ("TotalDevicePathsSize = 0x%x.\n", TotalDevicePathsSize);

  if ((TotalDevicePathsSize == 0) || (*NumberOfDevicePaths == 0)) {
    return EFI_NOT_FOUND;
  }

  *DevicePaths = FinalDevicePaths;

  DPRINTF_MB3 ("Done.\n");
  return EFI_SUCCESS;
} // Mb3HddXGetDevicePaths

//
// FUNCTION NAME.
//      Mb3HddXSearchDevicePaths - Get device path from give device path pair.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs for all device paths to find an applicable matching given device pair. This function wraps this common action.
//
// ENTRY PARAMETERS.
//      ControllerIndex - The index of the parent device path.
//      SearchNodeIndex - The index of the search node device path.
//
// EXIT PARAMETERS.
//      DevicePaths     - The address of a device path pointer in which to
//                        return the pointer to the array of device paths.
//      NumberOfDevicePaths - The number of device paths in the array.
//      Function Return - SCT status code.
//

EFI_STATUS
Mb3HddXSearchDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  OUT OPTIONAL EFI_DEVICE_PATH_PROTOCOL **dp,
  OUT OPTIONAL UINTN *n
  )
{
  UINTN TempN;
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *TempDp;
  BOOT_MANAGER_DEVICE_PATH_SEARCH PathToSearch;

  //
  // Search for a DevicePath match for (ControllerIndex, SearchNodeIndex)
  //

  if (gConnectedList[ControllerIndex] == FALSE) {
    DPRINTF_MB3 ("  SctBdsLibConnectDevices 0x%x.\n", ControllerIndex);
    Status = SctBdsLibConnectDevices (&(mHddConnectListArray [ControllerIndex]));
    if (EFI_ERROR (Status)) {
      DPRINTF_MB3 ("  SctBdsLibConnectDevices returned %r.\n", Status);
      return Status;
    } else {
      gConnectedList[ControllerIndex] = TRUE;
    }
  } else {
    //DPRINTF_MB3 ("  SctBdsLibConnectDevices 0x%x already connected.\n", ControllerIndex);
  }

  ShadowOproms (&(mHddConnectListArray[ControllerIndex]));

  //
  // Search for devices that match this Mb3Hdd criteria.
  //

  PathToSearch.ParentDevicePathText = mHddConnectListArray[ControllerIndex].TextDevicePath;
  PathToSearch.SearchDeviceNodeText = SearchNodeDevicePathArray[SearchNodeIndex];

  Status = SearchForDevicePath (
             &PathToSearch,
             &TempDp,
             &TempN
             );

  if (dp != NULL) {
    *dp = TempDp;
  }

  if (n != NULL) {
    *n = TempN;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  DPRINTF_MB3 ("SearchForDevicePaths returned %r, %d entries.\n", Status, TempN);
  return Status;
} // Mb3HddXSearchDevicePaths

//
// FUNCTION NAME.
//      Mb3HddXGetChildren - Append Child Nodes to a Linked List.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches for child devices, creates nodes for the devices
//      that are found and appends the nodes to a linked list.
//
// ENTRY PARAMETERS.
//      Record          - The device record to search.
//
// EXIT PARAMETERS.
//      ChildListHead   - The children list.
//      Function Return - SCT status code.
//

EFI_STATUS
Mb3HddXGetChildren (
  IN PMB3_DEVICE_RECORD Record,
  OUT PSCT_BOOT_OPTION_NODE *ChildListHead
  )
{
  UINTN i, n;
  UINT32 Attr;
  EFI_STATUS Status;
  PSCT_BOOT_OPTION_NODE *q;
  EFI_DEVICE_PATH_PROTOCOL *p, *dp;


  DPRINTF_MB3 ("Attr=0x%x, (0x%x,0x%x)\n",
    Record->Attr,
    Record->ControllerIndex,
    Record->SearchNodeIndex
    );

  DUMP_BYTES_MB3 ((UINT8 *)(Record->UsbPortNumber), sizeof (UINT8) * MB3_USB_MAX_LAYER);
  DPRINTF_MB3 ("\n");

  Attr = Record->Attr;

  //
  // Connect all the device paths associated with this Mb3Hdd Device.
  //

  dp = NULL;
  n = 0;
  Status = Mb3HddXGetDevicePaths (
             Record->ControllerIndex,
             Record->SearchNodeIndex,
             Record,
             &dp,
             &n
             );

  DPRINTF_MB3 ("Mb3HddXGetDevicePaths returned %r, %d entries.\n", Status, n);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // The last node in the list will have a Next pointer that is NULL. We want
  // the address of this pointer in q.
  //

  q = ChildListHead;
  while (TRUE) {
    if (*q == NULL) {
      break;
    }
    q = &((*q)->Next);
  }

  //
  // Process each device path, create the node and append it to the list.
  //

  p = dp;
  for (i = 0; i < n; i++, p = NextDevicePath (p)) {
    //
    // Create the node.
    //

    *q = AllocateZeroPool (sizeof (SCT_BOOT_OPTION_NODE));
    if (*q == NULL) {
      DPRINTF_MB3 ("Failed to allocate SCT_BOOT_OPTION_NODE.\n");
      return EFI_OUT_OF_RESOURCES;
    }
    DPRINTF_MB3 ("New BootOptionNode 0x%x:0x%x", q, *q);

    //
    // Copy the device path into the new Boot Option Node.
    //

    (*q)->NumberOfFilePaths = 1;
    (*q)->FilePathListLength = (UINT16)GetDevicePathSize (p);
    (*q)->FilePathList = AllocateCopyPool ((*q)->FilePathListLength, p);

    //
    // Create a description string for this device path.
    //

    (*q)->Description = Mb3HddCreateDeviceDescription (p);

    //
    // Assign a default description string.
    //

    if ((*q)->Description == NULL) {
      (*q)->Description = Mb3HddConstructDefaultDeviceName (p);
    }

    DPRINTF_MB3 ("CreateDeviceDescription Done.\n");
    if ((Attr & MB3_ATTR_DISABLED) == MB3_ATTR_DISABLED) {
      (*q)->Attributes = 0;
    } else {
      (*q)->Attributes = LOAD_OPTION_ACTIVE;
    }

    //
    // Advance the address of the next pointer.
    //

    q = &((*q)->Next);
  }

  DPRINTF_MB3 ("Release Memory.\n");
  SafeFreePool (dp);
  DPRINTF_MB3 ("Done.\n");
  return EFI_SUCCESS;
} // Mb3HddXGetChildren

//
// FUNCTION NAME.
//      CreateNvmeModelName - Create Nvme Model Name
//
// FUNCTIONAL DESCRIPTION.
//      This function will build the Nvme model name according to the input
//      device path.
//
// ENTRY PARAMETERS.
//      EFI_HANDLE      - Handle for modele name construction.
//
// EXIT PARAMETERS.
//      None.
//

PCHAR16
CreateNvmeModelName (
  IN EFI_HANDLE Handle
  )
{
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_HANDLE NvmeControllerHandle;
  UINTN i;
  UINTN HandleCount;
  EFI_HANDLE *Handles;
  SCT_NVME_DEVICE_SERVICE_PROTOCOL *NvmeDeviceService;

  DevicePath = DevicePathFromHandle (Handle);
  if (DevicePath == NULL) {
    return NULL;
  }

  NvmeControllerHandle = NULL;
  RemainingDevicePath = DevicePath;

  Status = gBS->LocateDevicePath (
                  &gEfiNvmExpressPassThruProtocolGuid,
                  &RemainingDevicePath,
                  &NvmeControllerHandle
                  );
  DPRINTF_MB3 ("LocateDevicePath gEfiNvmExpressPassThruProtocolGuid - %r\n", Status);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  HandleCount = 0;
  Handles = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctNvmeDeviceServiceProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  DPRINTF_MB3 ("LocateHandleBuffer gSctNvmeDeviceServiceProtocolGuid - %r\n", Status);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  NvmeDeviceService = NULL;
  for (i = 0; i < HandleCount; i++) {
    Status = gBS->HandleProtocol (
                    Handles[i],
                    &gSctNvmeDeviceServiceProtocolGuid,
                    (VOID **)&NvmeDeviceService
                    );
    DPRINTF_MB3 ("HandleProtocol SctNvmeDeviceService - (%d, %r)\n", i, Status);
    if (EFI_ERROR (Status)) {
      continue;
    }

    if (NvmeDeviceService->DeviceInfo->ControllerHandle == NvmeControllerHandle) {
      DPRINTF_MB3 ("Found match protocol instance.\n");
      break;
    }

    NvmeDeviceService = NULL;
  }

  FreePool (Handles);

  if (NvmeDeviceService == NULL) {
    return NULL;
  }

  return (PCHAR16)AllocateCopyPool (
                    StrSize (NvmeDeviceService->DeviceInfo->ModelNameStr),
                    NvmeDeviceService->DeviceInfo->ModelNameStr
                    );
}

//
// FUNCTION NAME.
//      Mb3HddCreateDeviceDescription - Create a string based on a device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes a device path and creates an appropriate
//      description string.
//
//      This function will locate the handle that has the device path and use
//      the protocol's on the handle to find information about the HDD.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path to create description for.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

PCHAR16
Mb3HddCreateDeviceDescription (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  UINT32 BufferSize;
  EFI_STATUS Status;
  PCHAR16 Str;
  EFI_HANDLE Handle;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;
  EFI_IDENTIFY_DATA *IdentifyDriveInfo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  BBS_DEVICE_INFO BbsBcv;
  UINTN StringLength;
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle
                  );
  DPRINTF_MB3 ("LocateDevicePath: Status = %r, Handle = 0x%x\n", Status, Handle);

  if (EFI_ERROR (Status)) {
    return NULL;
  }

  if (!IsDevicePathEnd (RemainingDevicePath)) {
    return NULL;
  }

  //
  // Get the DiskInfo protocol for this handle.
  //

  Status = gBS->HandleProtocol (Handle, &gEfiDiskInfoProtocolGuid, (VOID **) &DiskInfo);
  DPRINTF_MB3 ("HandleProtocol (DiskInfo): Status = %r\n", Status);
  if (EFI_ERROR (Status)) {
    goto CreateDeviceDesc_blockio;
  }

  //
  // Get the identify data for this drive.
  //

  if (CompareGuid (&DiskInfo->Interface, &gEfiDiskInfoIdeInterfaceGuid) ||
      CompareGuid (&DiskInfo->Interface, &gEfiDiskInfoAhciInterfaceGuid)) {

    BufferSize = sizeof (EFI_IDENTIFY_DATA);
    IdentifyDriveInfo = AllocatePool (sizeof(EFI_IDENTIFY_DATA));

    Status = DiskInfo->Identify (
                         DiskInfo,
                         IdentifyDriveInfo,
                         &BufferSize
                         );
    DPRINTF_MB3 ("DiskInfo->Identify: Status = %r\n", Status);
    if (EFI_ERROR (Status)) {
      goto CreateDeviceDesc_blockio;
    }

    //
    // Convert the Model Name into a Unicode string.
    //

    return AtaModelNameToUnicode (&(IdentifyDriveInfo->AtaData.ModelName [0]));
  }
  else if (CompareGuid (&DiskInfo->Interface, &gEfiDiskInfoUsbInterfaceGuid)) {
    Status = GetUsbMsdDeviceName (Handle, &Str);
    if (!EFI_ERROR (Status)) {
      return Str;
    } else {
      return NULL;
    }
  }
  else if (CompareGuid (&DiskInfo->Interface, &gEfiDiskInfoNvmeInterfaceGuid)) {
    return CreateNvmeModelName (Handle);
  }

CreateDeviceDesc_blockio:

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  //
  // For the device which is not usb mass storage device, this is the device
  // connected to the external oprom. Its device string should be retrieved
  // from the BBS table.
  //

  Status = GetBbsDesc (DevicePath, &BbsBcv);
  if (!EFI_ERROR (Status)) {
    StringLength = AsciiStrLen (BbsBcv.DescriptionString) + 1;
    Str = (CHAR16 *)AllocateZeroPool (StringLength * sizeof (CHAR16));
    AsciiStrToUnicodeStrS (BbsBcv.DescriptionString, Str, StringLength);
    DPRINTF_MB3 ("Found: desc=[%s]\n", Str);
    return Str;
  }
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  return NULL;
} // Mb3HddCreateDeviceDescription

//
// FUNCTION NAME.
//      Mb3HddIsDevicePathFixedDisk - Check to see if a device path is an fixed disk.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes a device path and do some checks with it to see
//      if it's an fixed disk.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path to check.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

BOOLEAN
Mb3HddIsDevicePathFixedDisk (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UINT8 DeviceType;
  EFI_STATUS Status;
  BBS_DEVICE_INFO BbsBcv;

  Status = GetBbsDesc (DevicePath, &BbsBcv);
  if (!EFI_ERROR (Status)) {
    DPRINTF_MB3 ("Found: type=0x%x\n", BbsBcv.DeviceType);
    if (BbsBcv.DeviceType == BBS_HARDDISK) {
      return TRUE;
    }
    return FALSE;
  }
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  if (!IsEfiBootableDevicePath (DevicePath)) {
    return FALSE;
  }

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  if (IsRemovableMediaDevicePath (DevicePath, NULL)) {
    Status = GetUsbBbsDeviceTypeFromDevicePath (DevicePath, &DeviceType);
    DPRINTF_MB3 ("DeviceType = 0x%02x. Status = %r.\n", DeviceType, Status);
    if (EFI_ERROR (Status) || DeviceType != BBS_HARDDISK) {
      return FALSE;
    }
  }
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  return TRUE;
} // Mb3HddIsDevicePathFixedDisk

//
// FUNCTION NAME.
//      Mb3HddConstructDefaultDeviceName - Build the default device name.
//
// FUNCTIONAL DESCRIPTION.
//      This function will construct the default device name according to the
//      device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path to be referred.
//
// EXIT PARAMETERS.
//      Function Return - Default device name string.
//

PCHAR16
Mb3HddConstructDefaultDeviceName (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  PCHAR16 DeviceName;

  DeviceName = NULL;
  LastNode = NULL;

  if (DevicePath == NULL) {
    return NULL;
  }

  LastNode = GetLastDeviceNode (DevicePath);

  if (LastNode == NULL) {
    return NULL;
  }

  switch (LastNode->SubType) {
    case MSG_SCSI_DP:
      DeviceName = (PCHAR16)AllocateZeroPool (StrSize (L"SCSI DISK"));
      if (DeviceName != NULL) {
        StrCpyS (DeviceName, StrSize (L"SCSI DISK") / sizeof (CHAR16), L"SCSI DISK");
      }
      break;
    case MSG_SATA_DP:
    case MSG_ATAPI_DP:
    case MSG_VENDOR_DP:
    default:
      DeviceName = (PCHAR16)AllocateZeroPool (StrSize (L"DISK"));
      if (DeviceName != NULL) {
        StrCpyS (DeviceName, StrSize (L"DISK") / sizeof (CHAR16), L"DISK");
      }
  }

  return DeviceName;
} // Mb3HddConstructDefaultDeviceName
