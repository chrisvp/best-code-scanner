//
// FILENAME.
//      BopPciLanMb3.c - SecureCore Technology(TM) Boot Option Protocol for PCI Lan card.
//
// FUNCTIONAL DESCRIPTION.
//      This file implements MultiBootIII style boot option support for PCI
//      NICs.
//
// NOTICE.
//      Copyright (C) 2009-2024 Phoenix Technologies.  All Rights Reserved.
//

#include "Meta.h"

//
// Private data types used by this module are defined here and any
// static items are declared here.
//


//
// All predefined possible last node device path of fixed disks.
//

static PCHAR16 mPciLanEndNodeDevicePaths[] = {
  L"",
  L"IPv4(0.0.0.0:0)",
  L"IPv6(0000:0000:0000:0000:0000:0000:0000:0000)",
};

static UINTN mPciLanEndNodeDevicePathsSize = sizeof (mPciLanEndNodeDevicePaths) / sizeof (mPciLanEndNodeDevicePaths[0]);

//
// Connect list of the platform.
//

static BOOT_MANAGER_CONNECTION_DEVICE mPciLanConnectListArray[] = {
  CONFIG_Mb3PciLanConnectList
};

static UINTN mPciLanConnectListArraySize =
sizeof (mPciLanConnectListArray) / sizeof (mPciLanConnectListArray[0]) - 1;

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

static EFI_HANDLE mImageHandle;

//
// Prototypes for functions in other modules that are a part of this component.
//

EFI_STATUS
Mb3PciLanXSearchDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  OUT OPTIONAL EFI_DEVICE_PATH_PROTOCOL **dp,
  OUT OPTIONAL UINTN *n
  );

STATIC
BOOLEAN
IsEfiNetworkDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *dp
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
Mb3PciLanSaveDeviceRecord (
  VOID
  );

VOID
Mb3PciLanFullScanPerformed (
  VOID
  );

EFI_STATUS
Mb3PciLanXInsertDeviceRecord (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

EFI_STATUS
Mb3PciLanXGetDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN PMB3_DEVICE_RECORD Record OPTIONAL,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePaths,
  OUT PUINTN NumberOfDevicePaths
  );

EFI_STATUS
Mb3PciLanXGetChildren (
  IN PMB3_DEVICE_RECORD Record,
  OUT PSCT_BOOT_OPTION_NODE *ChildListHead
  );

PCHAR16
Mb3PciLanCreateDeviceDescription (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

BOOLEAN
Mb3PciLanIsDevicePathPciLan (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      Mb3PciLanGetDevicePaths - Execute the policy for Mb3PciLan Boot Option.
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
Mb3PciLanGetDevicePaths (
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

  DPRINTF_MB3_LAN ("Context @ 0x%x, ContextSize = %d\n", Context, ContextSize);
  DUMP_BYTES_MB3 (Context, ContextSize);
  DPRINTF_MB3_LAN ("\n");

  if ((DevicePaths == NULL) || (NumberOfDevicePaths == NULL)) {
    DPRINTF_MB3_LAN ("  Bad parameters, NULL pointers.\n");
    return EFI_INVALID_PARAMETER;
  }

  *DevicePaths = NULL;
  *NumberOfDevicePaths = 0;

  if ((DeviceRecordCacheSize != 0) || (SavedDeviceRecordCacheSize > 0)) {
    DPRINTF_MB3_LAN ("Use old data\n");

    //
    // If there is scanned data, it's used now.
    //

    if (DeviceRecordCacheSize == 0) {
      DPRINTF_MB3_LAN ("Use old data in variable\n");
      DeviceRecords = SavedDeviceRecordCache;
      DeviceRecordsCount = SavedDeviceRecordCacheSize;
    } else {
      DPRINTF_MB3_LAN ("Use latest data\n");
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
      Status = Mb3PciLanXGetDevicePaths (i, j, Record, &dp, &n);
      DPRINTF_MB3_LAN ("Mb3PciLanXGetDevicePaths returned %r, %d\n", Status, n);
      if ((EFI_ERROR (Status)) || (n == 0)) {
        DPRINTF_MB3_LAN ("Continue.\n");
        continue;
      }

      DISPLAY_DEVICE_PATH_ARRAY (dp, n, L"  Mb3PciLanX:");

      //
      // Return only the first device found.
      //

      if (n > 1) {
        ASSERT_MB3_LAN (n == 1);
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

  for (i = 0; i < mPciLanConnectListArraySize; i++) {
    for (j = 0; j < SearchNodeDevicePathArraySize; ++j) {
      dp = NULL;
      n = 0;
      Status = Mb3PciLanXGetDevicePaths (i, j, NULL, &dp, &n);
      DPRINTF_MB3_LAN ("Mb3PciLanXGetDevicePaths returned %r, %d\n", Status, n);
      if ((EFI_ERROR (Status)) || (n == 0)) {
        DPRINTF_MB3_LAN ("Continue.\n");
        continue;
      }

      DISPLAY_DEVICE_PATH_ARRAY (dp, n, L"  Mb3PciLanX:");

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
            DPRINTF_MB3_LAN ("Skip old data\n");
            break;
          }
        }

        if (Count == DeviceRecordsCount) {
          *NumberOfDevicePaths = 1;
          *DevicePaths = DuplicateDevicePath (p);
          DPRINTF_MB3_LAN ("Found new device path\n");
          return Status;
        }
      }
    }                 // for each entry in SearchNode list
  }                   // for each entry in ConnectList

  return EFI_SUCCESS;
} // Mb3PciLanGetDevicePaths

VOID
Mb3PciLanPerformFullScan (
  VOID
  )
{
  UINTN k, n;
  UINT8 i;
  UINT8 j;
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *p, *dp;

  for (i = 0; i < mPciLanConnectListArraySize; i++) {
    if (mPciLanConnectListArray[i].TextDevicePath == NULL) {
      continue;
    }

    for (j = 0; j < SearchNodeDevicePathArraySize; ++j) {
      dp = NULL;
      n = 0;
      Status = Mb3PciLanXGetDevicePaths (i, j, NULL, &dp, &n);
      if (!EFI_ERROR (Status)) {
        p = dp;
        for (k = 0; k < n; ++k) {
          Mb3PciLanXInsertDeviceRecord (i, j, p);
          p = NextDevicePath (p);
        }
      }
      SafeFreePool (dp);
    }
  }

  Mb3PciLanFullScanPerformed ();
  return;
}

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
Mb3PciLanGetChildren (
  IN SCT_BOOT_OPTION_PROTOCOL *This,
  IN PVOID Context,
  IN UINTN ContextSize,
  OUT PSCT_BOOT_OPTION_NODE *ChildListHead
  )
{
  UINT8 i;
  EFI_STATUS Status;

  DPRINTF_MB3_LAN ("Context @ 0x%x, ContextSize = %d\n", Context, ContextSize);
  DUMP_BYTES_MB3 (Context, ContextSize);
  DPRINTF_MB3_LAN ("\n");

  if (ChildListHead == NULL) {
    DPRINTF_MB3_LAN ("ChildListHead is NULL.\n");
    return EFI_INVALID_PARAMETER;
  }

  *ChildListHead = NULL;

  if (!mFullScanPerformed) {
    Mb3PciLanPerformFullScan ();
  }

  //
  // Insert Children according to the order.
  //
  DPRINTF_MB3_LAN ("DeviceRecordCacheSize = 0x%x.\n", DeviceRecordCacheSize);

  for (i = 0; i < DeviceRecordCacheSize; ++i) {
    DPRINTF_MB3_LAN ("Mb3PciLanXGetChildren loop 0x%x.\n", i);
    Status = Mb3PciLanXGetChildren (&(DeviceRecordCache[i]), ChildListHead);
    DPRINTF_MB3_LAN ("Mb3PciLanXGetChildren returned %r.\n", Status);
  }

  if (*ChildListHead == NULL) {
    DPRINTF_MB3_LAN ("Didn't find any Children.\n");
    return EFI_NOT_FOUND;
  }

  DPRINTF_MB3_LAN ("Done, ChildListHead=0x%x.\n", ChildListHead);
  return EFI_SUCCESS;
} // Mb3PciLanGetChildren

SCT_BOOT_OPTION_PROTOCOL mMb3PciLanBootOptionProtocol = {
  sizeof (SCT_BOOT_OPTION_PROTOCOL),
  Mb3PciLanGetDevicePaths,
  Mb3PciLanGetChildren
};

//
// FUNCTION NAME.
//      Mb3PciLanSaveDeviceRecord - Save DeviceRecordCache to variable.
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
Mb3PciLanSaveDeviceRecord (
  VOID
  )
{
  EFI_STATUS Status;
  PMB3_DEVICE_RECORD MergedDeviceRecordCache;
  UINT8 MergedDeviceRecordCacheSize;

  DPRINTF_MB3_LAN ("Current Matched Pair: Size = %d\n", DeviceRecordCacheSize);
  DPRINTF_MB3_LAN ("Saved Matched Pair: Size = %d\n", SavedDeviceRecordCacheSize);
  Status = MergeMb3DeviceRecord (
             SavedDeviceRecordCache,
             SavedDeviceRecordCacheSize,
             DeviceRecordCache,
             DeviceRecordCacheSize,
             &MergedDeviceRecordCache,
             &MergedDeviceRecordCacheSize
             );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3_LAN ("Merge Matched Pair Cache returned %r\n", Status);
    return;
  }

  DPRINTF_MB3_LAN ("Merge Matched Pair: Size = %d\n", MergedDeviceRecordCacheSize);
  DUMP_BYTES_MB3 ((UINT8 *)DeviceRecordCache, DeviceRecordCacheSize * sizeof (MB3_DEVICE_RECORD));
  DPRINTF_MB3_LAN ("\n");

  //
  // Save Current.
  //

  Status = gRT->SetVariable (
                  SCT_MB3_VARIABLE_NAME,
                  &gMb3PciLanBootOptionProtocolGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  MergedDeviceRecordCacheSize * sizeof (MB3_DEVICE_RECORD),
                  (VOID *)MergedDeviceRecordCache
                  );

  DPRINTF_MB3_LAN ("Save Matched Pair returned %r\n", Status);

  SafeFreePool (SavedDeviceRecordCache);
  SafeFreePool (DeviceRecordCache);

  DeviceRecordCache = MergedDeviceRecordCache;
  DeviceRecordCacheSize = MergedDeviceRecordCacheSize;
  SavedDeviceRecordCache = DeviceRecordCache;
  SavedDeviceRecordCacheSize = DeviceRecordCacheSize;

  return;
} // Mb3PciLanSaveDeviceRecord

//
// FUNCTION NAME.
//      Mb3PciLanFullScanPerformed - Callback when a full scan has been performed.
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
Mb3PciLanFullScanPerformed (
  VOID
  )
{
  //
  // Full scan performed, save the data we got.
  // Connected devices changed. Need to update the variable as well
  // as the device path in boot options.
  //
  DPRINTF_MB3_LAN ("Full Scan Performed, update variable\n");
  Mb3PciLanSaveDeviceRecord ();
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
  UINTN VarSize;
  EFI_STATUS Status;

  //
  // Initialize gConnectedList.
  //

  DPRINTF_MB3_LAN ("  Initialize gConnectedList of size 0x%x.\n", mPciLanConnectListArraySize);

  gConnectedList = AllocateZeroPool (mPciLanConnectListArraySize * sizeof (BOOLEAN));
  DPRINTF_MB3_LAN (
    "  Allocated gConnectedList of size 0x%x @0x%x.\n",
    mPciLanConnectListArraySize * sizeof (BOOLEAN),gConnectedList
    );

  if (gConnectedList == NULL) {
    DPRINTF_MB3_LAN ("  Failed to allocate memory for gConnectedList.\n");
    return EFI_OUT_OF_RESOURCES;
  } else {
    for (i = 0; i < mPciLanConnectListArraySize; ++i) {
      gConnectedList[i] = FALSE;
    }
  }

  SearchNodeDevicePathArraySize = mPciLanEndNodeDevicePathsSize;


  DPRINTF_MB3_LAN ("  Initialize SearchNode array, size=0x%x.\n", SearchNodeDevicePathArraySize);
  SearchNodeDevicePathArray = AllocateZeroPool (SearchNodeDevicePathArraySize * sizeof (PCHAR16));
  if (SearchNodeDevicePathArray == NULL) {
    DPRINTF_MB3_LAN ("  Failed to allocate memory for Last node DevicePaths.\n");
    return EFI_OUT_OF_RESOURCES;
  }


  for (i = 0; i < mPciLanEndNodeDevicePathsSize; ++i) {
    SearchNodeDevicePathArray[i] = mPciLanEndNodeDevicePaths[i];
    DPRINTF_MB3_LAN ("  Initialize SearchNode array[0x%x], value=[%s].\n", i, SearchNodeDevicePathArray[i]);
  }

  DeviceRecordCache = AllocateZeroPool (CONFIG_SYSTEM_MULTI_BOOT_III_MATCHED_CACHE_SIZE * sizeof (MB3_DEVICE_RECORD));
  if (DeviceRecordCache == NULL) {
    DPRINTF_MB3_LAN ("  Failed to allocate memory for DeviceRecordCache\n");
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
             &gMb3PciLanBootOptionProtocolGuid,
             (VOID **) &SavedDeviceRecordCache,
             &VarSize
             );
  DPRINTF_MB3_LAN ("Get Saved Variable %r\n", Status);
  if (!EFI_ERROR (Status)) {
    SavedDeviceRecordCacheSize = (UINT8)VarSize;
    DUMP_BYTES_MB3 ((UINT8 *)SavedDeviceRecordCache, SavedDeviceRecordCacheSize);
    DPRINTF_MB3_LAN ("\n");
    SavedDeviceRecordCacheSize /= sizeof (MB3_DEVICE_RECORD);
  } else {
    SavedDeviceRecordCacheSize = 0;
    SavedDeviceRecordCache = NULL;
  }

  return EFI_SUCCESS;
} // InitializeInternalData

//
// FUNCTION NAME.
//      InitializeBopPciLanMb3 - Initialize the BopMb3PciLan module.
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
InitializeBopPciLanMb3 (
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
                  &gMb3PciLanBootOptionProtocolGuid,
                  &mMb3PciLanBootOptionProtocol,
                  NULL
                  );

  mImageHandle = ImageHandle;

  return Status;
} // InitializeBopPciLanMb3

//
// Private (static) routines used by this component.
//

//
// FUNCTION NAME.
//      Mb3PciLanXInsertDeviceRecord - Insert a DeviceRecord into cache.
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
Mb3PciLanXInsertDeviceRecord (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  UINTN i;
  EFI_STATUS Status;
  MB3_DEVICE_RECORD Temp;

  DPRINTF_MB3_LAN (
    "ControllerIndex: 0x%x, SearchNodeIndex: 0x%x\n",
    ControllerIndex,
    SearchNodeIndex
    );

  if (DeviceRecordCacheSize == CONFIG_SYSTEM_MULTI_BOOT_III_MATCHED_CACHE_SIZE) {
    DPRINTF_MB3_LAN ("Full\n");
    return EFI_OUT_OF_RESOURCES;
  }

  Status = Mb3SetRecord (
             ControllerIndex,
             SearchNodeIndex,
             DevicePath,
             &Temp
             );

  DPRINTF_MB3_LAN (
    "Attr=0x%x, (0x%x, 0x%x)\n",
    Temp.Attr,
    Temp.ControllerIndex,
    Temp.SearchNodeIndex
    );
  DPRINTF_MB3_LAN ("UsbPortNumber\n");
  DUMP_BYTES_MB3 ((UINT8 *)(Temp.UsbPortNumber), sizeof (UINT8) * MB3_USB_MAX_LAYER);
  DPRINTF_MB3_LAN ("\n");

  //
  // Find duplicate entries.
  //

  for (i = 0; i < DeviceRecordCacheSize; ++i) {
    if (Mb3CompareDeviceRecords (&Temp, (DeviceRecordCache + i))) {
      DPRINTF_MB3_LAN ("skip existing entry\n", DeviceRecordCacheSize);
      return EFI_SUCCESS;
    }
  }

  CopyMem (&(DeviceRecordCache[DeviceRecordCacheSize]), &Temp, sizeof (MB3_DEVICE_RECORD));
  DeviceRecordCacheSize++;
  DPRINTF_MB3_LAN ("Current Size = 0x%x\n", DeviceRecordCacheSize);
  return EFI_SUCCESS;
} // Mb3PciLanXInsertDeviceRecord

//
// FUNCTION NAME.
//      Mb3PciLanXGetDevicePaths - Get device path from give device path pair.
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
Mb3PciLanXGetDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN PMB3_DEVICE_RECORD Record OPTIONAL,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePaths,
  OUT PUINTN NumberOfDevicePaths
  )
{
  EFI_STATUS Status;
  CHAR16 *TempDesc;
  MB3_DEVICE_RECORD TempRecord;
  EFI_DEVICE_PATH_PROTOCOL *p, *dp, *q;
  EFI_DEVICE_PATH_PROTOCOL *FinalDevicePaths;
  UINTN i, n, Size;
  UINTN TotalDevicePathsSize;

  DPRINTF_MB3_LAN (
    "ControllerIndex: 0x%x, SearchNodeIndex: 0x%x\n",
    ControllerIndex,
    SearchNodeIndex
    );

  if ((DevicePaths == NULL) || (NumberOfDevicePaths == NULL)) {
    DPRINTF_MB3_LAN ("Either DevicePaths or NumberOfDevicePaths is NULL.\n");
    return EFI_INVALID_PARAMETER;
  }

  //
  // Connect all the device paths associated with this Mb3PciLan Device.
  //

  Status = Mb3PciLanXSearchDevicePaths (ControllerIndex, SearchNodeIndex, &dp, &n);
  DPRINTF_MB3_LAN (" PciLanXSearchDevicePaths returned %r, %d device paths.\n", Status, n);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DISPLAY_DEVICE_PATH_ARRAY (dp, n, L"  Mb3PciLanXSearchDevicePaths:");

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
    // Filter out non PciLan devices.
    //

    if (!Mb3PciLanIsDevicePathPciLan (p) && !IsEfiNetworkDevice (p)) {
      continue;
    }

    TempDesc = Mb3PciLanCreateDeviceDescription (p);
    if (TempDesc == NULL) {
      continue;
    }
    SafeFreePool (TempDesc);

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
        DPRINTF_MB3_LAN ("Memory out of resources!\n");
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
        DPRINTF_MB3_LAN ("Memory out of resources!\n");
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

  DPRINTF_MB3_LAN ("FinalDevicePaths buffer @ 0x%x.\n", (UINTN)FinalDevicePaths);
  DPRINTF_MB3_LAN ("NumberOfDevicePaths = 0x%x.\n", *NumberOfDevicePaths);
  DPRINTF_MB3_LAN ("TotalDevicePathsSize = 0x%x.\n", TotalDevicePathsSize);

  if ((TotalDevicePathsSize == 0) || (*NumberOfDevicePaths == 0)) {
    return EFI_NOT_FOUND;
  }

  *DevicePaths = FinalDevicePaths;

  DPRINTF_MB3_LAN ("Done.\n");
  return EFI_SUCCESS;
} // Mb3PciLanXGetDevicePaths

//
// FUNCTION NAME.
//      Mb3PciLanXSearchDevicePaths - Get device path from give device path pair.
//
// FUNCTIONAL DESCRIPTION.
//      This function searchs for all device paths to find an applicable matching given device pair. This function wraps this common action.
//
// ENTRY PARAMETERS.
//      ControllerIndex        - The index of the parent device path.
//      SearchNodeIndex - The index of the search node device path.
//
// EXIT PARAMETERS.
//      DevicePaths     - The address of a device path pointer in which to
//                        return the pointer to the array of device paths.
//      NumberOfDevicePaths - The number of device paths in the array.
//      Function Return - SCT status code.
//

EFI_STATUS
Mb3PciLanXSearchDevicePaths (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  OUT OPTIONAL EFI_DEVICE_PATH_PROTOCOL **dp,
  OUT OPTIONAL UINTN *n
  )
{
  UINTN TempN;
  EFI_STATUS Status;
  EFI_HANDLE DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL *TempDp;
  EFI_DEVICE_PATH_PROTOCOL *PciLanDp;
  BOOT_MANAGER_DEVICE_PATH_SEARCH PathToSearch;

  //
  // Search for a DevicePath match for (ControllerIndex, SearchNodeIndex)
  //

  if (gConnectedList[ControllerIndex] == FALSE) {
    DPRINTF_MB3_LAN ("  SctBdsLibConnectDevices 0x%x.\n", ControllerIndex);
    Status = SctBdsLibConnectDevices (&(mPciLanConnectListArray [ControllerIndex]));
    if (EFI_ERROR (Status)) {
      DPRINTF_MB3_LAN ("  SctBdsLibConnectDevices returned %r.\n", Status);
      return Status;
    } else {
      gConnectedList[ControllerIndex] = TRUE;
    }
  } else {
    //DPRINTF_MB3_LAN ("  SctBdsLibConnectDevices 0x%x already connected.\n", ControllerIndex);
  }

  ShadowOproms (&(mPciLanConnectListArray[ControllerIndex]));

  if (SearchNodeDevicePathArray[SearchNodeIndex][0] == L'\0') {
    //
    // To support complete device path in connect list.
    //

    PciLanDp = ConvertTextToDevicePath (mPciLanConnectListArray[ControllerIndex].TextDevicePath);
    if (PciLanDp == NULL) {
      DPRINTF_MB3_LAN ("ConvertTextToDevicePath returned failed.\n");
    }

    TempDp = PciLanDp;
    Status = gBS->LocateDevicePath (
                    &gEfiPciIoProtocolGuid,
                    &TempDp,
                    &DeviceHandle
                    );

    if (!EFI_ERROR (Status)) {
      if (Mb3PciLanIsDevicePathPciLan (PciLanDp)) {
        *dp = NULL;
        *n = 0;
        AppendDevicePathArray (PciLanDp, 1, dp, n);
        return EFI_SUCCESS;
      }
    }
    SafeFreePool (PciLanDp);
  }

  //
  // Search for devices that match this Mb3PciLan criteria.
  //

  TempDp = NULL;
  PathToSearch.ParentDevicePathText = mPciLanConnectListArray[ControllerIndex].TextDevicePath;
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

  DPRINTF_MB3_LAN ("Returned %r, %d entries.\n", Status, TempN);
  return Status;
} // Mb3PciLanXSearchDevicePaths

//
// FUNCTION NAME.
//      Mb3PciLanXGetChildren - Append Child Nodes to a Linked List.
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
Mb3PciLanXGetChildren (
  IN PMB3_DEVICE_RECORD Record,
  OUT PSCT_BOOT_OPTION_NODE *ChildListHead
  )
{
  UINTN i, n;
  UINT32 Attr;
  EFI_STATUS Status;
  PSCT_BOOT_OPTION_NODE *q;
  EFI_DEVICE_PATH_PROTOCOL *p, *dp;

  DPRINTF_MB3_LAN (
    "Attr=0x%x, (0x%x,0x%x)\n",
    Record->Attr,
    Record->ControllerIndex,
    Record->SearchNodeIndex
    );
  DUMP_BYTES_MB3 ((UINT8 *)(Record->UsbPortNumber), sizeof (UINT8) * MB3_USB_MAX_LAYER);
  DPRINTF_MB3_LAN ("\n");

  Attr = Record->Attr;

  //
  // Connect all the device paths associated with this Mb3PciLan Device.
  //

  dp = NULL;
  n = 0;
  Status = Mb3PciLanXGetDevicePaths (Record->ControllerIndex, Record->SearchNodeIndex, Record, &dp, &n);
  DPRINTF_MB3_LAN ("Mb3PciLanXGetDevicePaths returned %r, %d entries.\n", Status, n);
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
      DPRINTF_MB3_LAN ("  Failed to allocate SCT_BOOT_OPTION_NODE.\n");
      return EFI_OUT_OF_RESOURCES;
    }
    DPRINTF_MB3_LAN ("New BootOptionNode 0x%x:0x%x", q, *q);

    //
    // Copy the device path into the new Boot Option Node.
    //

    (*q)->NumberOfFilePaths = 1;
    (*q)->FilePathListLength = (UINT16)GetDevicePathSize (p);
    (*q)->FilePathList = AllocateCopyPool ((*q)->FilePathListLength, p);

    //
    // Create a description string for this device path.
    //

    (*q)->Description = Mb3PciLanCreateDeviceDescription (p);
    DPRINTF_MB3_LAN ("CreateDeviceDescription Done.\n");
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

  DPRINTF_MB3_LAN ("Release Memory.\n");
  SafeFreePool (dp);
  DPRINTF_MB3_LAN ("Done.\n");
  return EFI_SUCCESS;
} // Mb3PciLanXGetChildren

//
// FUNCTION NAME.
//      Mb3PciLanCreateDeviceDescription - Create a string based on a device path.
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
Mb3PciLanCreateDeviceDescription (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  PCHAR16 Str = NULL;
  CHAR16 *DevicePathName;
  CHAR16 *IpVersionName;
  CHAR16 *MacName;

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  EFI_STATUS Status;
  BBS_DEVICE_INFO BbsBcv;
  UINTN StringLength;

  Status = GetBbsDesc (DevicePath, &BbsBcv);
  if (!EFI_ERROR (Status)) {
    StringLength = AsciiStrLen (BbsBcv.DescriptionString) + 1;
    Str = (CHAR16 *)AllocateZeroPool (StringLength * sizeof (CHAR16));
    AsciiStrToUnicodeStrS (BbsBcv.DescriptionString, Str, StringLength);
    DPRINTF_MB3_LAN ("Found: desc=[%s]\n", Str);
    return Str;
  }
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  if (IsEfiNetworkDevice (DevicePath)) {
    Str = AllocateZeroPool (40 * sizeof (CHAR16));
    DevicePathName = ConvertDevicePathToText (DevicePath, FALSE, TRUE);
    MacName = StrStr (DevicePathName, L"MAC");
    IpVersionName = StrStr (DevicePathName, L"IPv");
    MacName += 4;                     // skip MAC address header: "MAC(".
    MacName[12] = 0;                  // place terminated character for MAC address.
    IpVersionName[4] = 0;             // place terminated character for IP version.

    UnicodeSPrint (Str, 80, L"LAN(%s)-%s", MacName, IpVersionName);
    DPRINTF_MB3_LAN ("EFI Device found: desc=[%s]\n", Str);
    return Str;
  }

  return NULL;
} // Mb3PciLanCreateDeviceDescription

//
// FUNCTION NAME.
//      Mb3PciLanIsDevicePathPciLan - Check to see if a handle is a pci lan device.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes a device handle and do some checks with it to see
//      if it's an pci lan device.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path to check.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

BOOLEAN
Mb3PciLanIsDevicePathPciLan (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  EFI_STATUS Status;
  EFI_PCI_IO_PROTOCOL *PciIo;
  UINT8 Class;
  EFI_HANDLE PciHandle;

  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &DevicePath,
                  &PciHandle
                  );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = gBS->HandleProtocol (
                  PciHandle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **) &PciIo
                  );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3_LAN ("  FALSE:Could not open PciIo Protocol.\n");
    return FALSE;
  }

  PciIo->Pci.Read (
               PciIo,
               EfiPciIoWidthUint8,
               0x0b,
               1,
               &Class
               );
  DPRINTF_MB3_LAN ("  Class = 0x%x.\n", Class);

  if (Class != PCI_CLASS_NETWORK) {
    return FALSE;
  }

  return TRUE;
} // Mb3PciLanIsDevicePathPciLan

//
// FUNCTION NAME.
//      IsEfiNetworkDevice - Test if this is a valid EFI Network device.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes a device path and tests it to determine if it
//      is a valid EFI Network device.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path to test.
//
// EXIT PARAMETERS.
//      Function Return - TRUE if a valid EFI Network device; otherwise, FALSE.
//
// WARNINGS.
//      None.
//

STATIC
BOOLEAN
IsEfiNetworkDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *dp
  )
{
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_MB3_LAN ("\n");

  if (dp == NULL) {
    DPRINTF_MB3_LAN ("  FALSE:DevicePath is NULL.\n");
    return FALSE;
  }

  if (IsDevicePathEnd (dp)) {
    DPRINTF_MB3_LAN ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  RemainingDevicePath = dp;

  //
  // Must support PXE Base Code Protocol.
  //

  Status = gBS->LocateDevicePath (
                  &gEfiPxeBaseCodeProtocolGuid,
                  &RemainingDevicePath,
                  &Handle
                  );

  //
  // Must be totally matched.
  //

  if (!EFI_ERROR (Status) && IsDevicePathEnd (RemainingDevicePath)) {
    return TRUE;
  }

  return FALSE;
} // IsEfiNetworkDevice
