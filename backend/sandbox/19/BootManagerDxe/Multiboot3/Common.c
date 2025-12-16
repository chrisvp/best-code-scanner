//
// FILENAME.
//      Common.c - SecureCore Technology(TM) MultiBoot III Boot Option protocol.
//
// FUNCTIONAL DESCRIPTION.
//      Common functions for MB3 BOP.
//
// NOTICE.
//      Copyright (C) 2010-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//


#include "Meta.h"

#define UNKNOWN_DESCRIPTION_STR "Unknown Device"

//
// Private data types used by this module are defined here and any
// static items are declared here.
//

//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      Mb3CompareDeviceRecords - Compare two MB3_DEVICE_RECORD.
//
// FUNCTIONAL DESCRIPTION.
//      Compare two MB3_DEVICE_RECORD and see if they are the same device.
//
// ENTRY PARAMETERS.
//      RecordA         - A record to be compared.
//      RecordB         - The other record to be compared.
//
// EXIT PARAMETERS.
//      Function Return - TRUE if they are the same device.
//                        FALSE if they are not the same.
//

BOOLEAN
Mb3CompareDeviceRecords (
  IN PMB3_DEVICE_RECORD RecordA,
  IN PMB3_DEVICE_RECORD RecordB
  )
{
  UINT16 AttrA, AttrB;
  INTN Result;

  AttrA = RecordA->Attr;
  AttrB = RecordB->Attr;

  DPRINTF_MB3 ("\n");
  if ((AttrA & MB3_ATTR_USB) != (AttrB & MB3_ATTR_USB)) {
    DPRINTF_MB3 ("Different device type\n");
    return FALSE;
  }

  RecordA->Attr = 0;
  RecordB->Attr = 0;

  Result = CompareMem (RecordA, RecordB, sizeof (MB3_DEVICE_RECORD));
  RecordA->Attr = AttrA;
  RecordB->Attr = AttrB;
  DPRINTF_MB3 ("Result=%d\n", Result);

  if (Result == 0) {
    return TRUE;
  }
  return FALSE;
} // Mb3CompareDeviceRecords

//
// FUNCTION NAME.
//      MergeMb3DeviceRecord - Merge two MB3_DEVICE_RECORD.
//
// FUNCTIONAL DESCRIPTION.
//      Merge the boot devices found in the system with the old records saved
//      in the variable to keep old settings. Newly found devices will be
//      appended to the tail.
//
// ENTRY PARAMETERS.
//      OldRecords      - Old records.
//      OldRecordsSize  - Number of elements in OldRecords.
//      NewRecords      - New records.
//      NewRecordsSize  - Number of elements in NewRecords.
//
// EXIT PARAMETERS.
//      MergedRecords   - Merged records.
//      MergedRecordsSize - Number of elements in MergedRecords.
//      Function Return - EFI status code.
//

EFI_STATUS
MergeMb3DeviceRecord (
  IN PMB3_DEVICE_RECORD OldRecords,
  IN UINT8 OldRecordsSize,
  IN PMB3_DEVICE_RECORD NewRecords,
  IN UINT8 NewRecordsSize,
  OUT PMB3_DEVICE_RECORD *MergedRecords,
  OUT UINT8 *MergedRecordsSize
  )
{
  UINTN i, j;
  UINTN MergedIndex;
  PMB3_DEVICE_RECORD Temp;

  if (OldRecords == NewRecords) {
    return EFI_SUCCESS;
  }

  if (NewRecordsSize + OldRecordsSize < 1) {
    return EFI_INVALID_PARAMETER;
  }

  *MergedRecords = NULL;
  *MergedRecordsSize = 0;

  Temp = AllocatePool ((OldRecordsSize + NewRecordsSize) * (sizeof (MB3_DEVICE_RECORD)));

  if (Temp == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // For each OldRecords[i], copy it to MergedRecords if it's in NewRecords.
  // Then remove the entry in NewRecords.
  //

  MergedIndex = 0;
  for (i = 0; i < OldRecordsSize; ++i) {
    for (j = 0; j < NewRecordsSize; ++j) {
      if (Mb3CompareDeviceRecords ((OldRecords + i), (NewRecords + j))) {
        CopyMem ((Temp + MergedIndex), (OldRecords + i), sizeof (MB3_DEVICE_RECORD));

        MergedIndex++;

        NewRecords[j].ControllerIndex = MB3_DEVICE_RECORD_INDEX_OUT_OF_BOUND;
        NewRecords[j].SearchNodeIndex = MB3_DEVICE_RECORD_INDEX_OUT_OF_BOUND;
        break;
      }

    }
  }

  //
  // Copy anything left in NewRecords to MergedRecords.
  //

  for (j = 0; j < NewRecordsSize; ++j) {
    if (NewRecords[j].ControllerIndex == MB3_DEVICE_RECORD_INDEX_OUT_OF_BOUND) {
      continue;
    }

    CopyMem ((Temp + MergedIndex), (NewRecords + j), sizeof (MB3_DEVICE_RECORD));

    MergedIndex++;
  }

  *MergedRecords = AllocatePool (MergedIndex * (sizeof (MB3_DEVICE_RECORD)));

  if (*MergedRecords == NULL) {
    SafeFreePool (Temp);
    return EFI_OUT_OF_RESOURCES;
  }

  for (i = 0; i < MergedIndex; ++i) {
    CopyMem (((*MergedRecords) + i), (Temp + i), sizeof (MB3_DEVICE_RECORD));
  }

  *MergedRecordsSize = (UINT8)MergedIndex;
  SafeFreePool (Temp);

  return EFI_SUCCESS;
} // MergeMb3DeviceRecord


//
// FUNCTION NAME.
//      Mb3SetRecord - Fill the MB3_DEVICE_RECORD for a device.
//
// FUNCTIONAL DESCRIPTION.
//      Fill the MB3_DEVICE_RECORD for a device path.
//
// ENTRY PARAMETERS.
//      ControllerIndex - The index of the controller list.
//      SearchNodeIndex - The index of the search node array.
//      DevicePath      - The device path of the device.
//      Record          - The record to be filled.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status code.
//

EFI_STATUS
Mb3SetRecord (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN OUT PMB3_DEVICE_RECORD Record
  )
{
  UINTN UsbLayerCount;
  DEVICE_PATH_PTR Dp;
  EFI_DEVICE_PATH_PROTOCOL *p;

  DPRINTF_MB3 ("\n");

  if (Record == NULL || DevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  DISPLAY_DEVICE_PATH_ARRAY (DevicePath, 1, L"  Mb3SetRecord:");

  ZeroMem (Record, sizeof (MB3_DEVICE_RECORD));

  UsbLayerCount = 0;
  Record->Attr = 0;
  Record->ControllerIndex = ControllerIndex;
  Record->SearchNodeIndex = SearchNodeIndex;

  p = DevicePath;
  while (TRUE) {
    if (IsDevicePathEnd (p)) {
      break;
    }

    if (UsbLayerCount == MB3_USB_MAX_LAYER) {
      DPRINTF_MB3 ("USbPortNumber buffer overflow before device path ends");
      break;
    }

    if (IsDeviceNodeUsb (p)) {
      Dp.DevPath = p;
      Record->UsbPortNumber[UsbLayerCount] = Dp.Usb->ParentPortNumber;
      DPRINTF_MB3 ("UsbPortNumber[%d] = 0x%x\n", UsbLayerCount, Dp.Usb->ParentPortNumber);
      UsbLayerCount++;
    }

    if (DevicePathTypeSubType (p) ==
        TypeSubType (MESSAGING_DEVICE_PATH, MSG_DEVICE_LOGICAL_UNIT_DP)) {
      Dp.DevPath = p;
      Record->UsbPortNumber[UsbLayerCount] = Dp.UsbLun->Lun;
      DPRINTF_MB3 ("UsbPortNumber (Lun) [%d] = 0x%x\n", UsbLayerCount, Dp.UsbLun->Lun);
      UsbLayerCount++;
    }

    if (IsDeviceNodeScsi (p)) {
      Dp.DevPath = p;
      Record->UsbPortNumber[UsbLayerCount] = (UINT8)(Dp.Scsi->Pun & 0xff);
      UsbLayerCount++;
      Record->UsbPortNumber[UsbLayerCount] = (UINT8)((Dp.Scsi->Pun >> 8) & 0xff);
      UsbLayerCount++;
      Record->UsbPortNumber[UsbLayerCount] = (UINT8)(Dp.Scsi->Lun & 0xff);
      UsbLayerCount++;
      Record->UsbPortNumber[UsbLayerCount] = (UINT8)((Dp.Scsi->Lun >> 8) & 0xff);
      UsbLayerCount++;
    }

    p = NextDevicePathNode (p);
  }

  ASSERT_MB3 (UsbLayerCount <= MB3_USB_MAX_LAYER);

  return EFI_SUCCESS;
} // Mb3SetRecord

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
//
// FUNCTION NAME.
//      GetBbsDesc - Get the SctBbsBcvHddDesc protocol of a device path.
//
// FUNCTIONAL DESCRIPTION.
//      Get the SctBbsBcvHddDesc protocol of a device path. This protocol
//      provides desc and type information for pure legacy boot devices
//      so that boot menu can get the correct desc and type of the devices.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      BbsBcv          - A pointer to BBS_DEVICE_INFO data structure.
//

EFI_STATUS
GetBbsDesc (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PBBS_DEVICE_INFO BbsBcv
  )
{
  int i;
  EFI_STATUS Status;
  BBS_TABLE *BbsTable;
  UINT16 BbsCount;
  int BbsTableIndex;                    // BBS Table index of device to boot.
  UINT16 HddCount;                      // number of entries in HddInfo.
  HDD_INFO *HddInfo;                    // points to Hard Drive information.
  UINT16 DescriptionStringOffset;
  UINT16 DescriptionStringSegment;
  EFI_LEGACY_BIOS_PROTOCOL *LegacyBios;
  EFI_DEVICE_PATH_PROTOCOL **BbsTableDevicePaths;
  CHAR8 *Description;

  i = 0;
  DescriptionStringOffset = 0;
  DescriptionStringSegment = 0;
  Description = NULL;

  Status = gBS->LocateProtocol (
                  &gEfiLegacyBiosProtocolGuid,
                  NULL,
                  (VOID **) &LegacyBios
                  );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Couldn't locate Legacy Bios Protocol:%r.\n", Status);
    return Status;
  }

  //
  // Get the BBS Table from the LegacyBios driver.
  //
  BbsTable = NULL;
  Status = LegacyBios->GetBbsInfo (
                          LegacyBios,
                          &HddCount,
                          &HddInfo,
                          &BbsCount,
                          (VOID **) &BbsTable
                          );
  DPRINTF_MB3 ("  GetBbsInfo returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    BbsTable = NULL;
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gBbsTableDevicePathsTableGuid,
                  NULL,
                  (VOID **)&BbsTableDevicePaths
                  );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Can't locate BBS device path table\n");
    return Status;
  }

  for (BbsTableIndex = 0; BbsTableIndex < BbsCount; BbsTableIndex++) {
    if (BbsTableDevicePaths[BbsTableIndex] != NULL) {
      DEBUG_MB3 (
        CHAR16 *Str = NULL;
        Str = ConvertDevicePathToText (BbsTableDevicePaths[BbsTableIndex], FALSE, TRUE);
        DPRINTF_MB3 (
          "Found Device Path for BBS Table index %d='%s'.\n",
          BbsTableIndex,
          Str
          );
        SafeFreePool (Str);
      );
      if (CompareDevicePath (DevicePath, BbsTableDevicePaths[BbsTableIndex])) {
        DPRINTF_MB3 ("DevicePath Found in BBS Table index #%d\n", BbsTableIndex);
        break;
      }
    }
  }

  if (BbsTableIndex == BbsCount) {
    DPRINTF_MB3 ("Unable to find a matching device path in the BBS table\n");
    Status = EFI_NOT_FOUND;
    return Status;
  }

  DescriptionStringSegment = BbsTable[BbsTableIndex].DescStringSegment;
  DescriptionStringOffset = BbsTable[BbsTableIndex].DescStringOffset;

  if (DescriptionStringSegment == 0) {
    Description = UNKNOWN_DESCRIPTION_STR;
    BbsBcv->DescriptionString = AllocateZeroPool (AsciiStrLen (Description) + 1);
    AsciiStrCpyS (BbsBcv->DescriptionString, AsciiStrLen (Description) + 1, Description);
  } else {
    Description = (CHAR8 *)(UINTN)((DescriptionStringSegment << 4) + DescriptionStringOffset);

    //
    // According to BBS Spec. 3.1.2, the max length of visible string is
    // 32 bytes. Plus the additional NULL terminator, we allocate 33 bytes.
    //

    BbsBcv->DescriptionString = AllocateZeroPool (CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH + 1);
    CopyMem (BbsBcv->DescriptionString, Description, (CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH + 1));

    //
    // Check if Product Name string length exceed the maximum visible range.
    //

    for (i = 0; i < (CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH + 1); i++) {
      if (*(BbsBcv->DescriptionString + i) == 0) {
        break;
      }
    }

    //
    // If no terminated character found, truncate string length to 32.
    //

    if (i == (CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH + 1)) {
      *(BbsBcv->DescriptionString + CONFIG_SYSTEM_CSM_MAXIMUM_VISIBLE_STRING_LENGTH) = 0;
    }
  }

  BbsBcv->DeviceType = BbsTable[BbsTableIndex].DeviceType;
  BbsBcv->Class = BbsTable[BbsTableIndex].Class;
  BbsBcv->SubClass = BbsTable[BbsTableIndex].SubClass;

  DPRINTF_MB3 ("BbsBcv.DescriptionString: %s.\n", BbsBcv->DescriptionString);
  DPRINTF_MB3 ("BbsBcv.DeviceType: 0x%x.\n", BbsBcv->DeviceType);
  DPRINTF_MB3 ("BbsBcv.Class: 0x%x.\n", BbsBcv->Class);
  DPRINTF_MB3 ("BbsBcv.SubClass: 0x%x.\n", BbsBcv->SubClass);

  return EFI_SUCCESS;
} // GetBbsDesc
#endif

//
// FUNCTION NAME.
//      GetUsbMsdDeviceName - Get USB mass storage name.
//
// FUNCTIONAL DESCRIPTION.
//      Get USB mass storage name.
//
// ENTRY PARAMETERS.
//      UsbHandle       - USB device handle.
//
// EXIT PARAMETERS.
//      UsbDeviceName   - CHAR16 String - Name of USB mass storage.
//      Function Return - EFI Status Code.
//

EFI_STATUS
GetUsbMsdDeviceName (
  IN EFI_HANDLE UsbHandle,
  OUT CHAR16 **UsbDeviceName
  )
{
  EFI_STATUS Status;
  UINT32 InfoSize;
  CHAR8 DeviceName[USB_MSD_DEVICE_LEN + 1];
  CHAR8 VendorId[USB_VENDOR_ID_LEN + 1];
  CHAR8 ProductId[USB_PRODUCT_ID_LEN + 1];
  USB_MASS_INQUIRY_DATA Info;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;

  if (UsbDeviceName == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *UsbDeviceName = NULL;

  Status = gBS->HandleProtocol (
                  UsbHandle,
                  &gEfiDiskInfoProtocolGuid,
                  (VOID **)&DiskInfo
                  );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Fail to get Disk_Info\n");
    return Status;
  }

  InfoSize = sizeof (USB_MASS_INQUIRY_DATA);
  Status = DiskInfo->Inquiry (DiskInfo, &Info, &InfoSize);
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Fail to Inquiry data\n");
    return Status;
  }

  //
  // Copy Vendor ID.
  //

  CopyMem (VendorId, Info.VendorID, USB_VENDOR_ID_LEN);
  VendorId[USB_VENDOR_ID_LEN] = '\0';
  DPRINTF_MB3 ("  Vendor ID = %a\n", VendorId);
  BmAsciiStrTrim (VendorId, ' ');

  //
  // Copy Product ID.
  //

  CopyMem (ProductId, Info.ProductID, USB_PRODUCT_ID_LEN);
  ProductId[USB_PRODUCT_ID_LEN] = '\0';
  DPRINTF_MB3 ("  Product ID = %a\n", ProductId);
  BmAsciiStrTrim (ProductId, ' ');


  SetMem (DeviceName, (USB_MSD_DEVICE_LEN + 1), 0);
  if (AsciiStrLen (VendorId) == 0 && AsciiStrLen (ProductId) == 0) {
    //
    // Default device name.
    //
    AsciiStrCatS (DeviceName, USB_MSD_DEVICE_LEN + 1, "Generic USB Device");
  } else {
    AsciiStrCatS (DeviceName, USB_MSD_DEVICE_LEN + 1, VendorId);
    AsciiStrCatS (DeviceName, USB_MSD_DEVICE_LEN + 1, " ");
    AsciiStrCatS (DeviceName, USB_MSD_DEVICE_LEN + 1, ProductId);
  }

  DPRINTF_MB3 ("  DeviceName = %a\n", DeviceName);

  //
  // Convert to Unicode string.
  //

  *UsbDeviceName = (CHAR16 *)AllocateZeroPool (sizeof (CHAR16) * (USB_MSD_DEVICE_LEN + 1));
  AsciiStrToUnicodeStrS (DeviceName, *UsbDeviceName, (USB_MSD_DEVICE_LEN + 1));

  DPRINTF_MB3 ("  USB Device Name = %s\n", *UsbDeviceName);
  return EFI_SUCCESS;
} // GetUsbMsdDeviceName

//
// FUNCTION NAME.
//      DelayForUsb - Delay for USB Detection.
//
// FUNCTIONAL DESCRIPTION.
//      It takes time to detect USB devices, but it can cost  extra time
//      to wait in each BOP instance. So a common function is created
//      to wait once in each boot.
//
// ENTRY PARAMETERS.
//      Delay           - Time to delay.
//
// EXIT PARAMETERS.
//      None.
//

VOID
DelayForUsb (
  IN UINTN Delay
  )
{
  STATIC BOOLEAN Delayed = FALSE;

  if (Delayed == TRUE) {
    return;
  }

  gBS->Stall (Delay);
  Delayed = TRUE;

  return;
} // DelayForUsb

//
// FUNCTION NAME.
//      BmAsciiStrTrim - Removes specified leading and trailing characters from a string.
//
// FUNCTIONAL DESCRIPTION.
//      This function will remove unwanted leading and trailing characters of a string.
//
// ENTRY PARAMETERS.
//      String          - Pointer to the null-terminated string to be trimmed. On return,
//                        str will hold the trimmed string.
//      CharC           - Character will be trimmed from str.
//
// EXIT PARAMETERS.
//      String          - Trimmed string.
//

VOID
BmAsciiStrTrim (
  IN OUT CHAR8 *String,
  IN CHAR8 CharC
  )
{
  CHAR8 *p1;
  CHAR8 *p2;

  if (*String == 0) {
    return;
  }

  //
  // Trim off the leading and trailing characters c.
  //

  for (p1 = String; *p1 && *p1 == CharC; p1++) {
    ;
  }

  p2 = String;
  if (p2 == p1) {
    while (*p1) {
      p2++;
      p1++;
    }
  } else {
    while (*p1) {
    *p2 = *p1;
    p1++;
    p2++;
    }
    *p2 = 0;
  }

  for (p1 = String + AsciiStrLen (String) - 1; p1 >= String && *p1 == CharC; p1--) {
    ;
  }
  if (p1 !=  String + AsciiStrLen (String) - 1) {
    *(p1 + 1) = 0;
  }
} // BmAsciiStrTrim

//
// FUNCTION NAME.
//      IsEfiBootableDevicePath - Is it a EFI-bootable device.
//
// FUNCTIONAL DESCRIPTION.
//      This function checks the device path to see if it is a EFI-bootable
//      device.
//
// ENTRY PARAMETERS.
//      DevicePath      - a pointer to an instance of the Device Path Protocol
//                        which is installed on the handle that this function
//                        will examine.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN, TRUE for Bootable Media, else FALSE.
//

BOOLEAN
IsEfiBootableDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;
  EFI_LOAD_FILE_PROTOCOL * LoadFile;
  EFI_PXE_BASE_CODE_PROTOCOL *PxeBase;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_MB3 ("\n");

  if (DevicePath == NULL) {
    DPRINTF_MB3 ("  FALSE:DevicePath is NULL.\n");
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_MB3 ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle
                  );
  DPRINTF_MB3 (
    "  LocateDevicePath: Status = %r, Handle = 0x%x\n",
    Status,
    Handle
    );

  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  FALSE:LocateDevicePath error.\n");
    return FALSE;
  }

  if (!IsDevicePathEnd (RemainingDevicePath)) {
    DPRINTF_MB3 ("  FALSE:No exact DevicePath match found.\n");
    return FALSE;
  }

  //
  // Get the Simple FS Protocol instance that is installed on this handle.
  //

  Status = gBS->HandleProtocol (
                  Handle,                     // the handle being tested.
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&SimpleFileSystem
                  );
  DPRINTF_MB3 ("  HandleProtocol (gEfiSimpleFileSystemProtocolGuid): %r\n", Status);
  if (!EFI_ERROR (Status)) {
    return TRUE;
  }

  //
  // Get the LoadFile Protocol instance that is installed on this handle.
  //

  Status = gBS->HandleProtocol (
                  Handle,                     // the handle being tested.
                  &gEfiLoadFileProtocolGuid,
                  (VOID **)&LoadFile
                  );
  DPRINTF_MB3 ("  HandleProtocol (gEfiLoadFileProtocolGuid): %r\n", Status);

  if (!EFI_ERROR (Status)) {
    return TRUE;
  }

  //
  // Get the BlockIo Protocol instance that is installed on this handle.
  //

  Status = gBS->HandleProtocol (
                  Handle,                     // the handle being tested.
                  &gEfiBlockIoProtocolGuid,
                  (VOID **)&BlockIo
                  );
  DPRINTF_MB3 ("  HandleProtocol (gEfiBlockIoProtocolGuid): %r\n", Status);
  if (!EFI_ERROR (Status)) {
    return TRUE;
  }

  //
  // Get the BlockIo Protocol instance that is installed on this handle.
  //

  Status = gBS->HandleProtocol (
                  Handle,                     // the handle being tested.
                  &gEfiPxeBaseCodeProtocolGuid,
                  (VOID **)&PxeBase
                  );
  DPRINTF_MB3 ("  HandleProtocol (gEfiPxeBaseCodeProtocolGuid): %r\n", Status);
  if (!EFI_ERROR (Status)) {
    return TRUE;
  }

  DPRINTF_MB3 ("IsEfiBootableDevicePath: FALSE\n");
  return FALSE;
} // IsEfiBootableDevicePathc


//
// FUNCTION NAME.
//      LoadOpromFromDevicePath - Load OPROM from Device Path.
//
// FUNCTIONAL DESCRIPTION.
//      Load an option ROM based on the device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path for the option ROM to boot.
//
// EXIT PARAMETERS.
//      Function return - EFI status code.
//

EFI_STATUS
LoadOpromFromDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT VOID **RomShadowAddress, OPTIONAL
  OUT UINT32 *RomShadowedSize OPTIONAL
  )
{
#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_HANDLE Handle;
  VOID  *RomImage;
  UINTN RomImageSize;
  UINTN Flags;
  VOID *LocalRomShadowAddress;
  UINT32 LocalRomShadowedSize;
  EFI_LEGACY_BIOS_PROTOCOL *LegacyBios;

  DPRINTF_MB3 ("LoadOpromFromDevicePath:\n");

  if (DevicePath == NULL){
    DPRINTF_MB3 ("  Invalid Parameter.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (
                  &gEfiLegacyBiosProtocolGuid,
                  NULL,
                  &LegacyBios
                  );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Couldn't locate Legacy Bios Protocol:%r.\n", Status);
    return Status;
  }

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &Handle
                  );
  DPRINTF_MB3 ("  LocateDevicePath: Status = %r, Handle = 0x%x\n", Status, Handle);

  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Failed to locate device path, status: %r.\n", Status);
    return Status;
  }

#if (OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3_INSTRUMENTATION)
  Status = DisplayDevicePath (Handle, 2);
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Failed to display device path, status: %r.\n", Status);
    return Status;
  }
#endif // ((OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3_INSTRUMENTATION)

  //
  // Check to see if there is a legacy option ROM image associated with
  // this PCI device. If there is, install it.
  //

  Status = LegacyBios->CheckPciRom (
                         LegacyBios,
                         Handle,
                         &RomImage,
                         &RomImageSize,
                         &Flags
                         );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  Failed legacy check PCI ROM, status: %r.\n", Status);
    return Status;
  }

  //
  // Load the legacy option ROM.
  //

  Status = LegacyBios->InstallPciRom (
                         LegacyBios,
                         Handle,
                         NULL,
                         &Flags,
                         NULL,
                         NULL,
                         &LocalRomShadowAddress,
                         &LocalRomShadowedSize
                         );
  if (EFI_ERROR (Status)) {
    DPRINTF_MB3 ("  InstallPciRom error, status: %r.\n", Status);
    return Status;
  }

  //
  // Optionally return OPROM statistics.
  //

  if (RomShadowAddress) {
    *RomShadowAddress = LocalRomShadowAddress;
  }

  if (RomShadowedSize) {
    *RomShadowedSize = LocalRomShadowedSize;
  }

  return SCT_STATUS_SUCCESS;
#else
  return SCT_STATUS_UNSUPPORTED;
#endif //OPTION_DEBUG_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
} // LoadOpromFromDevicePath

//
// FUNCTION NAME.
//      ShadowOproms - Shadow all OPROMs.
//
// FUNCTIONAL DESCRIPTION.
//      This function will shadow the OPROMs based on the list.
//
// ENTRY PARAMETERS.
//      DeviceList      - Array of BOOT_MANAGER_CONNECTION_DEVICE objects.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
ShadowOproms (
  IN BOOT_MANAGER_CONNECTION_DEVICE *DeviceList
  )
{
#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  PBOOT_MANAGER_CONNECTION_DEVICE p;

  DPRINTF_MB3 ("ShadowOproms:\n");

  //
  // If there is no list to connect return immediately.
  //

  if (DeviceList == NULL) {
    return SCT_STATUS_SUCCESS;
  }

  p = DeviceList;
  while (TRUE) {
    if (p->TextDevicePath == NULL) {
      break;
    }
    DevicePath = NULL;
    DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (DevicePath == NULL) {
      DPRINTF_MB3 (
        "  Failed to convert %s to a device path.\n",
        p->TextDevicePath);
      p++;
      continue;
    }

    Status = LoadOpromFromDevicePath (DevicePath, NULL, NULL);
    DPRINTF_MB3 (" LoadOpromFromDevicePath result %r:\n", Status);
    SafeFreePool (DevicePath);
    p++;
  }

  DPRINTF_MB3 ("ShadowOproms End.\n");
#endif
  return SCT_STATUS_SUCCESS;
} // ShadowOproms