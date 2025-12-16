//
// FILENAME.
//      Legacy.h - SecureCore Technology(TM) Legacy Function Head file.
//
// FUNCTIONAL DESCRIPTION.
//      This include file contains standard data type definitions for Legacy
//      functions for BootManager DXE Driver.
//
// NOTICE.
//      Copyright (C) 2016-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_LEGACY_CMD
#define _SCT_H_LEGACY_CMD



#ifndef SCT_MODULE_CSMMODULE

#define EFI_LEGACY_BIOS_GUID \
  { \
    0x2e3044ac, 0x879f, 0x490f, {0x97, 0x60, 0xbb, 0xdf, 0xaf, 0x69, 0x5f, 0x50 } \
  }


extern EFI_GUID gEfiLegacyBiosGuid;

#else // SCT_MODULE_CSMMODULE

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
  );

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
  );

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
  );

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
  );

EFI_STATUS
UpdateBdaKeyboardFlag (VOID);

#endif //SCT_MODULE_CSMMODULE

#endif // _SCT_H_LEGACY_CMD
