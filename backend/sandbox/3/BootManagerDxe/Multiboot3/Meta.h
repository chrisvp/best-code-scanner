//
// FILENAME.
//      Meta.h - SecureCore Technology(TM) MultiBootIII BOP driver Top-Level Include File.
//
// FUNCTIONAL DESCRIPTION.
//      This include file includes all of the other include files for
//      the MultiBootIII BOP driver.
//
// NOTICE.
//      Copyright (C) 2009-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_META
#define _SCT_H_META

//
// Standard header files included by modules in this driver.
//

#include <SysMeta.h>                    // SCT System Includes.

//
// EDK2 standard headers
//
#include <PiDxe.h>
#include <IndustryStandard/Pci.h>       // for PCI_CLASS_NETWORK

#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Protocol/DevicePath.h>
#include <Protocol/BlockIo.h>
#include <Protocol/PciIo.h>
#include <Protocol/DiskInfo.h>
#include <Protocol/IdeControllerInit.h>
#include <Protocol/PxeBaseCode.h>
#include <Protocol/LoadFile.h>
#include <Protocol/SimpleFileSystem.h>

//
// SCT specific headers
//
#include "BdsMisc.h"                    // Private data for USB Legacy support
#include <Guid/MultiBoot3.h>
#include <Protocol/SctBdsServices.h>
#include <Protocol/SctBootOption.h>

#if OPTION_SUPPORT_CSM
#include <SctLegacy.h>
#include <LegacyBiosIntr.h>
#include <Guid/LegacyBios.h>            // Access the LegacyBios driver's private data.
#include <Protocol/LegacyBios.h>
#endif //OPTION_SUPPORT_CSM

#include <Library/SctDxeLib.h>
#include <Library/SctBdsLib.h>          // Boot Manager object definition and function prototypes.
#include <Library/SctBmDevicePathLib.h>
#include <Library/SctBmDebugLib.h>

#include <Protocol/SctHddSecurityServiceProtocol.h>
#include <Protocol/SctNvmeDeviceServiceProtocol.h>

//
// Function definition
//
typedef
EFI_STATUS
(EFIAPI *BopInitialization) (EFI_HANDLE);

//
// BopFixedDisk.c
//
EFI_STATUS
EFIAPI
InitializeBopFixedDiskMb3 (
  IN EFI_HANDLE ImageHandle
  );

//
// BopOpticalDrive.c
//
EFI_STATUS
EFIAPI
InitializeBopOpticalDriveMb3 (
  IN EFI_HANDLE ImageHandle
  );

//
// BopRemovableDisk.c
//
EFI_STATUS
EFIAPI
InitializeBopRemovableDiskMb3 (
  IN EFI_HANDLE ImageHandle
  );

//
// BopPciLanMb3.c
//
EFI_STATUS
EFIAPI
InitializeBopPciLanMb3 (
  IN EFI_HANDLE ImageHandle
  );

//
// Common.c
//
BOOLEAN
Mb3CompareDeviceRecords (
  IN PMB3_DEVICE_RECORD RecordA,
  IN PMB3_DEVICE_RECORD RecordB
  );

EFI_STATUS
MergeMb3DeviceRecord (
  IN PMB3_DEVICE_RECORD OldRecords,
  IN UINT8 OldRecordsSize,
  IN PMB3_DEVICE_RECORD NewRecords,
  IN UINT8 NewRecordsSize,
  OUT PMB3_DEVICE_RECORD *MergedRecords,
  OUT UINT8 *MergedRecordsSize
  );

EFI_STATUS
Mb3SetRecord (
  IN UINT8 ControllerIndex,
  IN UINT8 SearchNodeIndex,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN OUT PMB3_DEVICE_RECORD Record
  );

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
EFI_STATUS
GetBbsDesc (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PBBS_DEVICE_INFO BbsBcv
  );
#endif

EFI_STATUS
GetUsbMsdDeviceName (
  IN EFI_HANDLE UsbHandle,
  OUT CHAR16 **UsbDeviceName
  );

VOID
DelayForUsb (
  IN UINTN Delay
  );

VOID
BmAsciiStrTrim (
  IN OUT CHAR8 *String,
  IN CHAR8 CharC
  );

BOOLEAN
IsEfiBootableDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

SCT_STATUS
ShadowOproms (
  IN BOOT_MANAGER_CONNECTION_DEVICE *DeviceList
  );

#endif // not defined, _SCT_H_META
