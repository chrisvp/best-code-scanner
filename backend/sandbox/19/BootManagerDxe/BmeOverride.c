//
// FILENAME.
//      BmeOverride.c - Bus Master Enable Override
//
// FUNCTIONAL DESCRIPTION.
//      This file provides an implementation of Bus Master Enable (BME)
//      override that forces BME to be enabled for on board devices (and
//      bridges upstream of on board devices) to enable compatibility
//      with Windows 10 RS2 when BitLocker is enabled.
//
//      This feature requires OEMs to specify which PCIe root bridges
//      correspond to on board devices that must have BME enabled to
//      operate properly in Windows 10 RS2 with BitLocker enabled.  The
//      list of PCIe root bridges MUST be limited to internal PCIe
//      ports that are not easily accessible to end users.  Failure to
//      strictly follow this guidance will open a security vulnerability!
//
// NOTICE.
//      Copyright (C) 2018-2024 Phoenix Technologies.  All Rights Reserved.
//

#include "Meta.h"
#include <Guid/EventGroup.h>

#if (CONFIG_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_PHASE > 0)

typedef struct _BME_OVERRIDE {
  CHAR16 *DevicePathText;
  BOOLEAN Unused;
} BME_OVERRIDE;

#define BME_OVERRIDE_LIST_END NULL

static CHAR16 *mBmeOverrideList [] = { CONFIG_BmeOverrideList };

#if OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID
static UINT32 mBmeOverrideDevices [] = { CONFIG_BmeOverrideDevices };
#endif // OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID

//
// FUNCTION NAME.
//      EnableBmeOnList - Enable BME On Listed Devices.
//
// FUNCTIONAL DESCRIPTION.
//      This function finds all devices to which the specified list applies,
//      and enables BME for those devices.
//
// ENTRY PARAMETERS.
//      Event       - event registered for this event handler.
//      Context     - context for event.
//
// EXIT PARAMETERS.
//      None.
//

static
VOID
EFIAPI
EnableBmeOnList (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  UINTN NumberOfHandles;
  EFI_HANDLE *HandleBuffer = NULL;
  EFI_STATUS Status;
  UINTN HandleIndex;

  //
  // Close the event, as we don't need to do this more than once.
  //

  gBS->CloseEvent (Event);

  //
  // Locate handles for all PCI IO devices.
  //

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer);
  if (EFI_ERROR (Status)) {
    return;
  }

  //
  // Check each PCI IO device interface against the BME override list.
  //

  for (HandleIndex = 0; HandleIndex < NumberOfHandles; HandleIndex ++) {
    UINTN i;
    EFI_DEVICE_PATH_PROTOCOL *DevicePath = NULL, *TargetPath;

    //
    // Locate device path for this PCI device.
    //

    Status = gBS->HandleProtocol (HandleBuffer [HandleIndex], &gEfiDevicePathProtocolGuid, (VOID**)&TargetPath);
    if (EFI_ERROR (Status)) {
      continue;
    }

    //
    // Check target path against each device path in the override list.
    //

    for (i = 0; i < (sizeof (mBmeOverrideList) / sizeof (mBmeOverrideList [0])); i++) {
      UINTN DevicePathLength;

      //
      // Skip NULL entries.
      //

      if (mBmeOverrideList [i] == NULL) {
        continue;
      }

      //
      // Convert as needed.
      //

      DevicePath = ConvertTextToDevicePath (mBmeOverrideList [i]);
      DevicePathLength = 0;
      if (DevicePath != NULL) {
        EFI_DEVICE_PATH_PROTOCOL *TempDevicePath = DevicePath;
        while ((TempDevicePath->Type & END_DEVICE_PATH_TYPE) != END_DEVICE_PATH_TYPE) {
          DevicePathLength += TempDevicePath->Length [0];
          TempDevicePath = (EFI_DEVICE_PATH_PROTOCOL*)((UINTN)TempDevicePath + TempDevicePath->Length [0]);
        }
      }

      //
      // Handle case in which we find a match.
      //

      if (CompareMem (DevicePath, TargetPath, DevicePathLength) == 0) {
        EFI_PCI_IO_PROTOCOL *PciIo;
#if OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID
        UINTN ii;
        UINT32 DevVendorId;
#endif // OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID

        gBS->FreePool (DevicePath);

        //
        // We need the PCI IO protocol in order to set the bus master enable
        // attribute for this device.
        //

        Status = gBS->HandleProtocol (HandleBuffer [HandleIndex], &gEfiPciIoProtocolGuid, (VOID**)&PciIo);
        if (EFI_ERROR (Status)) {
          continue;
        }

#if OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID

        //
        // Only do this for devices with the specified device / vendor ID.
        //

        Status = PciIo->Pci.Read (
                              PciIo,
                              EfiPciIoWidthUint32,
                              0,
                              1,
                              &DevVendorId);
        if (EFI_ERROR (Status)) {
          continue;
        }

        for (ii = 0; ii < (sizeof (mBmeOverrideDevices) / sizeof (mBmeOverrideDevices [0])); ii ++) {
          if (mBmeOverrideDevices [ii] != DevVendorId) {
            continue;
          }
#endif // OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID

          //
          // Set bus master enable.
          //

          PciIo->Attributes (
                   PciIo,
                   EfiPciIoAttributeOperationEnable,
                   EFI_PCI_DEVICE_ENABLE,
                   NULL);
#if OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID
          break;
        }
#endif // OPTION_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_CHECK_DEVID
        break;
      }
      gBS->FreePool (DevicePath);
    }
  }

  //
  // All done with handle buffer.
  //

  if (HandleBuffer != NULL) {
    gBS->FreePool (HandleBuffer);
  }
} // EnableBmeOnList

//
// FUNCTION NAME.
//      BmeOverrideRegisterHandler - Register BME Override Event Handler.
//
// FUNCTIONAL DESCRIPTION.
//      This function creates the appropriate event so that EnableBmeOnList
//      will be called at the correct time during BDS phase (or on exit from
//      BDS phase).
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
BmeOverrideRegisterHandler (VOID)
{
  EFI_EVENT Event;

  //
  // Register ReadyToBoot event to force BME to be enabled for some devices.
  //

#if (CONFIG_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_PHASE == 1)
  EfiCreateEventReadyToBootEx (
    TPL_CALLBACK,
    EnableBmeOnList,
    NULL,
    &Event);
#endif

  //
  // Register Exit Boot Services event to force BME to be enabled for some devices.
  //

#if (CONFIG_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_PHASE == 2)
  gBS->CreateEventEx (
         EVT_NOTIFY_SIGNAL,
         TPL_NOTIFY,
         EnableBmeOnList,
         NULL,
         &gEfiEventExitBootServicesGuid,
         &Event);
#endif
} // BmeOverrideRegisterHandler

#endif // CONFIG_SYSTEM_BOOT_MANAGER_BME_OVERRIDE_PHASE