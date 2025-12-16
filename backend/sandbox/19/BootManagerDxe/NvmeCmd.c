//
// FILENAME.
//      NvmeCmd.c - SecureCore Technology(TM) NVMe Command Function for BootManager Dxe Driver.
//
// FUNCTIONAL DESCRIPTION.
//      This include file contains standard data type definitions for NVMe Command
//      functions for BootManager DXE Driver.
//
// NOTICE.
//      Copyright (C) 2015-2024 Phoenix Technologies.  All Rights Reserved.
//

#include "Meta.h"


//
// FUNCTION NAME.
//      GetNvmePassThruHandleFromThisHandle - Try to get the NVMe controller handle
//                                            from DiskInfo handle.
//
// FUNCTIONAL DESCRIPTION.
//      This function tries to get the NVMe controller handle from DiskInfo handle.
//
// ENTRY PARAMETERS.
//      Handle          - The EFI device handle that contains hdd DiskInfo
//                        protocol.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      NvmePassThruHandleBuffer - a pointer to NVMe controller handle that contains
//                                 EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL protocol.
//

EFI_STATUS
EFIAPI
GetNvmePassThruHandleFromThisHandle (
  IN EFI_HANDLE Handle,
  OUT EFI_HANDLE *NvmePassThruHandleBuffer
  )
{
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DevicePath = DevicePathFromHandle (Handle);

  if (DevicePath == NULL) {
    return EFI_NOT_FOUND;
  }

  *NvmePassThruHandleBuffer = NULL;
  RemainingDevicePath = DevicePath;

  Status = gBS->LocateDevicePath (
                    &gEfiNvmExpressPassThruProtocolGuid,
                    &RemainingDevicePath,
                    NvmePassThruHandleBuffer);

  return Status;
} // GetNvmePassThruHandleFromThisHandle

//
// FUNCTION NAME.
//      GetNvmePassThruInstance - Get the EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL instance.
//
// FUNCTIONAL DESCRIPTION.
//      Get the EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL instance from a specific NVMe
//      controller handle.
//
// ENTRY PARAMETERS.
//      Handle          - The NVMe controller handle.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status code.
//      NvmePassThru    - A pointer to the EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL instance
//                        associated with a NVMe controller.
//

EFI_STATUS
EFIAPI
GetNvmePassThruInstance (
  IN EFI_HANDLE Handle,
  OUT EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL **NvmePassThru
  )
{
  EFI_STATUS Status;

  Status = gBS->HandleProtocol (
                  Handle,
                  &gEfiNvmExpressPassThruProtocolGuid,
                  (VOID**)NvmePassThru);
  if (EFI_ERROR (Status)){
    DEBUG ((EFI_D_ERROR, (CHAR8 *)"Failed to handle gEfiNvmExpressPassThruProtocolGuid. Status: %r\n", Status));
  }

  return Status;
} // GetNvmePassThruInstance

//
// FUNCTION NAME.
//      GetNvmePassThruInfo - Try to get the EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL
//                            from the DiskInfo handle.
//
// FUNCTIONAL DESCRIPTION.
//      This function tries to get the EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL from
//      the DiskInfo handle.
//
// ENTRY PARAMETERS.
//      DiskHandle      - The EFI device handle that contains the hdd DiskInfo
//                        protocol.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status code.
//      NvmePassThru    - A pointer to the controller EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL
//                        protocol instance.
//

EFI_STATUS
EFIAPI
GetNvmePassThruInfo (
  IN EFI_HANDLE DiskHandle,
  OUT EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL **NvmePassThru
  )
{
  EFI_STATUS Status;
  EFI_HANDLE NvmePassThruHandle;

  //
  // Get the NVMe controller handle.
  //

  Status = GetNvmePassThruHandleFromThisHandle (
             DiskHandle,
             &NvmePassThruHandle);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, (CHAR8 *)"Failed to GetNvmePassThruHandleFromThisHandle. Status: %r \n", Status));
    return Status;
  }

  Status = GetNvmePassThruInstance (NvmePassThruHandle, NvmePassThru);
  if (EFI_ERROR (Status)){
    DEBUG ((EFI_D_ERROR, (CHAR8 *)"Failed to GetNvmePassThruInstance. Status: %r \n", Status));
  }

  return Status;
} // GetNvmePassThruInfo

//
// FUNCTION NAME.
//      NvmeIdentifyController - Send "IDENTIFY CONTROLLER (06h)" command to NVMe device.
//
// FUNCTIONAL DESCRIPTION.
//      This function is responsible for sending "IDENTIFY CONTROLLER (06h)" command
//      to NVMe device via EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL.
//
// ENTRY PARAMETERS.
//      DiskHandle      - The EFI device handle that contains the hdd DiskInfo
//                        protocol.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status code.
//      IdentData       - Return 4096 bytes identify data buffer.
//

EFI_STATUS
EFIAPI
NvmeIdentifyController (
  IN EFI_HANDLE DiskHandle,
  OUT NVME_ADMIN_CONTROLLER_DATA *IdentData
  )
{
  EFI_STATUS Status;
  EFI_NVM_EXPRESS_COMMAND Command;
  EFI_NVM_EXPRESS_COMPLETION Response;
  EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL *NvmePassThru;
  EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET CommandPacket;

  Status = GetNvmePassThruInfo (DiskHandle, &NvmePassThru);
  if (EFI_ERROR (Status)){
    DEBUG ((EFI_D_ERROR, (CHAR8 *)"Failed to GetNvmePassThruInfo. Status: %r \n", Status));
    return Status;
  }

  ZeroMem (&CommandPacket, sizeof(EFI_NVM_EXPRESS_PASS_THRU_COMMAND_PACKET));
  ZeroMem (&Command, sizeof(EFI_NVM_EXPRESS_COMMAND));
  ZeroMem (&Response, sizeof(EFI_NVM_EXPRESS_COMPLETION));

  Command.Cdw0.Opcode = NVME_ADMIN_IDENTIFY_CMD;

  //
  // According to Nvm Express 1.1 spec Figure 38, When not used, the field shall be cleared to 0h.
  // For the Identify command, the Namespace Identifier is only used for the Namespace data structure.
  //
  Command.Nsid        = 0;

  CommandPacket.NvmeCmd = &Command;
  CommandPacket.NvmeCompletion = &Response;
  CommandPacket.TransferBuffer = (VOID *)IdentData;
  CommandPacket.TransferLength = sizeof (NVME_ADMIN_CONTROLLER_DATA);
  CommandPacket.CommandTimeout = NVME_GENERIC_TIMEOUT;
  CommandPacket.QueueType = NVME_ADMIN_QUEUE;
  //
  // Set bit 0 (Cns bit) to 1 to identify a controller
  //
  Command.Cdw10 = 1;
  Command.Flags = CDW10_VALID;

  Status = NvmePassThru->PassThru (
                           NvmePassThru,
                           NVME_CONTROLLER_ID,
                           &CommandPacket,
                           NULL
                           );

  return Status;
} // NvmeIdentifyController

