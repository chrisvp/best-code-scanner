//
// FILENAME.
//      Device.c - SecureCore Technology(TM) Device management services.
//
// FUNCTIONAL DESCRIPTION.
//      This module provides device connection and device path services.
//
// NOTICE.
//      Copyright (C) 2013-2025 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

typedef struct {
  UINT8 PI;
  UINT8 SubClassCode;
  UINT8 BaseCode;
} USB_CLASSC, *PUSB_CLASSC;

//
// firmware volume block device path
//   FVB_MEMMAP_DEVICE_PATH
typedef struct {
  MEMMAP_DEVICE_PATH          MemMapDevPath;
  EFI_DEVICE_PATH_PROTOCOL    EndDevPath;
} FV_MEMMAP_DEVICE_PATH;


//
// Private data types used by this module are defined here and any
// static items are declared here.
//

SCT_STATUS
EFIAPI
HddDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

SCT_STATUS
EFIAPI
FvFileDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

SCT_STATUS
EFIAPI
UsbDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

SCT_STATUS
EFIAPI
BootOptionProtocolDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

SCT_STATUS
EFIAPI
HddDevicePathExpansionEx (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

static SCT_DEVICE_PATH_EXPANSION mConverterTable [] = {
  BootOptionProtocolDevicePathExpansion,
  FvFileDevicePathExpansion,
#if OPTION_SUPPORT_BLOCK_IO_DEVICE_PATH_EXPANSION
  HddDevicePathExpansionEx,
#else
  HddDevicePathExpansion,
#endif
  UsbDevicePathExpansion
};

static BOOLEAN mAllPciDeviceStarted = FALSE;

static BOOT_MANAGER_CONNECTION_DEVICE mDeviceConnectList [] = {
  CONFIG_BmDeviceDefaultConnect
};

static UINTN mUsbHcCount = 0;
static PCHAR16 DefaultCdRomStr = L"ATAPI-CDROM";

//
// Prototypes for functions in other modules that are a part of this component.
//


extern
SCT_STATUS
EFIAPI
GetUsbDeviceTypeFromDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PUINT8 DeviceType
  );

extern
SCT_STATUS
IsPciSdCardDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

extern
SCT_STATUS
IsPciEmmcCardDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  );

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
extern
SCT_STATUS
GetBbsEntryByIndex (
  IN UINT16 BbsIndex,
  OUT BBS_TABLE **BbsEntry
  );

extern
EFI_DEVICE_PATH_PROTOCOL *
CreateBbsDevicePath (
  IN UINT16 DeviceType,
  IN UINT16 StatusFlag,
  IN CHAR16 *DescriptionString
  );

extern
SCT_STATUS
GetBbsTableDevicePathByIndex (
  IN UINT16 BbsIndex,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath
  );

#endif

extern
BOOLEAN
EFIAPI
LegacyBootEnabled (OUT PBOOLEAN LegacyBeforeUefi OPTIONAL);

//
// Data shared with other modules *within* this component.
//

SCT_HDD_PWD_PROTOCOL * HddPwd = NULL;
EFI_HANDLE *mContextOverrideDriver = NULL;  // Driver Image Handles Context Override.
SCT_FIRMWAREVOLUME_LOADER_PROTOCOL *mFirmwareVolumeLoader = NULL;

//
// Data defined in other modules and used by this module.
//

extern EFI_HANDLE mFvHandle;
extern DRIVER_OBJECT mBootManager;
extern EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *mTextInEx;
extern BOOLEAN LegacyDevicesConnected;

BOOLEAN mUnlockHddPrompt = FALSE;

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

BOOLEAN
EFIAPI
IsChildHandle (
  IN EFI_HANDLE ParentHandle,
  IN EFI_HANDLE ChildHandle
  );

//
// Public API functions implemented by this component.
//

SCT_STATUS
EFIAPI
ConnectDevices (IN PBOOT_MANAGER_CONNECTION_DEVICE  DeviceList);

VOID
EFIAPI
ToggleHddUnlockPromptState (IN BOOLEAN Enabled);

VOID
EFIAPI
UnlockAllHdd (VOID);

SCT_STATUS
EFIAPI
ConnectAllPciDevices (VOID);

SCT_STATUS
EFIAPI
GetUsbHcProperStallTime (OUT PUINT16 Milliseconds);

SCT_STATUS
EFIAPI
PrepareContextOverrideDriverForEssential (VOID);

EFI_STATUS
EFIAPI
GetPciDeviceClassCode (
  IN EFI_HANDLE *PciHandle,
  OUT UINT8 *ClassCode,
  OUT UINT8 *SubClassCode
  );

BOOLEAN
IsFvFileExist (
  IN EFI_HANDLE FvHandle,
  IN EFI_GUID *FileName
  );

EFI_STATUS
FindOptionalFvHandle (
  IN EFI_GUID *FileName,
  OUT EFI_HANDLE *TargetHandle
  );

EFI_STATUS
DecompressOptionalFirmwareVolume (IN UINTN Type);

EFI_STATUS
EFIAPI
GetUsbMsdDeviceName (
  IN EFI_HANDLE UsbHandle,
  OUT CHAR16 **UsbDeviceName
  );

BOOLEAN
EFIAPI
IsPciRootDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN EFI_HANDLE DeviceHandle
  );


//
// FUNCTION NAME.
//      UnicodeToAscii - Convert a Unicode String to an Ascii String.
//
// FUNCTIONAL DESCRIPTION.
//      This function truncates each Unicode character to produce the Ascii
//      character.
//
//      This function stops when a UNICODE NULL is reached.
//
// ENTRY PARAMETERS.
//      UnicodeString   - a pointer to the Unicode string to convert.
//      AsciiString     - a pointer to the data buffer where the Ascii String
//                        should be written.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
UnicodeToAscii (
  IN PCHAR16 UnicodeString,
  OUT PCHAR8 AsciiString
  )
{
  PCHAR16 p;
  PCHAR8 q;

  DPRINTF_DEV ("UnicodeToAscii:\n");

  p = UnicodeString;
  q = AsciiString;
  while (TRUE) {

    //
    // Always copy, even the NULL.
    // NEWREL: cu 09/11/13, this would be a nice place to do more data
    // checking to handle unicode characters that are out of the ASCII range
    // gracefully.
    //

    *q = (CHAR8)*p;

    //
    // Check for ending condition, NULL terminated string.
    //

    if (*p == L'\0') {
      return SCT_STATUS_SUCCESS;
    }

    //
    // Advance to the next character.
    //

    p++;
    q++;
  }
} // UnicodeToAscii


//
// FUNCTION NAME.
//      CreateBbsDevicePath - Create A BBS Device Path.
//
// FUNCTIONAL DESCRIPTION.
//      This function creates the BBS Device Node based on the parameters.
//      The BBS node is then appended with an end node. The resulting Device
//      Path is returned.
//
// ENTRY PARAMETERS.
//      DeviceType      - the Value to use in the DeviceType field of the BBS
//                        Device Node.
//      StatusFlags     - the Value to use in the StatusFlags field of the BBS
//                        Device Node.
//      DescriptionString - a pointer to a CHAR16 string that must be converted
//                          to an ASCIIZ string. The BBS Device Node Field
//                          Description String must point to the ASCIIZ string.
//
// EXIT PARAMETERS.
//      Function Return - the address of the new device path.
//

EFI_DEVICE_PATH_PROTOCOL *
CreateBbsDevicePath (
  IN UINT16 DeviceType,
  IN UINT16 StatusFlag,
  IN CHAR16 *DescriptionString
  )
{
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *rDp;        // return device path.
  BBS_BBS_DEVICE_PATH *BbsNode;
  EFI_DEVICE_PATH_PROTOCOL *EndNode;
  UINTN SizeOfBbsNode;

  DPRINTF_DEV ("CreateBbsDevicePath:%s.\n", DescriptionString);

  SizeOfBbsNode = sizeof (BBS_BBS_DEVICE_PATH) + StrLen (DescriptionString);
  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  SizeOfBbsNode + sizeof (EFI_DEVICE_PATH_PROTOCOL),
                  (VOID **) &rDp);
  if (EFI_ERROR (Status)) {
    return NULL;
  }
  DPRINTF_DEV (
    "  0x%x bytes @ 0x%x:\n",
    SizeOfBbsNode + sizeof (EFI_DEVICE_PATH_PROTOCOL),
    rDp);

  //
  // Fill in the BBS Node fields.
  //

  BbsNode = (BBS_BBS_DEVICE_PATH *)rDp;
  BbsNode->Header.Type = BBS_DEVICE_PATH;
  BbsNode->Header.SubType = BBS_BBS_DP;
  SetDevicePathNodeLength (&(BbsNode->Header), (UINT16)SizeOfBbsNode);
  BbsNode->DeviceType = DeviceType;
  BbsNode->StatusFlag = StatusFlag;
  UnicodeToAscii (DescriptionString, (PCHAR8)&(BbsNode->String));

  //
  // Fill in the End Node fields.
  //

  EndNode = (EFI_DEVICE_PATH_PROTOCOL *)(((UINTN)rDp) + SizeOfBbsNode);
  SetDevicePathEndNode (EndNode);

  DEBUG_DEV ({
    CHAR16 *Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (rDp, FALSE, TRUE);
    DPRINTF_DEV ("  %s\n", Str);
    SafeFreePool (Str);
  });

  return rDp;
} // CreateBbsDevicePath


//
// FUNCTION NAME.
//      InitializeDevice - Initialize Device Module.
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
InitializeDevice (VOID)
{
  SCT_STATUS Status;

  DPRINTF_INIT ("InitializeDevice:\n");

  Status = InitializeBopIsaFdd ();
  DPRINTF_INIT ("  InitializeBopIsaFdd returned %r\n", Status);

  Status = InitializeBopAtaHdd ();
  DPRINTF_INIT ("  InitializeBopAtaHdd returned %r\n", Status);

  Status = InitializeBopAtapiCd ();
  DPRINTF_INIT ("  InitializeBopAtapiCd returned %r\n", Status);

  Status = InitializeBopPciLan ();
  DPRINTF_INIT ("  InitializeBopPciLan returned %r\n", Status);

  Status = InitializeBopUsbLan ();
  DPRINTF_INIT ("  InitializeBopUsbLan returned %r\n", Status);

  Status = InitializeBopUsbCd ();
  DPRINTF_INIT ("  InitializeBopUsbCd returned %r\n", Status);

  Status = InitializeBopUsbFdd ();
  DPRINTF_INIT ("  InitializeBopUsbFdd returned %r\n", Status);

  Status = InitializeBopUsbHdd ();
  DPRINTF_INIT ("  InitializeBopUsbHdd returned %r\n", Status);

  Status = InitializeBopCd ();
  DPRINTF_INIT ("  InitializeBopCd returned %r\n", Status);

  Status = InitializeBopExecOprom ();
  DPRINTF_INIT ("  InitializeBopExecOprom returned %r\n", Status);

#if OPTION_SYSTEM_BOOT_MANAGER_BOP_LEGACY_BEV
  Status = InitializeBopLegacyBev ();
  DPRINTF_INIT ("  InitializeBopLegacyBev returned %r\n", Status);
#endif //OPTION_SYSTEM_BOOT_MANAGER_BOP_LEGACY_BEV

  Status = InitializeBopSdCard ();
  DPRINTF_INIT ("  InitializeBopSdCard returned %r\n", Status);

  Status = InitializeBopEmmcCard ();
  DPRINTF_INIT ("  InitializeBopEmmcCard returned %r\n", Status);

  Status = InitializeBopNvme ();
  DPRINTF_INIT ("  InitializeBopNvme returned %r\n", Status);

  Status = InitializeBopUfs ();
  DPRINTF_INIT ("  InitializeBopUfs returned %r\n", Status);

  Status = InitializeBopHttpBoot ();
  DPRINTF_INIT ("  InitializeBopHttpBoot returned %r\n", Status);

  Status = InitializeBopFixedDisk ();
  DPRINTF_INIT ("  InitializeBopFixedDisk returned %r\n", Status);

  if (HddPwd == NULL) {
    Status = gBS->LocateProtocol (&gSctHddPwdProtocolGuid, NULL, (VOID **) &HddPwd);
    DPRINTF_INIT ("  LocateProtocol for SctHddPwdProtocol returned %r\n", Status);
    if (EFI_ERROR (Status)) {
      HddPwd = NULL;
    }
  }

  return SCT_STATUS_SUCCESS;
} // InitializeDevice


//
// FUNCTION NAME.
//      ConnectAllHandlesExceptPciVga - Connect all handles except PCI VGA handles.
//
// FUNCTIONAL DESCRIPTION.
//      This function will call gBS->ConnectController for each handle excpet PCI VGA.
//      Once all handles have been connected this function will call
//      gDS->Dispatch.
//      This function will call gBS->ConnectController for each handle again
//      until gDS->Dispatch fails to dispatch any additional drivers.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
ConnectAllHandlesExceptPciVga (VOID)
{
  UINTN i;
  PCI_TYPE00 Pci;
  EFI_STATUS Status;
  EFI_STATUS DispatchStatus = EFI_SUCCESS;
  BOOLEAN Recursive;
  EFI_PCI_IO_PROTOCOL *PciIo;
  UINTN NumberOfHandles;
  EFI_HANDLE *HandleBuffer;

  DPRINTF_DEV ("ConnectAllHandlesExceptPciVga:\n");

  do {

    //
    // Get an array of all the handles in the database.
    //

    Status = gBS->LocateHandleBuffer (
                    AllHandles,
                    NULL,
                    NULL,
                    &NumberOfHandles,
                    &HandleBuffer);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    DPRINTF_DEV ("  Connecting 0x%x handles.\n", NumberOfHandles);

    //
    // Connect each controller in the array of controllers.
    //

    for (i = 0; i < NumberOfHandles; i++) {


      Status = gBS->OpenProtocol (
                      HandleBuffer [i],
                      &gEfiPciRootBridgeIoProtocolGuid,
                      NULL,
                      mImageHandle,
                      NULL,
                      EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

      DPRINTF_DEV (" Pci Root Bridge test %r\n", Status);
      Recursive = (EFI_ERROR (Status)) ? TRUE : FALSE;
      PciIo = NULL;
      Status = gBS->HandleProtocol (
                      HandleBuffer [i],
                      &gEfiPciIoProtocolGuid,
                      (VOID **)&PciIo);

      if (!EFI_ERROR (Status)) {
        Status = PciIo->Pci.Read (
                              PciIo,
                              EfiPciIoWidthUint32,
                              0,
                              sizeof (Pci) / sizeof (UINT32),
                              &Pci);

        //
        // Skip VGA Devices.
        //

        if (!EFI_ERROR (Status) && (IS_PCI_VGA (&Pci) || IS_PCI_OLD_VGA (&Pci) || IS_PCI_GFX (&Pci))) {
          DPRINTF_DEV ("  Pci VGA devices .. skip\n");
          continue;
        }
      }

#if OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME

      Status = FindDeviceHandleNode (HandleBuffer [i], Recursive);
      DPRINTF_DEV ("FindDeviceHandleNode Status=%r, Number is 0x%x\n", Status, i);

      if (Status == EFI_SUCCESS) {
        DPRINTF_DEV ("Duplicate a device path.\n");
        continue;
      }
      DEBUG_DEV ({
        EFI_DEVICE_PATH_PROTOCOL *DevicePath;
        CHAR16 *Str = NULL;
        DevicePath = DevicePathFromHandle (HandleBuffer [i]);
        Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
        DPRINTF_DEV ("DevicePath:%s.\n", Str);
        SafeFreePool (Str);
      });

#endif // OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME

      Status = gBS->ConnectController (
                      HandleBuffer [i],
                      mContextOverrideDriver,
                      NULL,
                      Recursive);

#if OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME
      if (Status == EFI_SUCCESS) {
        Status = AddDeviceHandleNode (HandleBuffer [i], Recursive);
        DPRINTF_DEV ("AddDeviceHandleNode Status=%r.\n", Status);
      }
#endif // OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME

      CHECK_HOTKEYS_ABORT (mTextInEx);

      //
      // Update progress by percentage. Leave one for the calling function.
      //

      UpdateProgress (BOOT_MANAGER_PHASE_CONNECTION, i, NumberOfHandles, NULL);

    }

    //
    // Free the array of handles.
    //

    SafeFreePool (HandleBuffer);

#if !OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME
    if (!LegacyDevicesConnected && LegacyBootEnabled (NULL)) {
      DPRINTF_LEGACY ("Legacy NOT Initialized && Legacy Boot is Enabled.\n");

      //
      // Connect the devices needed for legacy boot.
      //
      Status = ConnectDevices (LegacyConnectList);
      if (EFI_ERROR (Status)) {
        DPRINTF_LEGACY ("  There was a problem connecting LegacyConnectList, %r.\n", Status);
        return Status;
      }

      LegacyDevicesConnected = TRUE;

    } // if (LegacyBootEnabled (NULL))
#endif // !OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME

    //
    // Dispatch any drivers whose dependency expressions are now met.
    // A failure to dispatch indicates that have successfully connected all
    // controllers, so return success.
    //

    DPRINTF_DEV ("ConnectAllHandlesExceptPciVga.gDS->Dispatch\n");
    DispatchStatus = BmDispatch (FALSE);
    CHECK_HOTKEYS_ABORT (mTextInEx);
    DPRINTF_DEV ("ConnectAllHandlesExceptPciVga.gDS->Dispatch returned [%r].\n", DispatchStatus);
    if (EFI_ERROR (DispatchStatus)) {
      return SCT_STATUS_SUCCESS;
    }
  } while (DispatchStatus == EFI_SUCCESS);
  return SCT_STATUS_SUCCESS;
} // ConnectAllHandlesExceptPciVga

//
// FUNCTION NAME.
//      ConnectDevices - Connect the device paths specified.
//
// FUNCTIONAL DESCRIPTION.
//      This function will connect each device path in the list.
//
// ENTRY PARAMETERS.
//      DeviceList      - Array of BOOT_MANAGER_CONNECTION_DEVICE objects.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConnectDevices (IN PBOOT_MANAGER_CONNECTION_DEVICE DeviceList)
{
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  EFI_HANDLE Handle;
  PBOOT_MANAGER_CONNECTION_DEVICE p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  DPRINTF_DEV ("ConnectDevices:\n");

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
      DPRINTF_DEV (
        "  Failed to convert %s to a device path.\n",
        p->TextDevicePath);
      p++;
      continue;
    }

    //
    // Increment the progress indicators by 1/10 of the connection phase.
    // This is a guess to provide good looking motion. Most connection lists
    // have less than 10 device paths. Some have a few more.
    //

    UpdateProgress (
      BOOT_MANAGER_PHASE_CONNECTION,
      (CONFIG_SYSTEM_BOOT_MANAGER_PHASE_CONNECTION_END
      - CONFIG_SYSTEM_BOOT_MANAGER_PHASE_CONNECTION_START)
      / 10,
      0,        // Indicate that this is an incremental not percentage update.
      NULL);

    //
    // Get the device path of parent controller, figure out the VGA devices.
    //

    if (IsVgaDevices (DevicePath, NULL)) {
      DPRINTF_CON ("  \nPCI VGA Device Found!! Skip it.\n");
      p++;
      continue;

    } // if (IsVgaDevices (DevicePath, NULL)) {


    Status = ConnectDevicePathWithRecurse (
               DevicePath,
               &Handle,
               p->Recursive);
    DPRINTF_DEV ("  ConnectDevicePathWithRecurse returned %r.\n", Status);
    p++;
    SafeFreePool (DevicePath);
  }

  DPRINTF_DEV ("ConnectDevices End.\n");
  return SCT_STATUS_SUCCESS;
} // ConnectDevices


//
// FUNCTION NAME.
//      CreateFileDevicePath - Create a device path from a file guid.
//
// FUNCTIONAL DESCRIPTION.
//      Construct a device path which consists of the device path of the
//      Fv plus the device path of the file name (a guid).
//
// ENTRY PARAMETERS.
//      FvHandle        - the handle of the Fv in which the file is located.
//      FileGuid        - Pointer to the FILE_GUID to convert.
//
// EXIT PARAMETERS.
//      Function Return - pointer to the device path.
//

EFI_DEVICE_PATH_PROTOCOL *
CreateFileDevicePath (
  IN EFI_HANDLE FvHandle,
  IN EFI_GUID *FileGuid
  )
{
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH FileNode;

  DPRINTF_DEV ("CreateFileDevicePath: FvHandle = 0x%x, FileGuid = %g\n",
    FvHandle, FileGuid);

  //
  // Start with the device path of the FV.
  //

  DevicePath = DevicePathFromHandle (FvHandle);
  DEBUG_DEV ({
    CHAR16 *Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_DEV ("  DevicePath:%s.\n", Str);
    SafeFreePool (Str);
  });

  //
  // Create the device path node for this file.
  //

  EfiInitializeFwVolDevicepathNode (&FileNode, FileGuid);
  DEBUG_DEV ({
    CHAR16 *Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT ((EFI_DEVICE_PATH_PROTOCOL *)&FileNode, FALSE, TRUE);
    DPRINTF_DEV ("  FileNode:%s.\n", Str);
    SafeFreePool (Str);
  });

  //
  // Append the file node to the FV device path.
  //

  DevicePath = AppendDevicePathNode (DevicePath, (EFI_DEVICE_PATH_PROTOCOL *)&FileNode);
  DEBUG_DEV ({
    CHAR16 *Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_DEV ("  DevicePath:%s.\n", Str);
    SafeFreePool (Str);
  });

  return DevicePath;
} // CreateFileDevicePath


//
// FUNCTION NAME.
//      FindDeviceChildren - Find the Device Path Children of a Handle.
//
// FUNCTIONAL DESCRIPTION.
//      This function finds the handles whose device paths are an extension
//      of the device path attached to this handle.
//
// ENTRY PARAMETERS.
//      Handle          - EFI Handle referencing the device path parent.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      NumberOfHandles - the number of children handles.
//      ChildHandleBuffer - the address of an array of children handles.
//

SCT_STATUS
EFIAPI
FindDeviceChildren (
  IN EFI_HANDLE     Handle,
  OUT PUINTN        NumberOfHandles,
  OUT EFI_HANDLE    **ChildHandleBuffer
  )
{
  SCT_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  UINTN HandleCount;
  UINTN i, j;

  DPRINTF_DEV ("FindDeviceChildren: Handle 0x%x.\n", Handle);

  if ((ChildHandleBuffer == NULL) || (NumberOfHandles == NULL)) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  *NumberOfHandles = 0;
  *ChildHandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDevicePathProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (i = 0, j = 0; i < HandleCount; i++) {
    if (IsChildHandle (Handle, HandleBuffer [i])) {
      HandleBuffer [j] = HandleBuffer [i];
      j++;
    }
  }

  if (j > 0) {
    *NumberOfHandles = j;
    *ChildHandleBuffer = AllocateCopyPool (j * sizeof (EFI_HANDLE), HandleBuffer);
    SafeFreePool (HandleBuffer);
  }

  DEBUG_DEV ({
    DPRINTF_DEV ("  0x%x Child Handles of Handle 0x%x are @ 0x%x:\n",
      *NumberOfHandles, Handle, *ChildHandleBuffer);
    for (i = 0; i < *NumberOfHandles; i++) {
      DPRINTF_DEV ("    0x%x.\n", (*ChildHandleBuffer) [i]);
    }
  });

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // FindDeviceChildren


//
// FUNCTION NAME.
//      ExpandDevicePath - Expand a device path back to the root.
//
// FUNCTIONAL DESCRIPTION.
//      In the UEFI Specification, Version 2.3, Section 3.1.2 Load Option
//      Processing, Paragraphs 4 and 5, the concept of expandable nodes is
//      presented. USB nodes for WWID and for Class and HDD nodes for partition
//      types GPT and MBR.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path to expand.
//
// EXIT PARAMETERS.
//      ExpandedDevicePaths - the address of a pointer to the expanded device
//                            path array.
//      NumberOfDevicePaths - the number of device paths in the array pointed
//                            to by the pointer whose address is
//                            ExpandedDevicePaths.
//      Function Return - the expanded device path or a copy of DevicePath.
//

SCT_STATUS
EFIAPI
ExpandDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  )
{

  UINTN i;
  SCT_STATUS Status;

  DPRINTF_DEV ("ExpandDevicePath @ 0x%x.\n", DevicePath);

  DEBUG_DEV ({
    CHAR16 *Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_DEV ("  %s.\n", Str);
    SafeFreePool (Str);
  });

  //
  // Try each converter. The first to return SCT_STATUS_SUCCESS handled this
  // device path.
  //

  for (i = 0; i < (sizeof (mConverterTable) / sizeof (SCT_DEVICE_PATH_EXPANSION)); i++) {
    Status = mConverterTable [i] (DevicePath, ExpandedDevicePaths, NumberDevicePaths);
    DPRINTF_DEV ("mConverterTable[%d], St:%r\n", i, Status);

    if (!EFI_ERROR (Status)) {
      DPRINTF_DEV ("ExpandDevicePath:Device Path Expansion:\n");
      DISPLAY_DEVICE_PATH_ARRAY (*ExpandedDevicePaths, *NumberDevicePaths, L"  ");
      return Status;
    }
  }

  DPRINTF_DEV ("ExpandDevicePath:No Device Path Expansion.\n");
  return SCT_STATUS_NOT_FOUND;
} // ExpandDevicePath


//
// FUNCTION NAME.
//      ExpandOneDevicePath - Expand the device path exactly once.
//
// FUNCTIONAL DESCRIPTION.
//      This function will expand the device path once. If the device path does
//      not expand this function will return a copy of DevicePath.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path to expand.
//
// EXIT PARAMETERS.
//      Function Return - the expanded device path or a copy of DevicePath.
//

EFI_DEVICE_PATH_PROTOCOL *
EFIAPI
ExpandOneDevicePath (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *ExpandedDevicePaths;
  UINTN NumberOfDevicePaths;

  DPRINTF_DEV ("ExpandOneDevicePath:\n");

  Status = ExpandDevicePath (
             DevicePath,
             &ExpandedDevicePaths,
             &NumberOfDevicePaths);

  DPRINTF_DEV (
    "  ExpandDevicePath returned %r, NumberOfDevicePaths = 0%d.\n",
    Status,
    NumberOfDevicePaths);

  if (EFI_ERROR (Status)) {
    return DuplicateDevicePath (DevicePath);
  }

  return ExpandedDevicePaths;
} // ExpandOneDevicePath



//
// FUNCTION NAME.
//      IsChildHandle - Is the second handle a device child of the first.
//
// FUNCTIONAL DESCRIPTION.
//      This function determines if the second handle is a child of the first
//      in the device path sense of child.
//
// ENTRY PARAMETERS.
//      ParentHandle    - EFI Handle that may be the parent.
//      ChildHandle     - EFI Handle that may be the child.
//
// EXIT PARAMETERS.
//      Function Return - true if ChildHandle is a child of ParentHandle,
//                         otherwise false.
//

BOOLEAN
EFIAPI
IsChildHandle (
  IN EFI_HANDLE ParentHandle,
  IN EFI_HANDLE ChildHandle
  )
{
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *ParentPath, *ChildPath;

  DPRINTF_DEV_CHILD ("IsChildHandle: Parent 0x%x, Child 0x%x.\n",
    ParentHandle, ChildHandle);

  ParentPath = NULL;
  ChildPath = NULL;

  Status = gBS->HandleProtocol (
                  ParentHandle,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **) &ParentPath);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = gBS->HandleProtocol (
                  ChildHandle,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **) &ChildPath);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  return IsChildPath (ParentPath, ChildPath);
} // IsChildHandle


//
// FUNCTION NAME.
//      HddSearchForNode - Search all the device paths for a node.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches all the device paths in the system for one which
//      ends with the first node in DevicePath and appends the remaining nodes
//      to the found path, returning this result.
//
//      This function implements searches for HDD nodes. The first node in
//      DevicePath must be a HDD node.
//
// ENTRY PARAMETERS.
//      DevicePath      - a pointer to the device path whose first node must
//                        match. The rest of the device path will be appended
//                        to the matching path.
//
// EXIT PARAMETERS.
//      Function Return - a pointer to the first matching device path with the
//                        remain path appended.
//

EFI_DEVICE_PATH_PROTOCOL *
HddSearchForNode (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  UINTN i;
  SCT_STATUS Status;
  HARDDRIVE_DEVICE_PATH *SearchNode;    // cast DevicePath to HDD Device Path.

  UINTN DevicePathHandleCount;          // the number of Device Paths in the buffer.
  EFI_HANDLE *DevicePathHandleBuffer;   // the buffer of Device Paths.
  EFI_DEVICE_PATH_PROTOCOL *ReturnPath;

  EFI_DEVICE_PATH_PROTOCOL *p;          // temp pointer. Used to walk "this" device path.
  EFI_DEVICE_PATH_PROTOCOL *dp;         // pointer to the start of "this" device path.
  HARDDRIVE_DEVICE_PATH *HddDeviceNode; // pointer to the Hdd Node in "this" device path.

  DPRINTF_DEV ("HddSearchForNode:\n");

  //
  // This function is for HDD expansion only. Return NULL if the search path is
  // not a HDD path.
  //

  if (!IsDeviceNodeHdd (DevicePath)) {
    DPRINTF_DEV ("  The search path does not begin with a HDD node.\n");
    return NULL;
  }
  SearchNode = (HARDDRIVE_DEVICE_PATH *)(DevicePath);

  //
  // NEWREL: cu 09/09/21, It would be nice to allow the no-signature signature
  // type function as wild card. This function would have to search any HDD
  // devices found to match the nodes that follow the HDD node in the search
  // path to the file system on the discovered HDD. This feature is not defined
  // in the specification and could have unwanted side effects. For now we do
  // not support the case, so return immediately.
  //

  if (SearchNode->SignatureType == 0) {
    DPRINTF_DEV (
      "  The search path contains an unsupported SignatureType = 0x%x.\n",
      SearchNode->SignatureType);
    return NULL;
  }

  //
  // Search all device paths for a device path that matches our SearchNode.
  //

  DevicePathHandleCount = 0;
  DevicePathHandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDevicePathProtocolGuid,
                  NULL,
                  &DevicePathHandleCount,
                  &DevicePathHandleBuffer);
  if (EFI_ERROR (Status) || DevicePathHandleCount == 0) {
    return NULL;
  }

  ReturnPath = NULL;
  for (i = 0 ; i < DevicePathHandleCount; i++ ) {
    Status = gBS->OpenProtocol(
                      DevicePathHandleBuffer [i],
                      &gEfiDevicePathProtocolGuid,
                      (VOID **) &dp,
                      mImageHandle,
                      NULL,
                      EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status) || dp == NULL) {
      DPRINTF_DEV ("  0x%x Error opening protocol, returned %r\n",
                  DevicePathHandleBuffer [i],
                  Status);
      continue;
    }

    //
    // Get the last node before the end node.
    //

    HddDeviceNode = (HARDDRIVE_DEVICE_PATH *)(GetLastDeviceNode (dp));
    if (HddDeviceNode == NULL) {
      continue;
    }

    //
    // If the last (Non-ending) node is not a Hdd Device Node then this is not
    // the device path we are looking for. Process the next device path.
    //

    if (!IsDeviceNodeHdd (HddDeviceNode)) {
      continue;
    }
    DPRINTF_DEV ("  Found a HddNode in Device Path");
    DEBUG_DEV ({
      PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (dp, FALSE, TRUE);
      DPRINTF_DEV (" %s.\n", Str);
      SafeFreePool (Str);
    });

    //
    // Compare the device node we found, HddDeviceNode, to the device node we
    // seek, SearchNode. First match the MBRType and SignatureType.
    //

    if ((HddDeviceNode->MBRType != SearchNode->MBRType) ||
        (HddDeviceNode->SignatureType != SearchNode->SignatureType)) {
      DPRINTF_DEV ("  MBRType or SignatureType didn't match.\n");
      continue;
    }

    //
    // Compare the Signature.
    //

    if (CompareMem (
          HddDeviceNode->Signature,
          SearchNode->Signature,
          sizeof (SearchNode->Signature)) != 0) {
      DPRINTF_DEV ("  Signature didn't match.\n");
      continue;
    }

    //
    // This is the matching case. Create a new device path like this:
    // mNode(0)/.../mNode(n)/MatchingNode/EndNode
    //                       SearchNode/sNode(1)/.../sNode(m)/EndNode
    // mNode(0)/.../mNode(n)/MatchingNode/sNode(1)/.../sNode(m)/EndNode
    // dp already points to mNode(0).
    //

    p = NextDevicePathNode (DevicePath); // p points to sNode(1).
    ReturnPath = AppendDevicePath (dp, p);
    DEBUG_DEV ({
      if (ReturnPath == NULL) {
        DPRINTF_DEV ("  Found a match, but failed to append to it.\n");
      }
    });
    break;
  }

  SafeFreePool (DevicePathHandleBuffer);
  return ReturnPath;
} // HddSearchForNode


//
// FUNCTION NAME.
//      HddDevicePathExpansion - Find a HDD that matches the search node.
//
// FUNCTIONAL DESCRIPTION.
//      This function connect the HddExpansionConnectList.
//      After each connection this function calls HddSearchForNode to search
//      all device paths for the HDD node being expanded.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - an SCT_STATUS code.
//

SCT_STATUS
EFIAPI
HddDevicePathExpansion (
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL  **ExpandedDevicePaths,
  OUT UINTN                     *NumberDevicePaths
  )
#ifndef CONFIG_BmHddExpansionConnectList
{
  EFI_STATUS Status;

  DPRINTF_DEV ("Entry:\n");

  //
  // check FIRST DeviceNode of input DevicePath is HD(...)
  //
  DPRINTF_DEV ("First DeviceNode->Type    = [0x%x]\n", DevicePathType (DevicePath));
  DPRINTF_DEV ("First DeviceNode->SubType = [0x%x]\n", DevicePathSubType(DevicePath));
  if (!IsDeviceNodeHdd (DevicePath)) {
    DPRINTF_DEV ("FIRST DeviceNode Not a HD(...) search path.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  DPRINTF_DEVICE_PATH ("DevicePath = ", DevicePath);

  //
  // Before ConnectController, unlock all HDDs first, hence the file system can
  // be installed.
  //

  ToggleHddUnlockPromptState (TRUE);
  UnlockAllHdd ();

  *NumberDevicePaths = 0;

  //
  // Check all handles after each connect to avoid extra connect events.
  // Exit with success at the first match found.
  //
  *ExpandedDevicePaths = HddSearchForNode (DevicePath);
  if (*ExpandedDevicePaths != NULL) {
    *NumberDevicePaths = 1;
  }
  ToggleHddUnlockPromptState (FALSE);

  DPRINTF_DEV("NumberDevicePaths = [%d]\n", *NumberDevicePaths);
  if (*NumberDevicePaths == 0) {
    DPRINTF_DEV ("Could not find a matching HDD path.\n");
    Status = SCT_STATUS_NOT_FOUND;
  } else {
    DPRINTF_DEVICE_PATH ("ExpandedDevicePaths = ", *ExpandedDevicePaths);
    Status = SCT_STATUS_SUCCESS;
  }
  DPRINTF_DEV ("Returne [%r]\n", Status);
  return Status;
} // HddDevicePathExpansion

#else // CONFIG_BmHddExpansionConnectList

{
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  EFI_HANDLE Handle;
  PBOOT_MANAGER_CONNECTION_DEVICE p;
  EFI_DEVICE_PATH_PROTOCOL *ParentDevicePath;

  BOOT_MANAGER_CONNECTION_DEVICE HddExpansionConnectList [] = {
    CONFIG_BmHddExpansionConnectList,
    BOOT_MANAGER_CONNECTION_DEVICE_LIST_END
  };

  DPRINTF_DEV ("HddDevicePathExpansion:\n");

  DEBUG_DEV ({
    PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_DEV ("  Expand %s.\n", Str);
    SafeFreePool (Str);
  });

  if (!IsDeviceNodeHdd (DevicePath)) {
    DPRINTF_DEV ("  Not a HDD search path.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  //
  // Before ConnectController, unlock all HDDs first, hence the file system can
  // be installed.
  //

  ToggleHddUnlockPromptState (TRUE);
  UnlockAllHdd ();

  p = HddExpansionConnectList;
  while (TRUE) {
    if (p->TextDevicePath == NULL) {
      break;
    }

    ParentDevicePath = NULL;
    ParentDevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (ParentDevicePath == NULL) {
      DPRINTF_DEV (
        "  Failed to convert %s to a device path.\n",
        p->TextDevicePath);
      p++;
      continue;
    }

    Status = ConnectDevicePathWithRecurse (
               ParentDevicePath,
               &Handle,
               p->Recursive);
    DPRINTF_DEV (
      "  ConnectDevicePathWithRecurse (%s) returned %r.\n",
      p->TextDevicePath,
      Status);
    SafeFreePool (ParentDevicePath);
    if (EFI_ERROR (Status)) {
      p++;
      continue;
    }

    //
    // Check all handles after each connect to avoid extra connect events.
    // Exit with success at the first match found.
    //

    *ExpandedDevicePaths = HddSearchForNode (DevicePath);
    if (*ExpandedDevicePaths != NULL) {
      *NumberDevicePaths = 1;
      ToggleHddUnlockPromptState (FALSE);
      Status = SCT_STATUS_SUCCESS;
      return Status;
    }

    p++;
  }

  ToggleHddUnlockPromptState (FALSE);
  DPRINTF_DEV ("  Could not find a matching HDD path.\n");
  Status = SCT_STATUS_NOT_FOUND;
  return Status;
} // HddDevicePathExpansion
#endif // CONFIG_BmHddExpansionConnectList

//
// FUNCTION NAME.
//      HddDevicePathExpansionEx - Enhanced HddDevicePathExpansion.
//
// FUNCTIONAL DESCRIPTION.
//
//      This function will *ONLY* connect those devices that belong to HDD type
//      recursively.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - an SCT_STATUS code.
//

SCT_STATUS
EFIAPI
HddDevicePathExpansionEx (
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL  **ExpandedDevicePaths,
  OUT UINTN                     *NumberDevicePaths
  )
#ifndef CONFIG_BmHddExpansionConnectList
{
  SCT_STATUS Status;

  DPRINTF_DEV ("Entry:\n");

  //
  // check FIRST DeviceNode of input DevicePath is HD(...)
  //
  DPRINTF_DEV ("First DeviceNode->Type    = [0x%x]\n", DevicePathType (DevicePath));
  DPRINTF_DEV ("First DeviceNode->SubType = [0x%x]\n", DevicePathSubType(DevicePath));
  if (!IsDeviceNodeHdd (DevicePath)) {
    DPRINTF_DEV ("  Not a HDD search path.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  DPRINTF_DEVICE_PATH ("  Expand ", DevicePath);

  //
  // Before ConnectController, unlock all HDDs first, hence the file system can
  // be installed.
  //

  ToggleHddUnlockPromptState (TRUE);
  UnlockAllHdd ();

  *NumberDevicePaths = 0;

  //
  // Check all handles after each connect to avoid extra connect events.
  // Exit with success at the first match found.
  //
  *ExpandedDevicePaths = HddSearchForNode (DevicePath);
  if (*ExpandedDevicePaths != NULL) {
    *NumberDevicePaths = 1;
  }

  ToggleHddUnlockPromptState (FALSE);
  if (*NumberDevicePaths == 0) {
    DPRINTF_DEV ("  Could not find a matching HDD path.\n");
    Status = SCT_STATUS_NOT_FOUND;
  } else {
    DPRINTF_DEVICE_PATH ("ExpandedDevicePaths = ", *ExpandedDevicePaths);
    Status = SCT_STATUS_SUCCESS;
  }
  DPRINTF_DEV ("Returne [%r]\n", Status);
  return Status;
} // HddDevicePathExpansionEx

#else // CONFIG_BmHddExpansionConnectList

{
  UINTN i;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  UINTN BlockIoHandleCount;
  EFI_HANDLE *HandleBuffers;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  PBOOT_MANAGER_CONNECTION_DEVICE p;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_DEVICE_PATH_PROTOCOL *ParentDevicePath;

  BOOT_MANAGER_CONNECTION_DEVICE HddExpansionConnectList [] = {
    CONFIG_BmHddExpansionConnectList,
    BOOT_MANAGER_CONNECTION_DEVICE_LIST_END
  };

  DPRINTF_DEV ("Entry:\n");

  //
  // check FIRST DeviceNode of input DevicePath is HD(...)
  //
  DPRINTF_DEV ("First DeviceNode->Type    = [0x%x]\n", DevicePathType (DevicePath));
  DPRINTF_DEV ("First DeviceNode->SubType = [0x%x]\n", DevicePathSubType(DevicePath));
  if (!IsDeviceNodeHdd (DevicePath)) {
    DPRINTF_DEV ("  Not a HDD search path.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  DPRINTF_DEVICE_PATH ("  Expand ", DevicePath);

  //
  // Before ConnectController, unlock all HDDs first, hence the file system can
  // be installed.
  //

  ToggleHddUnlockPromptState (TRUE);
  UnlockAllHdd ();

  p = HddExpansionConnectList;
  while (TRUE) {
    if (p->TextDevicePath == NULL) {
      break;
    }

    ParentDevicePath = NULL;
    ParentDevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (ParentDevicePath == NULL) {
      DPRINTF_DEV (
        "  Failed to convert %s to a device path.\n",
        p->TextDevicePath);
      p++;
      continue;
    }

    //
    // Step1. Connect controller non-recursively first.
    //

    Status = ConnectDevicePathWithRecurse (
               ParentDevicePath,
               &Handle,
               p->Recursive);
               //FALSE);
    DPRINTF_DEV (
      "  ConnectDevicePathWithRecurse (%s) returned %r.\n",
      p->TextDevicePath,
      Status);

    SafeFreePool (ParentDevicePath);
    if (EFI_ERROR (Status)) {
      p++;
      continue;
    }

    //
    // Setp2. Connect those handles that belong to HDD type recursively.
    //

    BlockIoHandleCount = 0;
    HandleBuffers = NULL;

    Status = gBS->LocateHandleBuffer (
                    ByProtocol,
                    &gEfiBlockIoProtocolGuid,
                    NULL,
                    &BlockIoHandleCount,
                    &HandleBuffers);

    DPRINTF_DEV ("  LocateHandleBuffer for BlkIo %d found (%r)\n",
      BlockIoHandleCount,
      Status);

    if (EFI_ERROR (Status) || BlockIoHandleCount == 0) {
      p++;
      continue;
    }

    for (i = 0; i < BlockIoHandleCount; i++) {

      DEBUG_DEV ({
        PCHAR16  Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (
                DevicePathFromHandle (HandleBuffers [i]),
                FALSE,
                TRUE);
        DPRINTF_DEV ("  BlkIo %d - %s.\n", i, Str);
        SafeFreePool (Str);
      });

      LastNode = GetLastDeviceNode (DevicePathFromHandle (HandleBuffers [i]));
      if (!(LastNode->SubType == MSG_SATA_DP ||
            LastNode->SubType == MSG_ATAPI_DP ||
            LastNode->SubType == MSG_SCSI_DP ||
            LastNode->SubType == MSG_VENDOR_DP||
            LastNode->SubType == MSG_NVME_NAMESPACE_DP||
            (LastNode->Type == HARDWARE_DEVICE_PATH && LastNode->SubType == HW_CONTROLLER_DP) ||
            (LastNode->Type == MESSAGING_DEVICE_PATH && LastNode->SubType == MSG_EMMC_DP) ||
            (LastNode->Type == MESSAGING_DEVICE_PATH && LastNode->SubType == MSG_SD_DP))) {
        DPRINTF_DEV ("It's not Storage. Check next device!!\n");
        continue;
      }

      BlockIo = NULL;
      Status = gBS->HandleProtocol (
                      HandleBuffers [i],
                      &gEfiBlockIoProtocolGuid,
                      (VOID **)&BlockIo);

      DPRINTF_DEV ("  Is removable = %d\n", BlockIo->Media->RemovableMedia);
      if (!EFI_ERROR (Status) &&
        BlockIo != NULL &&
        BlockIo->Media->RemovableMedia == FALSE) {
        gBS->ConnectController (HandleBuffers [i], NULL, NULL, FALSE);
      }
    }

    SafeFreePool (HandleBuffers);

    //
    // Check all handles after each connect to avoid extra connect events.
    // Exit with success at the first match found.
    //

    *ExpandedDevicePaths = HddSearchForNode (DevicePath);
    if (*ExpandedDevicePaths != NULL) {
      *NumberDevicePaths = 1;
      ToggleHddUnlockPromptState (FALSE);
      return SCT_STATUS_SUCCESS;
    }

    p++;
  }

  ToggleHddUnlockPromptState (FALSE);
  DPRINTF_DEV ("  Could not find a matching HDD path.\n");
  return SCT_STATUS_NOT_FOUND;
} // HddDevicePathExpansionEx
#endif // CONFIG_BmHddExpansionConnectList

//
// FUNCTION NAME.
//      UsbSearchForNode - Search all the device paths for a node.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches all the device paths in the system for one which
//      ends with the first node in DevicePath and appends the remaining nodes
//      to the found path, returning this result.
//
//      This function implements searches for USB nodes. The first node in
//      DevicePath must be a USB node.
//
// ENTRY PARAMETERS.
//      DevicePath      - a pointer to the device path whose first node must
//                        match. The rest of the device path will be appended
//                        to the matching path.
//      NumberOfDevicePaths - the number of device paths in the array.
//
// EXIT PARAMETERS.
//      Function Return - a pointer to the first matching device path with the
//                        remain path appended.
//

EFI_DEVICE_PATH_PROTOCOL *
UsbSearchForNode (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PUINTN NumberOfDevicePaths)
{
  UINTN i;
  SCT_STATUS Status;
  DEVICE_PATH_PTR SearchNode;

  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  EFI_DEVICE_PATH_PROTOCOL *ReturnPath;

  EFI_DEVICE_PATH_PROTOCOL *p;          // temp pointer. Used to walk "this" device path.
  EFI_DEVICE_PATH_PROTOCOL *dp;         // pointer to the start of "this" device path.
  DEVICE_PATH_PTR DeviceNode;           // pointer to the Usb Node in "this" device path.

  EFI_USB_IO_PROTOCOL *UsbIo;
  EFI_USB_DEVICE_DESCRIPTOR UsbDeviceDescriptor;
  EFI_USB_INTERFACE_DESCRIPTOR UsbInterfaceDescriptor;

  UINT16 InterfaceNumber;
  UINT16 IdVendor;
  UINT16 IdProduct;
  PCHAR16 SerialNumber, SerialNumberString;
  UINTN SerialNumberLength;
  UINT8 Class;
  UINT8 SubClass;
  UINT8 Protocol;
  UINTN Size;
  UINT8 *Record;

  DPRINTF_DEV ("UsbSearchForNode.\n");

  //
  // This function is for USB expansion only. Return NULL if the search path is
  // not a USB path.
  // Setup the cached search fields. Saves checking later.
  //

  SearchNode.DevPath = DevicePath;      // could be either UsbClass or UsbWwid.
  if (IsDeviceNodeUsbWwid (SearchNode.DevPath)) {
    InterfaceNumber = SearchNode.UsbWwid->InterfaceNumber;
    IdVendor = SearchNode.UsbWwid->VendorId;
    IdProduct = SearchNode.UsbWwid->ProductId;
    SerialNumber = (PCHAR16)(SearchNode.address + 10);
    SerialNumberLength = DevicePathNodeLength (SearchNode.DevPath) - 10;
    Class = 0xFF;
    SubClass = 0xFF;
    Protocol = 0xFF;
  } else if (IsDeviceNodeUsbClass (SearchNode.DevPath)) {
    InterfaceNumber = 0xFFFF;
    IdVendor = SearchNode.UsbClass->VendorId;
    IdProduct = SearchNode.UsbClass->ProductId;
    SerialNumber = NULL;
    SerialNumberLength = 0;
    Class = SearchNode.UsbClass->DeviceClass;
    SubClass = SearchNode.UsbClass->DeviceSubClass;
    Protocol = SearchNode.UsbClass->DeviceProtocol;
    if (Class == 0xff || Class == 0x08) {

      //
      // Any type of USB devices or USB Mass Storage.
      //

      gBS->Stall (1000 * CONFIG_SYSTEM_BOOT_MANAGER_STALL_FOR_ALL_USB_DEVICE);

    }
  } else {
    DPRINTF_DEV ("  The search path does not begin with a UsbSearch node.\n");
    return NULL;
  }

  DEBUG_DEV ({
    PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    if (Str != NULL) {
      DPRINTF_DEV ("  Search criteria DevicePath  %s.\n", Str);
      SafeFreePool (Str);
    }
  });

  DPRINTF_DEV ("  InterfaceNumber = 0x%x.\n", InterfaceNumber);
  DPRINTF_DEV ("  IdVendor = 0x%x.\n", IdVendor);
  DPRINTF_DEV ("  IdProduct = 0x%x.\n", IdProduct);
  DPRINTF_DEV ("  SerialNumber = 0x%x.\n", SerialNumber);
  DPRINTF_DEV ("  SerialNumberLength = 0x%x.\n", SerialNumberLength);
  DPRINTF_DEV ("  Class = 0x%x.\n", Class);
  DPRINTF_DEV ("  SubClass = 0x%x.\n", SubClass);
  DPRINTF_DEV ("  Protocol = 0x%x.\n", Protocol);

  //
  // Search all instances of UsbIo protocol for one that matches.
  //

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiUsbIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  if (EFI_ERROR (Status) || HandleCount == 0) {
    DPRINTF_DEV (
      "  LocateHandleBuffer (gEfiUsbIoProtocolGuid) returned %r, HandleCount = 0x%x.\n",
      Status,
      HandleCount);
    return NULL;
  }

  ReturnPath = NULL;
  Record = NULL;
  Size = 0;
  *NumberOfDevicePaths = 0;
  DPRINTF_DEV (" Total USB IO Handle = 0x%x\n", HandleCount);
  Record = AllocatePool (HandleCount * (sizeof (UINT8)));
  for (i = 0 ; i < HandleCount; i++ ) {

    //
    // Get the UsbIo protocol instance for this handle.
    //

    Status = gBS->OpenProtocol(
                    HandleBuffer [i],
                    &gEfiUsbIoProtocolGuid,
                    (VOID **) &UsbIo,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status) || UsbIo == NULL) {
      DPRINTF_DEV (
        "  0x%x Error opening protocol, returned %r\n",
        HandleBuffer [i],
        Status);
      continue;
    }

    //
    // Get the Device Path protocol instance for this handle.
    //

    Status = gBS->OpenProtocol(
                    HandleBuffer [i],
                    &gEfiDevicePathProtocolGuid,
                    (VOID **) &dp,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status) || dp == NULL) {
      DPRINTF_DEV (
        "  0x%x Error opening protocol, returned %r\n",
        HandleBuffer [i],
        Status);
      continue;
    }

    DEBUG_DEV ({
      PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (dp, FALSE, TRUE);
      if (!EFI_ERROR (Status)) {
        DPRINTF_DEV ("  USB IO Device path =   %s.\n", Str);
        SafeFreePool (Str);
      }
    });

    //
    // Get the USB Device Descriptor.
    //

    Status = UsbIo->UsbGetDeviceDescriptor (UsbIo, &UsbDeviceDescriptor);
    if (EFI_ERROR (Status)) {
      DPRINTF_DEV ("  UsbGetDeviceDescriptor returned %r.\n", Status);
      continue;
    }
    DISPLAY_USB_DEVICE_DESCRIPTOR (&UsbDeviceDescriptor);

    //
    // Get the USB Interface Descriptor.
    //

    Status = UsbIo->UsbGetInterfaceDescriptor (UsbIo, &UsbInterfaceDescriptor);
    if (EFI_ERROR (Status)) {
      DPRINTF_DEV ("  UsbGetInterfaceDescriptor returned %r.\n", Status);
      continue;
    }
    DISPLAY_USB_INTERFACE_DESCRIPTOR (&UsbInterfaceDescriptor);

    //
    // Check the InterfaceNumber SearchNode field.
    //

    if (InterfaceNumber != 0xFFFF) {
      DPRINTF_DEV (
        "  Check this handle for InterfaceNumber 0x%x.\n",
        InterfaceNumber);

      //
      // Find the last node of the dp.
      //

      DeviceNode.DevPath = GetLastDeviceNode (dp);
      if (DeviceNode.DevPath == NULL) {
        DPRINTF_DEV ("  Couldn't find the last device node.\n");
        continue;
      }

      //
      // If this last node is not a USB node skip this handle.
      //

      if (!IsDeviceNodeUsb (DeviceNode.DevPath)) {
        DPRINTF_DEV ("  The last device node was not USB.\n");
        continue;
      }

      //
      // Check to see if this interface is the one requested.
      //

      if ((UINT16)(DeviceNode.Usb->InterfaceNumber) != InterfaceNumber) {
        DPRINTF_DEV (
          "  DeviceNode.Usb->InterfaceNumber 0x%x didn't match.\n",
          DeviceNode.Usb->InterfaceNumber);
        continue;
      }

    }

    //
    // Check the IdVendor SearchNode field.
    //

    if (IdVendor != 0xFFFF) {
      DPRINTF_DEV ("  Check this handle for IdVendor 0x%x.\n", IdVendor);

      if (IdVendor != UsbDeviceDescriptor.IdVendor) {
        DPRINTF_DEV (
          "  UsbDeviceDescriptor.IdVendor 0x%x didn't match.\n",
          UsbDeviceDescriptor.IdVendor);
        continue;
      }
    }

    //
    // Check the IdProduct SearchNode field.
    //

    if (IdProduct != 0xFFFF) {
      DPRINTF_DEV ("  Check this handle for IdProduct 0x%x.\n", IdProduct);

      if (IdProduct != UsbDeviceDescriptor.IdProduct) {
        DPRINTF_DEV (
          "  UsbDeviceDescriptor.IdProduct 0x%x didn't match.\n",
          UsbDeviceDescriptor.IdProduct);
        continue;
      }
    }

    //
    // Check the Class SearchNode field.
    //

    if (Class != 0xFF) {
      DPRINTF_DEV ("  Check this handle for Class 0x%x.\n", Class);

      if ((Class != UsbInterfaceDescriptor.InterfaceClass) && (Class != UsbDeviceDescriptor.DeviceClass)) {
        DPRINTF_DEV (
          "  UsbInterfaceDescriptor.InterfaceClass 0x%x and UsbDeviceDescriptor.DeviceClass 0x%x didn't match.\n",
          UsbInterfaceDescriptor.InterfaceClass,
          UsbDeviceDescriptor.DeviceClass);
        continue;
      }
    }

    //
    // Check the SubClass SearchNode field.
    //

    if (SubClass != 0xFF) {
      DPRINTF_DEV ("  Check this handle for SubClass 0x%x.\n", SubClass);

      if ((SubClass != UsbInterfaceDescriptor.InterfaceSubClass) && (SubClass != UsbDeviceDescriptor.DeviceSubClass)) {
        DPRINTF_DEV (
          "  UsbInterfaceDescriptor.InterfaceSubClass 0x%x and UsbDeviceDescriptor.DeviceSubClass 0x%x didn't match.\n",
          UsbInterfaceDescriptor.InterfaceSubClass,
          UsbDeviceDescriptor.DeviceSubClass);
        continue;
      }
    }

    //
    // Check the Protocol SearchNode field.
    //

    if (Protocol != 0xFF) {
      DPRINTF_DEV ("  Check this handle for Protocol 0x%x.\n", Protocol);

      if ((Protocol != UsbInterfaceDescriptor.InterfaceProtocol) && (Protocol != UsbDeviceDescriptor.DeviceProtocol)) {
        DPRINTF_DEV (
          "  UsbInterfaceDescriptor.InterfaceProtocol 0x%x and UsbDeviceDescriptor.DeviceProtocol 0x%x didn't match.\n",
          UsbInterfaceDescriptor.InterfaceProtocol,
          UsbDeviceDescriptor.DeviceProtocol);
        continue;
      }
    }

    //
    // Check the SerialNumber SearchNode field.
    //

    if (SerialNumber != NULL) {
      DPRINTF_DEV (
        "  Check this handle for SerialNumber @ 0x%x.\n",
        SerialNumber);

      //
      // Get the Serial Number String.
      //

      Status = UsbIo->UsbGetStringDescriptor (
                        UsbIo,
                        USB_LANGID_US_ENGLISH,
                        UsbDeviceDescriptor.StrSerialNumber,
                        &SerialNumberString);
      if (EFI_ERROR (Status)) {
        DPRINTF_DEV ("  UsbGetStringDescriptor returned %r.\n", Status);
        continue;
      }

      if (StrnCmp (SerialNumber, SerialNumberString, SerialNumberLength) != 0) {
        DPRINTF_DEV ("  SerialNumber string didn't match.\n");
        continue;
      }
    }

    Record [*NumberOfDevicePaths] = (UINT8)i;
    *NumberOfDevicePaths = *NumberOfDevicePaths + 1;
    Size += GetDevicePathSize (dp);
  }

  DPRINTF_DEV ("  Total Matched  %d.\n", *NumberOfDevicePaths);

  if (*NumberOfDevicePaths > 0) {
    Status = (gBS->AllocatePool) (EfiBootServicesData, Size, (VOID **) &ReturnPath);
    p = ReturnPath;
    for (i = 0 ; i < *NumberOfDevicePaths; i++ ) {
      dp = DevicePathFromHandle (HandleBuffer [Record [i]]);
      DEBUG_DEV ({
        if (!EFI_ERROR (Status)) {
          PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (dp, FALSE, TRUE);
          DPRINTF_DEV ("  Matched USB CLASS  %s.\n", Str);
          SafeFreePool (Str);
        }
      });
      Size = GetDevicePathSize (dp);
      CopyMem (p, dp, Size);
      p = (EFI_DEVICE_PATH_PROTOCOL *)(((UINT8 *)p) + Size);
    }
  }

  SafeFreePool (HandleBuffer);
  SafeFreePool (Record);
  return ReturnPath;
} // UsbSearchForNode


//
// FUNCTION NAME.
//      UsbDevicePathExpansion - Expand USB nodes.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches for USB devices that will satisfy the criteria
//      presented by a USB shortcut node.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - an SCT_STATUS code.
//

SCT_STATUS
EFIAPI
UsbDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  )
#ifndef CONFIG_BmUsbExpansionConnectList
{
  EFI_STATUS Status;

  DPRINTF_DEV ("Entry:\n");

  if (!IsDeviceNodeUsbSearch (DevicePath)) {
    DPRINTF_DEV ("  Not a USB search path.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  DPRINTF_DEVICE_PATH ("  Expand ", DevicePath);

  *NumberDevicePaths = 0;

  //
  // Check all handles after each connect to avoid extra connect events.
  // Exit with success at the first match found.
  //
  *ExpandedDevicePaths = UsbSearchForNode (DevicePath, NumberDevicePaths);
  if (*NumberDevicePaths > 0) {
    Status = SCT_STATUS_SUCCESS;
  } else {
    Status = SCT_STATUS_NOT_FOUND;
  }
  return Status;
} // UsbDevicePathExpansion

#else // CONFIG_BmUsbExpansionConnectList

{
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  EFI_HANDLE Handle;
  PBOOT_MANAGER_CONNECTION_DEVICE p;
  EFI_DEVICE_PATH_PROTOCOL *ParentDevicePath;

  BOOT_MANAGER_CONNECTION_DEVICE mUsbExpansionConnectList [] = {
    CONFIG_BmUsbExpansionConnectList
  };

  DPRINTF_DEV ("UsbDevicePathExpansion:\n");

  DEBUG_DEV ({
    PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_DEV ("  Expand %s.\n", Str);
    SafeFreePool (Str);
  });

  if (!IsDeviceNodeUsbSearch (DevicePath)) {
    DPRINTF_DEV ("  Not a USB search path.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  p = mUsbExpansionConnectList;
  while (TRUE) {
    if (p->TextDevicePath == NULL) {
      break;
    }

    ParentDevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (ParentDevicePath == NULL) {
      DPRINTF_DEV (
        "  Failed to convert %s to a device path.\n",
        p->TextDevicePath);
      p++;
      continue;
    }

    Status = ConnectDevicePathWithRecurse (
               ParentDevicePath,
               &Handle,
               p->Recursive);
    DPRINTF_DEV (
      "  ConnectDevicePathWithRecurse (%s) returned %r.\n",
      p->TextDevicePath,
      Status);
    SafeFreePool (ParentDevicePath);

    p++;
  }

  *NumberDevicePaths = 0;
  *ExpandedDevicePaths = UsbSearchForNode (DevicePath, NumberDevicePaths);
  if (*NumberDevicePaths > 0) {
    return SCT_STATUS_SUCCESS;
  }

  DPRINTF_DEV ("  Could not find a matching USB path.\n");
  return SCT_STATUS_NOT_FOUND;
} // UsbDevicePathExpansion
#endif // CONFIG_BmUsbExpansionConnectList


//
// FUNCTION NAME.
//      FvFileDevicePathExpansion - Find a FvFile in an Fv.
//
// FUNCTIONAL DESCRIPTION.
//      .
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
FvFileDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  )
{
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *FvDevicePath;
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *FvFileDevicePath;
  EFI_HANDLE OptionalFvHandle;

  DPRINTF_DEV ("FvFileDevicePathExpansion:\n");

  DEBUG_DEV ({
    PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_DEV ("  Expand %s.\n", Str);
    SafeFreePool (Str);
  });

  if (!IsDeviceNodeFvFile (DevicePath)) {
    DPRINTF_DEV ("  Not an FvFile.\n");
    return SCT_STATUS_UNSUPPORTED;
  }

  FvFileDevicePath = (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)DevicePath;


  if (IsFvFileExist (mFvHandle, &FvFileDevicePath->FvFileName)) {
    FvDevicePath = DevicePathFromHandle (mFvHandle);
  } else {

    //
    // FvFile is in other separated firmware volumes.
    //

    DecompressOptionalFirmwareVolume (SCT_FIRMWAREVOLUME_TYPE_ALL);

    Status = FindOptionalFvHandle (&FvFileDevicePath->FvFileName, &OptionalFvHandle);
    if (EFI_ERROR(Status)) {
      return Status;
    }

    FvDevicePath = DevicePathFromHandle (OptionalFvHandle);
  }
  *ExpandedDevicePaths = AppendDevicePath (FvDevicePath, DevicePath);
  *NumberDevicePaths = 1;

  return SCT_STATUS_SUCCESS;
} // FvFileDevicePathExpansion


//
// FUNCTION NAME.
//      BootOptionProtocolDevicePathExpansion - Expand a Boot Option Protocol Device Path.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes Vendor Guid nodes. These nodes provide the GUID
//      for a protocol instance which implements the Oem Device Path Expansion
//      interface. This function will then use the interface (if found) to
//      expand the device path into an array of device paths.
//
// ENTRY PARAMETERS.
//      DevicePath      - the Device Path to expand.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      ExpandedDevicePaths - the array of expanded device paths.
//      NumberDevicePaths - the number of expanded device paths.
//

SCT_STATUS
EFIAPI
BootOptionProtocolDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  )
{
  SCT_STATUS Status;
  PSCT_BOOT_OPTION_PROTOCOL BootOptionProtocol;
  PSCT_BOOT_OPTION2_PROTOCOL BootOption2Protocol;
  PVOID Context;
  UINTN ContextSize;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *p;
  UINT16 MillisecondsToStall;

  DPRINTF_DEV ("Entry:\n");

  DEBUG_DEV ({
    PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_DEV (" DevicePath Expand %s.\n", Str);
    SafeFreePool (Str);
  });

  if (!IsDeviceNodeBootOptionProtocol (DevicePath)) {
    DPRINTF_DEV ("  Not an Oem Expansion Node.\n");
    return SCT_STATUS_UNSUPPORTED;
  }
  p = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *)DevicePath;

  if (DevicePathNodeLength (DevicePath) > sizeof (BOOT_OPTION_PROTOCOL_DEVICE_PATH)) {
    ContextSize = DevicePathNodeLength (DevicePath) - sizeof (BOOT_OPTION_PROTOCOL_DEVICE_PATH);
    Context = p + 1;
  } else {
    ContextSize = 0;
    Context = NULL;
  }
  DPRINTF_DEV ("  Found %d bytes of context.\n", ContextSize);

  Status = gBS->LocateProtocol (
                  &(p->ProtocolGuid),
                  NULL,
                  (VOID **) &BootOptionProtocol);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Failed to LocateProtocol, %r.\n", Status);
    return Status;
  }

  //
  // Check if it is SCT_BOOT_OPTION_PROTOCOL or SCT_BOOT_OPTION2_PROTOCOL by checking
  // the size.  Then assign the DevicePath back.
  //

  if (BootOptionProtocol->Size == SCT_BOOT_OPTION_PROTOCOL2_SIZE) {
    BootOption2Protocol = (PSCT_BOOT_OPTION2_PROTOCOL) BootOptionProtocol;
    BootOption2Protocol->OriginalPathList = DuplicateDevicePath (DevicePath);
  }

  DPRINTF_DEV ("  BootOptionProtocol size = 0x%x.\n", BootOptionProtocol->Size);
  Status = BootOptionProtocol->GetDevicePaths (
                                 BootOptionProtocol,
                                 Context,
                                 ContextSize,
                                 ExpandedDevicePaths,
                                 NumberDevicePaths);

  if (*NumberDevicePaths == 0) {

    DPRINTF_DEV (" No matched device path found\n");

    //
    // Give a second chance to retrieve USB MSDs.
    //

    if (CompareGuid (&(p->ProtocolGuid), &gUsbHddBootOptionProtocolGuid) ||
        CompareGuid (&(p->ProtocolGuid), &gUsbFddBootOptionProtocolGuid) ||
        CompareGuid (&(p->ProtocolGuid), &gUsbCdBootOptionProtocolGuid)) {

      DPRINTF_DEV (" Give second chance to USB related BOP\n");
      GetUsbHcProperStallTime (&MillisecondsToStall);

      DPRINTF_DEV (" Stall %d milliseconds\n");
      gBS->Stall (1000 * MillisecondsToStall);

      Status = BootOptionProtocol->GetDevicePaths (
                                     BootOptionProtocol,
                                     Context,
                                     ContextSize,
                                     ExpandedDevicePaths,
                                     NumberDevicePaths);
    }
  }

  DPRINTF_DEV (
    "  BootOptionProtocol->GetDevicePaths returned %r, NumberDevicePaths = %d.\n",
    Status,
    *NumberDevicePaths);

  return Status;
} // BootOptionProtocolDevicePathExpansion


//
// FUNCTION NAME.
//      ToggleHddUnlockPromptState - toggle the state of Unlock prompt.
//
// FUNCTIONAL DESCRIPTION.
//      This function will enable or disable the HDD Unlock prompt occurred when
//      Disk IO protocol installed on specific handle which has Disk Info
//      protocol installed already.
//
// ENTRY PARAMETERS.
//      Enabled         - State of the Unlock prompt.
//


VOID
EFIAPI
ToggleHddUnlockPromptState (IN BOOLEAN Enabled)
{
  if (HddPwd != NULL) {
    HddPwd->EnablePasswordPrompt (HddPwd, Enabled);
  }
  mUnlockHddPrompt = Enabled;

} // ToggleHddUnlockPromptState


//
// FUNCTION NAME.
//      UnlockAllHdd - Unlock all HDDs.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to unlock all HDDs via SCT_HDD_PWD_PROTOCOL.
//
// ENTRY PARAMETERS.
//      None.
//

VOID
EFIAPI
UnlockAllHdd (VOID)
{
  if (HddPwd != NULL) {
    HddPwd->UnlockAllHdd (HddPwd);
  }
} // UnlockAllHdd


//
// FUNCTION NAME.
//      UnlockHdd - Unlock one specific HDD.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to unlock certain HDD via SCT_HDD_PWD_PROTOCOL.
//
// ENTRY PARAMETERS.
//      None.
//

EFI_STATUS
EFIAPI
UnlockHdd (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  if (DevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (HddPwd == NULL) {
    return EFI_UNSUPPORTED;
  }

  Handle = NULL;
  RemainingDevicePath = DevicePath;

  //
  // Find the associated handle.
  // The device path should be totally matched.
  //

  Status = gBS->LocateDevicePath (
                  &gEfiDiskInfoProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (EFI_ERROR (Status) || !IsDevicePathEnd (RemainingDevicePath)) {
    return Status;
  }

  return HddPwd->UnlockOneHdd (HddPwd, Handle);
} // UnlockHdd


//
// FUNCTION NAME.
//      ConnectAllPciDevices - Connect all Pci devices.
//
// FUNCTIONAL DESCRIPTION.
//      This function will connect all Pci devices via ConnectController with
//      all PciRootBridge controller and null remaining device path.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

SCT_STATUS
EFIAPI
ConnectAllPciDevices (VOID)
{
  UINTN Index;
  UINTN NumHandles;
  SCT_STATUS Status;
  EFI_HANDLE *HandleBuffer;

  Index = 0;
  HandleBuffer = NULL;
  Status = EFI_NOT_FOUND;

  DPRINTF_DEV ("ConnectAllPciDevices \n");

  if (mAllPciDeviceStarted) {
    DPRINTF_DEV (" Already happened \n");
    return EFI_SUCCESS;
  }

  gBS->LocateHandleBuffer (
         ByProtocol,
         &gEfiPciRootBridgeIoProtocolGuid,
         NULL,
         &NumHandles,
         &HandleBuffer);

  if (NumHandles == 0) {
    DPRINTF_DEV ("  Could not find any Pci Root Bridge devices.\n");
    return EFI_NOT_FOUND;
  }

  PERF_START (0, "ConnectAllPciDevices", "BootManager", 0);
  for (Index = 0; Index < NumHandles; Index++) {
    Status = gBS->ConnectController (
                    HandleBuffer [Index],
                    NULL,
                    NULL,
                    FALSE);
    DPRINTF_DEV ("  ConnectController return %r.\n", Status);
  }
  PERF_END (0, "ConnectAllPciDevices", "BootManager", 0);

  //
  // Finally, freed the resource.
  //

  FreePool (HandleBuffer);
  mAllPciDeviceStarted = TRUE;
  DUMP_ALL_DEVICE_PATHS;

  return Status;

} // ConnectAllPciDevices


//
// FUNCTION NAME.
//      CompareConnectDevicePath - Compare Device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function compar two device path size with first device path.
//
// ENTRY PARAMETERS.
//      DevicePath1     - a point of the DevicePath1.
//      DevicePath2     - a point of the DevicePath2.
//
// EXIT PARAMETERS.
//      None.
//

BOOLEAN
EFIAPI
CompareConnectDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath1,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath2
  )
{
  UINTN Size;

  Size = GetDevicePathSize (DevicePath1);

  Size -= sizeof (EFI_DEVICE_PATH_PROTOCOL);

  //
  // Base on DevicePath1 size to compare
  //

  return CompareMem (DevicePath1, DevicePath2, Size) == 0 ? TRUE : FALSE;
} // CompareConnectDevicePath


//
// FUNCTION NAME.
//      ConnectDefaultDevices - Connect default devices list.
//
// FUNCTIONAL DESCRIPTION.
//      This function compar default device list, if no create always connect all
//      otherwise connect default device.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

SCT_STATUS
EFIAPI
ConnectDefaultDevices (VOID)
{
  SCT_STATUS Status;

  Status = ConnectDevices (mDeviceConnectList);
  DPRINTF_DEV ("  ConnectDevices returned %r.\n", Status);

  return Status;
} // ConnectDefaultDevices


//
// FUNCTION NAME.
//      CreateAtaOrAtapiModelName - Create ATA or ATAPI Model Name
//
// FUNCTIONAL DESCRIPTION.
//      This function will build the ATA/ATAPI model name according to the input
//      device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - Device path for module name construction.
//
// EXIT PARAMETERS.
//      None.
//

PCHAR16
CreateAtaOrAtapiModelName (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  UINT32 BufferSize;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  PCHAR16 DeviceDescString;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;
  EFI_IDENTIFY_DATA *IdentifyDriveInfo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV ("CreateAtaOrAtapiModelName\n");

  if (DevicePath == NULL) {
    return NULL;
  }

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);
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
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  //
  // Get the identity data for this drive.
  //

  BufferSize = sizeof (EFI_IDENTIFY_DATA);
  IdentifyDriveInfo = AllocatePool (sizeof (EFI_IDENTIFY_DATA));

  Status = DiskInfo->Identify (DiskInfo, IdentifyDriveInfo, &BufferSize);
  DPRINTF_DEV ("   DiskInfo->Identify %r\n",Status);

  if (EFI_ERROR (Status)) {
    DeviceDescString = NULL;
  } else {
    DeviceDescString = AtaModelNameToUnicode (&(IdentifyDriveInfo->AtaData.ModelName [0]));
  }

  //
  // Freed the resource.
  //

  FreePool (IdentifyDriveInfo);

  return DeviceDescString;
} // CreateAtaOrAtapiModelName


//
// FUNCTION NAME.
//      CreateUsbMsdDescription - Create a string based on a device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes a device path and creates an appropriate
//      description string.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

PCHAR16
EFIAPI
CreateUsbMsdDescription (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  CHAR16 *Desc;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  if (DevicePath == NULL) {
    return NULL;
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
    return NULL;
  }

  if (!IsDevicePathEnd (RemainingDevicePath)) {
    return NULL;
  }

  Desc = NULL;
  Status = GetUsbMsdDeviceName (Handle, &Desc);
  if (!EFI_ERROR (Status) && Desc != NULL) {
    return Desc;
  }
  return NULL;
} // CreateUsbMsdDescription

//
// FUNCTION NAME.
//      CreateNvmeModelName - Create Nvme Model Name
//
// FUNCTIONAL DESCRIPTION.
//      This function will build the Nvme model name according to the input
//      device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - Device path for module name construction.
//
// EXIT PARAMETERS.
//      None.
//

PCHAR16
CreateNvmeModelName (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{

  SCT_STATUS Status;
  EFI_HANDLE Handle;
  PCHAR16 DeviceDescString;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  NVME_ADMIN_CONTROLLER_DATA NvmeIdentifyControllerData;

  DPRINTF_DEV ("CreateNvmeModelName\n");

  if (DevicePath == NULL) {
    return NULL;
  }

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);
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
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  //
  // Get the identity data for this drive.
  //

  Status = NvmeIdentifyController (Handle, &NvmeIdentifyControllerData);
  if (EFI_ERROR (Status)) {

    VOID *IdentifyDataBuffer;
    UINT32 IdentifyDataSize;

    //
    // For special controller which may hide the NVMe device and its pass-thru
    // protocol.  Here we use DiskInfo to get the identify data instead.
    //

    if (CompareGuid (&DiskInfo->Interface, &gEfiDiskInfoNvmeInterfaceGuid) == TRUE) {

      IdentifyDataSize = (UINT32)sizeof (NvmeIdentifyControllerData);
      Status = DiskInfo->Identify (
                          DiskInfo,
                          &NvmeIdentifyControllerData,
                          &IdentifyDataSize);
      if (EFI_BUFFER_TOO_SMALL == Status) {
        IdentifyDataBuffer = AllocatePool (IdentifyDataSize);
        ASSERT (IdentifyDataBuffer != NULL);

        Status = DiskInfo->Identify (
                            DiskInfo,
                            IdentifyDataBuffer,
                            &IdentifyDataSize);
        if (EFI_ERROR (Status)) {
          FreePool (IdentifyDataBuffer);
          return NULL;
        }

        CopyMem (
          &NvmeIdentifyControllerData,
          IdentifyDataBuffer,
          sizeof (NvmeIdentifyControllerData));

        FreePool (IdentifyDataBuffer);

      } else if (EFI_ERROR (Status)) {
        return NULL;
      }
    } else if (CompareGuid (&DiskInfo->Interface, &gEfiDiskInfoAhciInterfaceGuid) == TRUE) {
      return CreateAtaOrAtapiModelName (DevicePath);
    } else {
      return NULL;
    }
  }
  DeviceDescString = (CHAR16*)AllocateZeroPool (sizeof(NvmeIdentifyControllerData.Mn)*2);
  NvmeIdentifyControllerData.Mn[39] = 0;
  AsciiStrToUnicodeStrS ((CHAR8*)&NvmeIdentifyControllerData.Mn, DeviceDescString, sizeof(NvmeIdentifyControllerData.Mn));
  return DeviceDescString;
} // CreateNvmeModelName

//
// FUNCTION NAME.
//      CreateUfsModelName - Create UFS Model Name
//
// FUNCTIONAL DESCRIPTION.
//      This function will build the UFS model name according to the input
//      controller handle.
//
// ENTRY PARAMETERS.
//      Handle      - controller handle.
//
// EXIT PARAMETERS.
//      None.
//

PCHAR16
CreateUfsModelName (IN EFI_HANDLE *Handle)
{
  UINT8 *Desc;
  UINT32 DescSize;
  UINTN StringLen;
  SCT_STATUS Status;
  UINTN Char8Counter;
  UINTN Char16Counter;
  UINT8 DescHeader[2];
  UINT32 DescMaxSize;
  UINT32 DescHeaderSize;
  CHAR16 *ProductName;
  CHAR16 *ManufacturerName;
  UINT8 ProductNameId;
  UINT8 ManufacturerNameId;
  UINT8 UfsDeviceDescId;
  UINT8 UfsStringDescId;
  CHAR8 *TempStringBuffer;
  PCHAR16 DeviceDescString;
  EFI_UFS_DEVICE_CONFIG_PROTOCOL *UfsDevConfig;

  Desc = NULL;
  ProductName = NULL;
  ManufacturerName = NULL;
  DeviceDescString = NULL;

  DescMaxSize = 255;
  DescHeaderSize = 2;
  UfsDeviceDescId = 0x00,
  UfsStringDescId = 0x05,

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiUfsDeviceConfigProtocolGuid,
                  (VOID **)&UfsDevConfig,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  //
  // Read Device Descriptor Header
  //
  DescSize = DescHeaderSize;
  Status = UfsDevConfig->RwUfsDescriptor (
                           UfsDevConfig,
                           TRUE,
                           UfsDeviceDescId,
                           0,
                           0,
                           (UINT8 *)&DescHeader,
                           &DescSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  //
  // Read Device Descriptor
  //
  DescSize = DescHeader[0];
  Desc = AllocateZeroPool (DescSize);
  if (Desc == NULL) {
    goto Exit;
  }
  Status = UfsDevConfig->RwUfsDescriptor (
                           UfsDevConfig,
                           TRUE,
                           UfsDeviceDescId,
                           0,
                           0,
                           (UINT8 *)Desc,
                           &DescSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  ProductNameId = Desc[21];
  ManufacturerNameId = Desc[20];

  if (Desc != NULL) {
    FreePool (Desc);
    Desc = NULL;
  }

  Desc = AllocateZeroPool (DescMaxSize);
  if (Desc == NULL) {
    goto Exit;
  }

  //
  // Read Manufacturer Name from String Descriptor
  //
  ZeroMem (Desc, DescMaxSize);
  DescSize = (UINT32)DescMaxSize;
  Status = UfsDevConfig->RwUfsDescriptor (
                           UfsDevConfig,
                           TRUE,
                           UfsStringDescId,
                           ManufacturerNameId,
                           0,
                           (VOID *)Desc,
                           &DescSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  //
  //convert Manufacturer Name to unicode
  //
  StringLen = (Desc[0] - DescHeaderSize) / 2;
  ManufacturerName = AllocateZeroPool ((StringLen + 1) * sizeof (CHAR16));
  if (ManufacturerName == NULL) {
    goto Exit;
  }

  TempStringBuffer = (CHAR8 *)ManufacturerName;
  for (Char8Counter = 0, Char16Counter = 0;
       Char8Counter < (Desc[0] - DescHeaderSize);
       Char8Counter += 2) {
    //
    // Swap the odd and even bytes.
    //
    TempStringBuffer [Char8Counter] = Desc [DescHeaderSize + Char8Counter + 1];
    TempStringBuffer [Char8Counter+1] = Desc [DescHeaderSize + Char8Counter];
    Char16Counter++;
  }
  ManufacturerName [Char16Counter] = 0; // terminate the string

  //
  // Read Product Name from String Descriptor
  //
  ZeroMem (Desc, DescMaxSize);
  DescSize = (UINT32)DescMaxSize;
  Status = UfsDevConfig->RwUfsDescriptor (
                           UfsDevConfig,
                           TRUE,
                           UfsStringDescId,
                           ProductNameId,
                           0,
                           (VOID*)Desc,
                           &DescSize);
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  //
  //convert Product Name to unicode
  //
  StringLen = (Desc[0] - DescHeaderSize) / 2;
  ProductName = AllocateZeroPool ((StringLen + 1) * sizeof (CHAR16));
  if (ProductName == NULL) {
    goto Exit;
  }

  TempStringBuffer = (CHAR8*)ProductName;
  for (Char8Counter = 0, Char16Counter = 0;
       Char8Counter < (Desc[0] - DescHeaderSize);
       Char8Counter += 2) {
    //
    // Swap the odd and even bytes.
    //
    TempStringBuffer [Char8Counter] = Desc [DescHeaderSize + Char8Counter + 1];
    TempStringBuffer [Char8Counter+1] = Desc [DescHeaderSize + Char8Counter];
    Char16Counter++;
  }
  ProductName [Char16Counter] = 0; // terminate the string

  //
  // Combine Manufacturer Name and Product Name
  //
  StringLen = (StrLen(ManufacturerName) + StrLen(L" ") + StrLen(ProductName) + 1);
  DeviceDescString = AllocateZeroPool (StringLen * sizeof (CHAR16));
  if (DeviceDescString == NULL) {
     goto Exit;
  }

  StrCatS (DeviceDescString, StringLen, ManufacturerName);
  StrCatS (DeviceDescString, StringLen, L" ");
  StrCatS (DeviceDescString, StringLen, ProductName);

Exit:

  if (ManufacturerName != NULL) {
    FreePool (ManufacturerName);
    ManufacturerName = NULL;
  }

  if (ProductName != NULL) {
    FreePool (ProductName);
    ProductName = NULL;
  }

  if (Desc != NULL) {
    FreePool (Desc);
    Desc = NULL;
  }

  return DeviceDescString;
}

//
// FUNCTION NAME.
//      IsPciLanDevice - Is the device path on behalf of PCI LAN.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      PCI LAN device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsPciLanDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  UINT8 Class;
  BOOLEAN IsWiFi;
  EFI_HANDLE Handle;
  SCT_STATUS Status;
  UINTN DescriptionSize;
  EFI_PCI_IO_PROTOCOL *PciIo;
  EFI_DEVICE_PATH_PROTOCOL *LastDeviceNode;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  UINT16 BbsIndex;
  BBS_TABLE *BbsEntry;
#endif

  DPRINTF_DEV_CHECK (":Entry\n");

  if (DevicePath == NULL) {
    return FALSE;
  }
  LastDeviceNode = NULL;

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  IsWiFi = FALSE;

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  FALSE:LocateDevicePath error.\n");
    return FALSE;
  }

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **) &PciIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  FALSE:Could not open PciIo Protocol.\n");
    return FALSE;
  }

  PciIo->Pci.Read (
               PciIo,
               EfiPciIoWidthUint8,
               0x0b,
               1,
               &Class);
  DPRINTF_DEV_CHECK ("  Class = 0x%x.\n", Class);

  if (Class != PCI_CLASS_NETWORK) {
    return FALSE;
  }

  //
  // Test EFI_SIMPLE_NETWORK_PROTOCOL first.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPxeBaseCodeProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (!EFI_ERROR (Status) && IsDevicePathEnd (RemainingDevicePath)) {

    //
    // Construct the default description string for EFI based PXE device.
    //

    if (Description != NULL) {


      TempDevicePath = DevicePath;
      while (!IsDevicePathEnd (TempDevicePath)) {

        //
        // Find the Wi-Fi node
        //

       if ((DevicePathType (TempDevicePath) == MESSAGING_DEVICE_PATH) &&
         (DevicePathSubType (TempDevicePath) == MSG_WIFI_DP)) {
         IsWiFi = TRUE;
         break;
        }

        TempDevicePath = NextDevicePathNode (TempDevicePath);
      } // While

      if (IsWiFi == TRUE) {
        DescriptionSize = StrSize (L"EFI Network (Wi-Fi)(IPvX)");
      } else {
        DescriptionSize = StrSize (L"EFI Network (IPvX)");
      }
      *Description = (PCHAR16)AllocateZeroPool (DescriptionSize);

      //
      // IPv4 or IPv6.
      //

      LastDeviceNode = GetLastDeviceNode (DevicePath);

      if (LastDeviceNode->Type == MESSAGING_DEVICE_PATH) {
        if (IsWiFi == TRUE) {

          if (LastDeviceNode->SubType == MSG_IPv4_DP) {

            UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (Wi-Fi)(%s)",
              L"IPv4");

          } else if (LastDeviceNode->SubType == MSG_IPv6_DP) {

             UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (Wi-Fi)(%s)",
              L"IPv6");
          }
        } else {
          if (LastDeviceNode->SubType == MSG_IPv4_DP) {

            UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (%s)",
              L"IPv4");

          } else if (LastDeviceNode->SubType == MSG_IPv6_DP) {

             UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (%s)",
              L"IPv6");
          }

        } // if (IsWiFi == TRUE) {
      }
    }
    return TRUE;
  }

#if !(OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  return FALSE;
#else

  //
  // Check if this device is created from PNP expansion header after OPROM
  // shadowed.
  //

  Status = GetBbsEntryByDevicePath (DevicePath, &BbsIndex, &BbsEntry);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Construct the description string.
  //

  if (Description != NULL) {
    Status = BuildDescriptionFromBbsEntry (BbsEntry, Description);
  }

  return TRUE;
#endif
} // IsPciLanDevice

//
// FUNCTION NAME.
//      IsUsbLanDevice - Is the device path on behalf of USB LAN.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      USB LAN device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsUsbLanDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  UINT8 Class;
  BOOLEAN IsWiFi;
  UINT8 SubClass;
  EFI_HANDLE Handle;
  SCT_STATUS Status;
  UINTN DescriptionSize;
  EFI_PCI_IO_PROTOCOL *PciIo;
  EFI_DEVICE_PATH_PROTOCOL *LastDeviceNode;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  UINT16 BbsIndex;
  BBS_TABLE *BbsEntry;
#endif

  DPRINTF_DEV_CHECK (":Entry\n");

  IsWiFi = FALSE;
  if (DevicePath == NULL) {
    return FALSE;
  }
  LastDeviceNode = NULL;

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  FALSE:LocateDevicePath error.\n");
    return FALSE;
  }

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **) &PciIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  FALSE:Could not open PciIo Protocol.\n");
    return FALSE;
  }

  PciIo->Pci.Read (
               PciIo,
               EfiPciIoWidthUint8,
               0x0b,
               1,
               &Class);
  DPRINTF_DEV_CHECK ("  Class = 0x%x.\n", Class);

  PciIo->Pci.Read (
               PciIo,
               EfiPciIoWidthUint8,
               0x0a,
               1,
               &SubClass);
  DPRINTF_DEV_CHECK ("  SubClass = 0x%x.\n", SubClass);

  if ((Class != PCI_CLASS_SERIAL) && (SubClass != PCI_CLASS_SERIAL_USB)) {
    return FALSE;
  }

  //
  // Test EFI_SIMPLE_NETWORK_PROTOCOL first.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPxeBaseCodeProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (!EFI_ERROR (Status) && IsDevicePathEnd (RemainingDevicePath)) {

    //
    // Construct the default description string for EFI based PXE device.
    //

    if (Description != NULL) {

      TempDevicePath = DevicePath;
      while (!IsDevicePathEnd (TempDevicePath)) {

        //
        // Find the Wi-Fi node
        //

        if ((DevicePathType (TempDevicePath) == MESSAGING_DEVICE_PATH) &&
          (DevicePathSubType (TempDevicePath) == MSG_WIFI_DP)) {
          IsWiFi = TRUE;
          break;
        }
        TempDevicePath = NextDevicePathNode (TempDevicePath);
      } // While

      if (IsWiFi == TRUE) {
        DescriptionSize = StrSize (L"EFI Network (Wi-Fi)(IPvX)");
      } else {
        DescriptionSize = StrSize (L"EFI Network (IPvX)");
      }
      *Description = (PCHAR16)AllocateZeroPool (DescriptionSize);

      //
      // IPv4 or IPv6.
      //

      LastDeviceNode = GetLastDeviceNode (DevicePath);

      if (LastDeviceNode->Type == MESSAGING_DEVICE_PATH) {

        if (IsWiFi == TRUE) {

          if (LastDeviceNode->SubType == MSG_IPv4_DP) {

            UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (Wi-Fi)(%s)",
              L"IPv4");

          } else if (LastDeviceNode->SubType == MSG_IPv6_DP) {

            UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (Wi-Fi)(%s)",
              L"IPv6");
          }
        } else {
          if (LastDeviceNode->SubType == MSG_IPv4_DP) {

            UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (%s)",
              L"IPv4");

          } else if (LastDeviceNode->SubType == MSG_IPv6_DP) {

            UnicodeSPrint (
              *Description,
              DescriptionSize,
              L"EFI Network (%s)",
              L"IPv6");
          }

        } // if (IsWiFi == TRUE) {
      }
    }
    return TRUE;
  }

#if !(OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  return FALSE;
#else

  //
  // Check if this device is created from PNP expansion header after OPROM
  // shadowed.
  //

  Status = GetBbsEntryByDevicePath (DevicePath, &BbsIndex, &BbsEntry);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if ((Class == PCI_CLASS_SERIAL) && (SubClass == PCI_CLASS_SERIAL_USB)) {
    if (BbsEntry->DeviceType != BBS_EMBED_NETWORK) {
      return FALSE;
    }
  }

  //
  // Construct the description string.
  //

  if (Description != NULL) {
    Status = BuildDescriptionFromBbsEntry (BbsEntry, Description);
  }

  return TRUE;
#endif
} // IsUsbLanDevice

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)


//
// FUNCTION NAME.
//      IsLegacyBevDevice - Is the device path on behalf of legacy BEV.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      legacy BEV device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsLegacyBevDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description
  )
{
  UINT16 BbsIndex;
  SCT_STATUS Status;
  BBS_TABLE *BbsEntry;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;

  DPRINTF_DEV_CHECK ("IsLegacyBevDevice\n");
  if (DevicePath == NULL) {
    return FALSE;
  }

  //
  // Retrieve the last node from the input devicePath.
  //

  LastNode = GetLastDeviceNode (DevicePath);

  if (LastNode == NULL ||
      LastNode->Type != BBS_DEVICE_PATH ||
      LastNode->SubType != BBS_TYPE_BEV) {
    return FALSE;
  }

  //
  // Check if this device is created from PNP expansion header after OPROM
  // shadowed.
  //

  Status = GetBbsEntryByDevicePath (DevicePath, &BbsIndex, &BbsEntry);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Construct the description string.
  //

  if (Description != NULL) {
    Status = BuildDescriptionFromBbsEntry (BbsEntry, Description);
  }

  return TRUE;
} // IsLegacyBevDevice

#endif


//
// FUNCTION NAME.
//      IsUsbHddDevice - Is the device path on behalf of an USB HDD.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      USB HDD device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsUsbHddDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  CHAR16 *TempStr;
  UINT8 DeviceType;
  SCT_STATUS Status;


  DPRINTF_DEV_CHECK ("IsUsbHddDevice\n");

  if (DevicePath == NULL) {
    return FALSE;
  }

  Status = GetUsbDeviceTypeFromDevicePath (DevicePath, &DeviceType);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (DeviceType != BM_USB_MSD_HDD) {
    return FALSE;
  }

  if (Description != NULL) {
    *Description = CreateUsbMsdDescription (DevicePath);
    TempStr = *Description;

    if (TempStr != NULL) {
      SctStrTrim (TempStr, L' ');
    }

    if (*Description == NULL || StrLen (TempStr) == 0) {

      //
      // Create default description for USB HDD MSD.
      //

      SafeFreePool (*Description);
      *Description = (CHAR16 *)AllocateZeroPool (StrSize (L"Generic USB HDD"));
      if (*Description != NULL) {
        StrCpyS (*Description, StrSize (L"Generic USB HDD") / sizeof (CHAR16), L"Generic USB HDD");
      }
    }
  }
  return TRUE;
} // IsUsbHddDevice

//
// FUNCTION NAME.
//      IsUsbFddDevice - Is the device path on behalf of an USB FDD.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      USB floppy device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsUsbFddDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  UINT8 DeviceType;
  SCT_STATUS Status;

  DPRINTF_DEV_CHECK ("IsUsbFddDevice\n");

  if (DevicePath == NULL) {
    return FALSE;
  }

  Status = GetUsbDeviceTypeFromDevicePath (DevicePath, &DeviceType);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (DeviceType != BM_USB_MSD_FDD) {
    return FALSE;
  }

  if (Description != NULL) {
    *Description = CreateUsbMsdDescription (DevicePath);
  }
  return TRUE;
} // IsUsbFddDevice

//
// FUNCTION NAME.
//      IsUsbCdromDevice - Is the device path on behalf of an USB CDROM.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      USB CDROM device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsUsbCdromDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  UINT8 DeviceType;
  SCT_STATUS Status;

  DPRINTF_DEV_CHECK ("IsUsbCdromDevice\n");

  if (DevicePath == NULL) {
    return FALSE;
  }

  Status = GetUsbDeviceTypeFromDevicePath (DevicePath, &DeviceType);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (DeviceType != BM_USB_MSD_CDROM) {
    return FALSE;
  }

  if (Description != NULL) {
    *Description = CreateUsbMsdDescription (DevicePath);
  }

  return TRUE;
} // IsUsbCdromDevice


//
// FUNCTION NAME.
//      IsAtaHddDevice - Is the device path on behalf of an ATA HDD.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      ATA HDD device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsAtaHddDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UINT16 BbsIndex;
  BBS_TABLE *BbsEntry;
#endif
  BOOLEAN Matched;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV_CHECK ("IsAttHddDevice\n");

  if (DevicePath == NULL) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is NULL.\n");
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  //
  // Retrieve the last node from the input devicePath.
  //

  LastNode = GetLastDeviceNode (DevicePath);
  if (LastNode == NULL) {
    return FALSE;
  }

  //
  // *Must* be Messaging Device Path or BBS.
  //

  if (LastNode->Type == MESSAGING_DEVICE_PATH) {

    DPRINTF_DEV_CHECK (" Messaging Device Path: SubType = %d.\n",
      LastNode->SubType);

    if (! (LastNode->SubType == MSG_SATA_DP ||
          LastNode->SubType == MSG_ATAPI_DP)) {
      return FALSE;
    }

#if OPTION_SUPPORT_CSM
  } else if (LastNode->Type == BBS_DEVICE_PATH) {

    DPRINTF_DEV_CHECK (" BBS Device Path; SubType = %d.\n", LastNode->SubType);

    if (LastNode->SubType != BBS_HARDDISK) {
      return FALSE;
    }
#endif
  } else {
    return FALSE;
  }

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (&gEfiDevicePathProtocolGuid, &RemainingDevicePath, &Handle);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (!IsDevicePathEnd (RemainingDevicePath)) {
    return FALSE;
  }

  Matched = FALSE;

  //
  // Get the BlockIo Protocol instance that is installed on this handle.
  //

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiBlockIoProtocolGuid,
                  (VOID **) &BlockIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  Found a BlockIo Handle. ");

    if (BlockIo->Media->RemovableMedia) {
      DPRINTF_DEV_CHECK (" ATAPI CDROM.\n");
      return FALSE;
    }
    DPRINTF_DEV_CHECK ("ATA HDD.\n");

    //
    // Retrieve the device model name from DiskInfo protocol.
    //

    if (Description != NULL) {
      *Description = CreateAtaOrAtapiModelName (DevicePath);
      if (*Description == NULL) {
        *Description = GetDeviceComponentName (DevicePath);
      }
    }
    Matched = TRUE;
  } else {

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

    //
    // Without Block IO protocol.
    // Check if this device is created from OPROM shadowed.
    //

    Status = GetBbsEntryByDevicePath (DevicePath, &BbsIndex, &BbsEntry);
    if (EFI_ERROR (Status)) {
      return FALSE;
    }

    //
    // Check Class code.
    //

    if (BbsEntry->Class != PCI_CLASS_MASS_STORAGE ||
        BbsEntry->DeviceType != BBS_HARDDISK) {
      return FALSE;
    }

    //
    // This device only support legacy boot.
    //

    //
    // Construct the description string.
    //

    if (Description != NULL) {
      Status = BuildDescriptionFromBbsEntry (BbsEntry, Description);
    }
    Matched = TRUE;
#else
    return FALSE;
#endif
  }

  if (Matched && Description != NULL && (*Description) == NULL) {

    *Description = GetDescFromComponentName2 (DevicePath);

    if ((*Description) == NULL) {
      *Description = BopLibConstructDefaultHddDeviceName (DevicePath);
    }
  }

  return Matched;
} // IsAtaHddDevice


//
// FUNCTION NAME.
//      IsAtapiCdromDevice - Is the device path on behalf of an ATA CDROM.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      ATA CDROM device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsAtapiCdromDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UINT16 BbsIndex;
  BBS_TABLE *BbsEntry;
#endif
  UINTN i;
  BOOLEAN Matched;
  BOOLEAN IsRaidCd;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  EFI_HANDLE ParentHandle;
  UINTN NumberBlockIoHandles;
  EFI_HANDLE *BlockIoHandles;
  EFI_HANDLE BlockIoParentHandle;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV_CHECK ("IsAtapiCdromDevice\n");

  Matched = FALSE;
  IsRaidCd = FALSE;

  if (DevicePath == NULL) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is NULL.\n");
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  //
  // Retrieve the last node from the input devicePath.
  //

  LastNode = GetLastDeviceNode (DevicePath);
  if (LastNode == NULL) {
    return FALSE;
  }

  //
  // *Must* be Messaging Device Path or BBS.
  //

  if (LastNode->Type == MESSAGING_DEVICE_PATH) {

    DPRINTF_DEV_CHECK (" Messaging Device Path: SubType = %d.\n",
      LastNode->SubType);

    if (!(LastNode->SubType == MSG_SATA_DP ||
         LastNode->SubType == MSG_ATAPI_DP)) {
      return FALSE;
    }

#if OPTION_SUPPORT_CSM
  } else if (LastNode->Type == BBS_DEVICE_PATH) {

    DPRINTF_DEV_CHECK (" BBS Device Path; SubType = %d.\n", LastNode->SubType);

    if (LastNode->SubType != BBS_CDROM) {
      return FALSE;
    }
#endif
  } else {
    return FALSE;
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
    return FALSE;
  }

  if (!IsDevicePathEnd (RemainingDevicePath)) {
    return FALSE;
  }

  //
  // Get the BlockIo Protocol instance that is installed on this handle.
  //

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiBlockIoProtocolGuid,
                  (VOID **) &BlockIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  Found a BlockIo Handle. ");

    if (!BlockIo->Media->RemovableMedia) {
      DPRINTF_DEV_CHECK (" ATA HDD.\n");
      return FALSE;
    }
    DPRINTF_DEV_CHECK (" ATAPI CDROM.\n");

    Matched = TRUE;
    DPRINTF_DEV_CHECK (" IsRaidCd = %d., Matched=%d\n", IsRaidCd, Matched);

    //
    // Get the DiskInfo protocol for this handle.
    //

    Status = gBS->HandleProtocol (Handle, &gEfiDiskInfoProtocolGuid, (VOID **) &DiskInfo);
    DPRINTF_DEV_CHECK ("DiskIo Status = %r.\n", Status);

    if (EFI_ERROR (Status)) {

      //
      // If Device can't locate DiskIo, check the parent handle. (Raid can't locate DiskIo)
      // If it is already managed by AHCI(That is real Raid CDROM), just skip it.
      // It can fix get 2 BootDevices in BootMenu.
      //

      ParentHandle = NULL;
      RemainingDevicePath = DevicePath;
      Status = gBS->LocateDevicePath (
                                    &gEfiPciIoProtocolGuid,
                                    &RemainingDevicePath,
                                    &ParentHandle);

      DPRINTF_DEV_CHECK ("ParentHandle=0x%x, Status=%r\n", ParentHandle, Status);
      if (EFI_ERROR (Status)) {
        return FALSE;
      }

      //
      // We only compare those devices that EFI_BLOCK_IO_PROTOCOL installed so far.
      //

      Status = gBS->LocateHandleBuffer (
                                      ByProtocol,
                                      &gEfiBlockIoProtocolGuid,
                                      NULL,
                                      &NumberBlockIoHandles,
                                      &BlockIoHandles);
      DPRINTF_DEV_CHECK ("BlockIo Num=0x%x, Status=%r\n", NumberBlockIoHandles, Status);

      if (EFI_ERROR (Status) || NumberBlockIoHandles == 0) {
        NumberBlockIoHandles = 0;
      }

      for (i = 0; i < NumberBlockIoHandles; i++) {
        TempDevicePath = DevicePathFromHandle (BlockIoHandles [i]);

        //
        // Get parent controller to verify if this device is from PCI mass storage.
        //

        BlockIoParentHandle = NULL;
        RemainingDevicePath = TempDevicePath;
        Status = gBS->LocateDevicePath (
                                      &gEfiPciIoProtocolGuid,
                                      &RemainingDevicePath,
                                      &BlockIoParentHandle);

        DPRINTF_DEV_CHECK ("BlockIoParentHandle=0x%x, Status=%r\n", BlockIoParentHandle, Status);
        if (EFI_ERROR (Status)) {
          continue;
        }
        if (BlockIoHandles [i] != Handle) {
          DPRINTF_DEV_CHECK ("BlockIoHandles [i] != Handle=0x%x, BlockIoHandle=0x%x\n", Handle, BlockIoHandles [i]);
          if (BlockIoParentHandle == ParentHandle) {
            DPRINTF_DEV_CHECK ("BlockIoParentHandle == ParentHandle. BlockIoParentHandle=0x%x, ParentHandle=0x%x\n", BlockIoParentHandle, ParentHandle);
            IsRaidCd = TRUE;
          }
        } // if (BlockIoHandles [i] != Handle) {
      } // for (i = 0; i < NumberBlockIoHandles; i++) {
    } else {
      DPRINTF_DEV_CHECK (" Locate DiskIo Success.\n");
    }

    DPRINTF_DEV_CHECK ("IsRaidCd = %d.\n", IsRaidCd);

    if (IsRaidCd == TRUE) {
      Matched = FALSE;
    } else {
      Matched = TRUE;
    }

    if (Description != NULL) {
      *Description = CreateAtaOrAtapiModelName (DevicePath);
      if (*Description == NULL) {
        *Description = AllocateZeroPool (StrSize (DefaultCdRomStr));
        StrCpyS (*Description, StrSize (DefaultCdRomStr) / sizeof (CHAR16), DefaultCdRomStr);
        Matched = TRUE;
      }
    }

  } else {

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

    //
    // Without Block IO protocol.
    // Check if this device is created from OPROM shadowed.
    //

    Status = GetBbsEntryByDevicePath (DevicePath, &BbsIndex, &BbsEntry);
    if (EFI_ERROR (Status)) {
      return FALSE;
    }

    //
    // Check Class code.
    //

    if (BbsEntry->Class != PCI_CLASS_MASS_STORAGE ||
        BbsEntry->DeviceType != BBS_CDROM) {
      return FALSE;
    }

    //
    // This device only support legacy boot.
    //

    //
    // Construct the description string.
    //

    if (Description != NULL) {
      Status = BuildDescriptionFromBbsEntry (BbsEntry, Description);
    }
    Matched = TRUE;
#else
    return FALSE;
#endif
  }

  return Matched;
} // IsAtapiCdromDevice


//
// FUNCTION NAME.
//      IsPciScsiDevice - Is the device path on behalf of a PCI SCSI Device.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      PCI SCSI device.
//
//      A SCSI device can be recognized as a bootable device by OPROM based or
//      EFI_BLOCK_IO_PROTOCOL installed.
//
//      Class code *MUST* be PCI_CLASS_MASS_STORAGE.
//      SubClass code *MUST* be one of below:
//         - PCI_CLASS_MASS_STORAGE_SCSI
//         - PCI_CLASS_MASS_STORAGE_RAID
//         - PCI_CLASS_MASS_STORAGE_OTHER
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsPciScsiDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  UINT8 Class;
  UINT8 SubClass;
  EFI_HANDLE Handle;
  SCT_STATUS Status;
  UINTN StringSize;
  EFI_HANDLE ParentHandle;
  UINT8 ScsiDeviceType;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_SCSI_IO_PROTOCOL *ScsiIo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  BOOLEAN EfiSupported;
  BOOLEAN LegacySupported;
  PCHAR16 Temp;
  PCHAR16 BbsDescription;       SUPPRESS_WARNING_IF_UNUSED (BbsDescription);
  PCHAR16 ComponentName;
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UINT16 BbsIndex;
  BBS_TABLE *BbsEntry;
#endif

  if (DevicePath == NULL) {
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  BbsDescription = NULL;

  //
  // Retrieve the last node from the input devicePath.
  //

  LastNode = GetLastDeviceNode (DevicePath);
  if (LastNode == NULL) {
    return FALSE;
  }

  if ((LastNode->Type != MESSAGING_DEVICE_PATH) &&
      (LastNode->Type != HARDWARE_DEVICE_PATH)) {
    return FALSE;
  }

  if (!(LastNode->SubType == MSG_SCSI_DP ||
    LastNode->SubType == MSG_VENDOR_DP ||
    LastNode->SubType == HW_VENDOR_DP)) {
    return FALSE;
  }

  DPRINTF_DEV_CHECK (" Device path type matched\n");

  //
  // Get parent controller to verify if this device is from PCI mass storage.
  //

  ParentHandle = NULL;
  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &ParentHandle);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Check class code and subClass code.
  //

  Status = GetPciDeviceClassCode (ParentHandle, &Class, &SubClass);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (Class != PCI_CLASS_MASS_STORAGE) {
    return FALSE;
  }

  //
  // SCSI, RAID or SAS controllers.
  //

  if (!(SubClass == PCI_CLASS_MASS_STORAGE_SCSI ||
     SubClass == PCI_CLASS_MASS_STORAGE_RAID ||
     SubClass == PCI_CLASS_MASS_STORAGE_OTHER ||
     SubClass == SCT_PCI_CLASS_MASS_STORAGE_SATA ||
     SubClass == SCT_PCI_CLASS_MASS_STORAGE_SAS)) {
    return FALSE;
  }

  EfiSupported = FALSE;

  //
  // Verify the EFI_BLOCK_IO_PROTOCOL on the handle.
  //

  Handle = NULL;
  RemainingDevicePath = DevicePath;
  ScsiDeviceType = EFI_SCSI_TYPE_UNKNOWN;

  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (!EFI_ERROR (Status)) {

    Status = gBS->OpenProtocol (
                    Handle,
                    &gEfiBlockIoProtocolGuid,
                    NULL,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

    if (!EFI_ERROR (Status)) {
      DPRINTF_DEV_CHECK ("  Block IO found\n");
      EfiSupported = TRUE;

      //
      // Check SCSI device type.
      //

      Status = gBS->HandleProtocol (
                      Handle,
                      &gEfiScsiIoProtocolGuid,
                      (VOID **) &ScsiIo);

      if (!EFI_ERROR (Status)) {
        DPRINTF_DEV_CHECK ("  SCSI IO found\n");
        Status = ScsiIo->GetDeviceType (ScsiIo, &ScsiDeviceType);
      }
    }
  }

  //
  // Construct the default description string.
  //

  if (EfiSupported == TRUE && Description != NULL) {

    if (ScsiDeviceType == EFI_SCSI_TYPE_DISK) {

      *Description = (CHAR16 *)AllocateZeroPool (StrSize (L"SCSI DISK"));
      if (*Description != NULL) {
        StrCpyS (*Description, StrSize (L"SCSI DISK") / sizeof (CHAR16), L"SCSI DISK");
      }

    } else if (ScsiDeviceType == EFI_SCSI_TYPE_CDROM) {

      *Description = (CHAR16 *)AllocateZeroPool (StrSize (L"SCSI DVD/CDROM"));
      if (*Description != NULL) {
        StrCpyS (*Description, StrSize (L"SCSI DVD/CDROM") / sizeof (CHAR16), L"SCSI DVD/CDROM");
      }
    } else {
      DPRINTF_DEV_CHECK ("  EFI_SCSI_TYPE_UNKNOWN\n");
      *Description = (CHAR16 *)AllocateZeroPool (StrSize (L"UEFI Misc Device"));
      if (*Description != NULL) {
        StrCpyS (*Description, StrSize (L"UEFI Misc Device") / sizeof (CHAR16), L"UEFI Misc Device");
      }
    }

    ComponentName = NULL;
    ComponentName = GetDeviceComponentName (DevicePath);
    if (ComponentName != NULL) {

      DPRINTF_DEV_CHECK ("  ComponentName %s\n", ComponentName);

      //
      // Re-build the device description with component name.
      //

      if (*Description != NULL) {
        StringSize = StrSize (*Description) + StrSize (ComponentName);
        Temp = *Description;
        *Description = (CHAR16 *)AllocateZeroPool (StringSize);
        UnicodeSPrint (*Description, StringSize, L"%s-%s", Temp, ComponentName);
        FreePool (Temp);
      } else {
        *Description = (CHAR16 *)AllocateCopyPool (
                                   StrSize (ComponentName),
                                   ComponentName);
      }
      FreePool (ComponentName);
    }

  }

  LegacySupported = FALSE;

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  //
  // Check if this device is created from PNP expansion header after OPROM
  // shadowed.
  //

  BbsEntry = NULL;
  Status = GetBbsEntryByDevicePath (DevicePath, &BbsIndex, &BbsEntry);
  if (!EFI_ERROR (Status)) {
    if ((BbsEntry->Class == PCI_CLASS_MASS_STORAGE) &&
        (BbsEntry->DeviceType == BBS_HARDDISK ||
         BbsEntry->DeviceType == BBS_CDROM)) {
      DPRINTF_DEV_CHECK ("  LegacySupported\n");
      LegacySupported = TRUE;
    }
  }

  //
  // Construct the BBS description string from PnP expansion header.
  //

  BbsDescription = NULL;
  Status = BuildDescriptionFromBbsEntry (BbsEntry, &BbsDescription);

  if (!EFI_ERROR (Status) &&
    Description != NULL &&
    BbsDescription != NULL &&
    LegacySupported) {
    DPRINTF_DEV_CHECK ("  BbsDescription = %s\n", BbsDescription);
    if (EfiSupported == TRUE) {

#if OPTION_SYSTEM_BOOT_MANAGER_USE_BBS_DEVICE_NAME
      SafeFreePool (*Description);
      *Description = BbsDescription;
#endif
    } else {
      *Description = BbsDescription;
    }
  }

#endif

  return (EfiSupported || LegacySupported);
} // IsPciScsiDevice

//
// FUNCTION NAME.
//      IsPciSdCardDevice - Is the device path on behalf of a SD card device.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      PCI SD card device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsPciSdCardDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  SCT_STATUS Status;
  EFI_HANDLE PciHandle;
  EFI_HANDLE DeviceHandle;
  UINT8 Class;
  UINT8 SubClass;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV_CHECK ("IsPciSdCardDevice\n");
  if (DevicePath == NULL) {
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    return FALSE;
  }

  Status = IsPciSdCardDevicePath(DevicePath);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Get the PCI handle to the device that is closest to DevicePath.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &PciHandle);

  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = GetPciDeviceClassCode (PciHandle, &Class, &SubClass);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Check if the Class code and SubClass code.
  //


  if (Class != PCI_CLASS_SYSTEM_PERIPHERAL) {
    return FALSE;
  }

  if (SubClass != PCI_SUBCLASS_SD_HOST_CONTROLLER) {
    return FALSE;
  }

  //
  // Test if SCT_SD_HOST_IO_PROTOCOL installed also to guarantee we support this
  // device.
  //

  Status = gBS->OpenProtocol (
                  PciHandle,
                  &gSctSdHostIoProtocolGuid,
                  NULL,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

  if (EFI_ERROR (Status)) {
    Status = gBS->OpenProtocol (
                    PciHandle,
                    &gSctSdHcIoProtocolGuid,
                    NULL,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

    if (EFI_ERROR (Status)) {

      //
      // Test if gEfiSdHostIoProtocolGuid is installed also to guarantee we support this
      // device.
      //

      Status = gBS->OpenProtocol (
                      PciHandle,
                      &gEfiSdHostIoProtocolGuid,
                      NULL,
                      mImageHandle,
                      NULL,
                      EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
    }

  }

  if (EFI_ERROR (Status)) {

    //
    // Test if gEfiSdMmcPassThruProtocolGuid installed also to guarantee we support this
    // device.
    //

    Status = gBS->OpenProtocol (
                    PciHandle,
                    &gEfiSdMmcPassThruProtocolGuid,
                    NULL,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
    if (EFI_ERROR (Status)) {
      DPRINTF_DEV_CHECK ("  FALSE:Could not open gEfiSdMmcPassThruProtocolGuid Protocol.\n");
      return FALSE;
    }
  }

  if (!EFI_ERROR (Status)) {

    RemainingDevicePath = DevicePath;
    Status = gBS->LocateDevicePath (
                    &gEfiDevicePathProtocolGuid,
                    &RemainingDevicePath,
                    &DeviceHandle);

    if (EFI_ERROR (Status)) {
      return FALSE;
    }

    //
    // Check if this handle has BlockIo installed.
    //

    Status = gBS->OpenProtocol (
                    DeviceHandle,
                    &gEfiBlockIoProtocolGuid,
                    NULL,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

    if (EFI_ERROR (Status)) {
      DPRINTF_DEV_CHECK ("  Device has no BLKIO installed\n");
      return FALSE;
    }

    //
    // Test the LastNode to check if any media is presented.
    // Retrieve the last node from the input devicePath.
    //

    LastNode = GetLastDeviceNode (DevicePath);
    if (LastNode == NULL) {
      return FALSE;
    }

    if (((LastNode->Type != HARDWARE_DEVICE_PATH) ||
         (LastNode->SubType != HW_CONTROLLER_DP)) &&
        ((LastNode->Type != MESSAGING_DEVICE_PATH) ||
         (LastNode->SubType != MSG_SD_DP))) {
      return FALSE;
    }

  }

  //
  // Retrieve the device description string from DiskInfo protocol.
  //

  if (Description != NULL) {
    *Description = CreateAtaOrAtapiModelName (DevicePath);
    if (*Description == NULL) {
      *Description = AllocateZeroPool (StrSize (L"DISK "));
      StrCpyS (*Description, StrSize (L"DISK ") / sizeof (CHAR16), L"DISK ");   // the default string is "DISK".
    }
  }

  return TRUE;
} // IsPciSdCardDevice

//
// FUNCTION NAME.
//      IsPciEmmcCardDevice - Is the device path on behalf of a Emmc card device.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device is created to stand for a
//      PCI Emmc card device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsPciEmmcCardDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  SCT_STATUS Status;
  EFI_HANDLE PciHandle;
  EFI_HANDLE DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV_CHECK ("IsPciEmmcCardDevice\n");
  if (DevicePath == NULL) {
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    return FALSE;
  }

  Status = IsPciEmmcCardDevicePath(DevicePath);

  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Test if gEfiSdMmcPassThruProtocolGuid installed also to guarantee we support this
  // device.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiSdMmcPassThruProtocolGuid,
                  &RemainingDevicePath,
                  &PciHandle);
  if (EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  FALSE:Could not locate gEfiSdMmcPassThruProtocolGuid Protocol.\n");
    return FALSE;
  }

  if (!EFI_ERROR (Status)) {

    RemainingDevicePath = DevicePath;
    Status = gBS->LocateDevicePath (
                    &gEfiDevicePathProtocolGuid,
                    &RemainingDevicePath,
                    &DeviceHandle);

    if (EFI_ERROR (Status)) {
      return FALSE;
    }

    //
    // Check if this handle has BlockIo installed.
    //

    Status = gBS->OpenProtocol (
                    DeviceHandle,
                    &gEfiBlockIoProtocolGuid,
                    NULL,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

    if (EFI_ERROR (Status)) {
      DPRINTF_DEV_CHECK ("  Device has no BLKIO installed\n");
      return FALSE;
    }
    DEBUG ((EFI_D_INFO, "IsPciEmmcCardDevice: BLKIO installed \n"));

    Status = gBS->OpenProtocol (
                    DeviceHandle,
                    &gSctSdMmcBootablePartitionGuid,
                    NULL,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

    if (EFI_ERROR (Status)) {
      DPRINTF_DEV_CHECK ("  Device has no BootablePartition installed\n");
      return FALSE;
    }
    DEBUG ((EFI_D_INFO, "IsPciEmmcCardDevice: BootablePartition installed \n"));

    //
    // Test the LastNode to check if any media is presented.
    // Retrieve the last node from the input devicePath.
    //

    LastNode = GetLastDeviceNode (DevicePath);
    if (LastNode == NULL) {
      return FALSE;
    }

    //
    // If this handle is created for a partition, skip it.
    //

    if (((LastNode->Type != HARDWARE_DEVICE_PATH) ||
         (LastNode->SubType != HW_CONTROLLER_DP)) &&
        ((LastNode->Type != MESSAGING_DEVICE_PATH) ||
         (LastNode->SubType != MSG_EMMC_DP))) {
      return FALSE;
    }

  }

  //
  // Retrieve the device description string from DiskInfo protocol.
  //

  if (Description != NULL) {
    *Description = CreateAtaOrAtapiModelName (DevicePath);
    if (*Description == NULL) {
      *Description = AllocateZeroPool (StrSize (L"DISK "));
      StrCpyS (*Description, StrSize (L"DISK ") / sizeof (CHAR16), L"DISK ");   // the default string is "DISK".
    }
  }

  return TRUE;

} // IsPciEmmcCardDevice


//
// FUNCTION NAME.
//      IsUfsDevice - Is the device path on behalf of a UFS device.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      UFS device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsUfsDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  UINT8 Class;
  UINT8 SubClass;
  EFI_HANDLE Handle;
  SCT_STATUS Status;
  UINTN StringSize;
  EFI_HANDLE ParentHandle;
  UINT8 ScsiDeviceType;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_SCSI_IO_PROTOCOL *ScsiIo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  BOOLEAN EfiSupported;
  PCHAR16 Temp;
  PCHAR16 BbsDescription;       SUPPRESS_WARNING_IF_UNUSED (BbsDescription);
  PCHAR16 ComponentName;
  EFI_DEV_PATH *DevicePathNode;

  DPRINTF_DEV_CHECK ("IsUfsDevice\n");

  if (DevicePath == NULL) {
   return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  BbsDescription = NULL;

  //
  // Retrieve the last node from the input devicePath.
  //

  LastNode = GetLastDeviceNode (DevicePath);
  if (LastNode == NULL) {
    return FALSE;
  }

  if (LastNode->Type != MESSAGING_DEVICE_PATH) {
    return FALSE;
  }

  if (LastNode->SubType != MSG_UFS_DP) {
    return FALSE;
  }

  //
  // Ufs Lun 0
  //

  DevicePathNode = (EFI_DEV_PATH *)LastNode;
  if (DevicePathNode->Ufs.Lun != 0x00) {
    return FALSE;
  }

  DPRINTF_DEV_CHECK (" Device path type matched\n");

  //
  // Get parent controller to verify if this device is from PCI mass storage.
  //

  ParentHandle = NULL;
  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &ParentHandle);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Check class code and subClass code.
  //

  Status = GetPciDeviceClassCode (ParentHandle, &Class, &SubClass);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (Class != PCI_CLASS_MASS_STORAGE) {
    return FALSE;
  }

  //
  // UFS controllers.
  //

  if (!(SubClass == 0x09)) {
    return FALSE;
  }

  EfiSupported = FALSE;

  //
  // Verify the EFI_BLOCK_IO_PROTOCOL on the handle.
  //

  Handle = NULL;
  RemainingDevicePath = DevicePath;
  ScsiDeviceType = EFI_SCSI_TYPE_UNKNOWN;

  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (!EFI_ERROR (Status)) {

    Status = gBS->OpenProtocol (
                    Handle,
                    &gEfiBlockIoProtocolGuid,
                    NULL,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

    if (!EFI_ERROR (Status)) {
      DPRINTF_DEV_CHECK ("  Block IO found\n");
      EfiSupported = TRUE;

      //
      // Check SCSI device type.
      //

      Status = gBS->HandleProtocol (
                      Handle,
                      &gEfiScsiIoProtocolGuid,
                      (VOID **) &ScsiIo);

      if (!EFI_ERROR (Status)) {
        DPRINTF_DEV_CHECK ("  SCSI IO found\n");
        Status = ScsiIo->GetDeviceType (ScsiIo, &ScsiDeviceType);
     }
    }
  }

  if (EfiSupported == FALSE) {
    return FALSE;
  }

  //
  // Construct the default description string.
  //

  if (Description != NULL) {

    if (ScsiDeviceType == EFI_SCSI_TYPE_DISK) {

      *Description = CreateUfsModelName (ParentHandle);

    } else {
      return FALSE;

    }

    ComponentName = NULL;
    ComponentName = GetDeviceComponentName (DevicePath);
    if (ComponentName != NULL) {

      DPRINTF_DEV_CHECK ("  ComponentName %s\n", ComponentName);

      //
      // Re-build the device description with component name.
      //

      if (*Description != NULL) {
        StringSize = StrSize (*Description) + StrSize (ComponentName);
        Temp = *Description;
        *Description = (CHAR16 *)AllocateZeroPool (StringSize);
        UnicodeSPrint (*Description, StringSize, L"%s-%s", Temp, ComponentName);
        FreePool (Temp);
      } else {
        *Description = (CHAR16 *)AllocateCopyPool (
                                   StrSize (ComponentName),
                                   ComponentName);
      }
      FreePool (ComponentName);
    }

  }

  return EfiSupported;

}
//
// FUNCTION NAME.
//      IsNvmeDevice - Is the device path represented a NVMe.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      NVMe device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsNvmeDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description  OPTIONAL
  )
{
  UINTN SegNo;
  UINTN BusNo;
  UINTN DeviceNo;
  UINTN FunNo;
  SCT_STATUS Status;
  EFI_HANDLE DeviceHandle;
  EFI_HANDLE PciHandle;
  EFI_PCI_IO_PROTOCOL *PciIo;
  UINT8 ClassCode [3];
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV_CHECK ("IsNvmeDevice:\n");

  if (DevicePath == NULL) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is NULL.\n");
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  //
  // The last node should be MESSAGING_DEVICE_PATH and the corresponding handle should has
  // EFI_BLOCK_IO_PROTOCOL installed.
  //

  LastNode = NULL;
  LastNode = GetLastDeviceNode (DevicePath);
  if (LastNode == NULL) {
    return FALSE;
  }
  if ( (LastNode->Type == MESSAGING_DEVICE_PATH) &&
       (LastNode->SubType == MSG_NVME_NAMESPACE_DP || LastNode->SubType == MSG_DEVICE_LOGICAL_UNIT_DP ) ) {
    DPRINTF_DEV_CHECK (" DevicePath is could be a NVMe messaging device\n");
  } else {
    DPRINTF_DEV_CHECK (" DevicePath is not a NVMe messaging device\n");
    return FALSE;
  }

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &DeviceHandle);

  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = gBS->OpenProtocol (
                  DeviceHandle,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  Device has no BLKIO installed\n");
    return FALSE;
  }

  //
  // Get the parent handle for this device path and check the class code.
  //
  DEBUG_DEV (
    DPRINTF_DEVICE_PATH ("DevicePath = ", DevicePath);
  );

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &PciHandle);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV_CHECK ("  [Warning]:LocateDevicePath gEfiPciIoProtocolGuid error.\n");
    if (Description != NULL) {
      *Description = CreateNvmeModelName (DevicePath);
      if (*Description == NULL) {
        *Description = GetDeviceComponentName (DevicePath);
      }
      if (*Description == NULL) {
        *Description = AllocateZeroPool (StrSize (CONFIG_NVME_DEVICE_DESCRIPTION));
        UnicodeSPrint (*Description, StrSize (CONFIG_NVME_DEVICE_DESCRIPTION), CONFIG_NVME_DEVICE_DESCRIPTION);
      }
    }
  } else {

    Status = gBS->OpenProtocol (
                    PciHandle,
                    &gEfiPciIoProtocolGuid,
                    (VOID **) &PciIo,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status)) {
      DPRINTF_DEV_CHECK ("  FALSE:Could not open PciIo Protocol.\n");
      return FALSE;
    }
    PciIo->Pci.Read (
                 PciIo,
                 EfiPciIoWidthUint8,
                 PCI_CLASSCODE_OFFSET,
                 sizeof (ClassCode),
                 ClassCode);
    if (
        (
          (ClassCode [0] != 0x02) ||
          (ClassCode [1] != PCI_CLASS_MASS_STORAGE_SOLID_STATE) ||
          (ClassCode [2] != PCI_CLASS_MASS_STORAGE)
        ) && (
          (ClassCode [0] != 0x00) ||
          (ClassCode [1] != PCI_CLASS_MASS_STORAGE_RAID) ||
          (ClassCode [2] != PCI_CLASS_MASS_STORAGE)
        )
    ) {
      return FALSE;
    }
    PciIo->GetLocation (PciIo, &SegNo, &BusNo, &DeviceNo, &FunNo);
    if (Description != NULL) {
      *Description = CreateNvmeModelName (DevicePath);
      if (*Description == NULL) {
        *Description = GetDeviceComponentName (DevicePath);
      }
      if (*Description == NULL) {
        *Description = AllocateZeroPool (256);
        UnicodeSPrint (*Description, 256, L"EFI NVMe Device (%02x:%02x:%02x)", BusNo, DeviceNo, FunNo);
      }
    }
  }
  return TRUE;
} // IsNvmeDevice

//
// FUNCTION NAME.
//      IsHttpDevice - Is the device path represented a http url.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      http url.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
EFIAPI
IsHttpDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description  OPTIONAL
  )
{
  BOOLEAN IsWiFi;
  BOOLEAN IsUsb;
  EFI_HANDLE Handle;
  SCT_STATUS Status;
  UINTN DescriptionSize;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  URI_DEVICE_PATH *UriDevicePath;
  UINTN UriStrLength;

  DPRINTF_DEV_CHECK ("IsHttpDevice:\n");

  if (DevicePath == NULL) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is NULL.\n");
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
    DPRINTF_DEV_CHECK ("  FALSE:DevicePath is End Node.\n");
    return FALSE;
  }

  IsWiFi = FALSE;
  IsUsb = FALSE;
  UriStrLength = 0;

  //
  // Retrieve the last node from the input devicePath.
  //

  LastNode = GetLastDeviceNode (DevicePath);
  if (LastNode == NULL) {
    return FALSE;
  }

  //
  // Must support URI device path.
  //

  if (LastNode->Type == MESSAGING_DEVICE_PATH) {
    DPRINTF_DEV_CHECK (" Messaging Device Path: SubType = 0x%x.\n", LastNode->SubType);

    if (LastNode->SubType != MSG_URI_DP) {
      return FALSE;
    } else {

      if (Description != NULL) {

        UriDevicePath = (URI_DEVICE_PATH*) LastNode;
        UriStrLength = DevicePathNodeLength (UriDevicePath) - sizeof(EFI_DEVICE_PATH_PROTOCOL);

        //
        // If the Description is not NULL, then it means the BDS might need to create the new Boot####
        // for it, but since the Http boot devicepath might have been updated because of the previous
        // http boot attempt (either success or fail), the URI node will be replaced by either the DHCP
        // or user specify URI.  So in order not to create the duplicate Boot#### for http boot during
        // BDS process, if the URI is not empty and caller pass-in the Description, then always return
        // FALSE to avoid BDS create duplicate Boot####.
        //

        if (UriStrLength != 0) {
          return FALSE;
        }
      }
    }
  } else {
    return FALSE;
  }

  //
  // Test EFI_SIMPLE_NETWORK_PROTOCOL first.
  //

  RemainingDevicePath = DevicePath;
  Handle = NULL;
  Status = gBS->LocateDevicePath (
                  &gEfiSimpleNetworkProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  DPRINTF_DEV_CHECK (" Locate EFI_SIMPLE_NETWORK_PROTOCOL (%r)\n", Status);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  RemainingDevicePath = DevicePath;
  Handle = NULL;

  //
  // Must support EFI_LOAD_FILE_PROTOCOL.
  //

  Status = gBS->LocateDevicePath (
                  &gEfiLoadFileProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  DPRINTF_DEV_CHECK (" Locate EFI_LOAD_FILE_PROTOCOL (%r)\n", Status);

  //
  // Must be totally matched.
  //

  if (!EFI_ERROR (Status) && IsDevicePathEnd (RemainingDevicePath)) {
    DPRINTF_DEV_CHECK (" return TRUE\n");

    if (Description != NULL) {

      TempDevicePath = DevicePath;
      while (!IsDevicePathEnd (TempDevicePath)) {

        //
        // Find the Wi-Fi node
        //

        if ((DevicePathType (TempDevicePath) == MESSAGING_DEVICE_PATH) &&
          (DevicePathSubType (TempDevicePath) == MSG_WIFI_DP)) {
          IsWiFi = TRUE;
          break;
        }

        //
        // Find the USB node.
        //

        if ((DevicePathType (TempDevicePath) == MESSAGING_DEVICE_PATH) &&
          (DevicePathSubType (TempDevicePath) == MSG_USB_DP)) {
          IsUsb = TRUE;
          break;
        }

        TempDevicePath = NextDevicePathNode (TempDevicePath);
      } // While

      if (IsWiFi == TRUE) {
        DescriptionSize = StrSize (L"EFI Network (Wi-Fi)(IPvX)");
      } else if (IsUsb == TRUE) {
        DescriptionSize = StrSize (L"EFI Network (USB)(IPvX)");
      } else {
        DescriptionSize = StrSize (L"EFI Network (IPvX)");
      }
      *Description = (PCHAR16)AllocateZeroPool (DescriptionSize);

      TempDevicePath = DevicePath;
      while (!IsDevicePathEnd (TempDevicePath)) {

        //
        // Find the URI node
        //

        if (DevicePathType (TempDevicePath) == MESSAGING_DEVICE_PATH) {
          if (IsWiFi == TRUE) {
            if (DevicePathSubType (TempDevicePath) == MSG_IPv4_DP) {

              UnicodeSPrint (
                *Description,
                DescriptionSize,
                L"EFI Network (Wi-Fi)(%s)",
                L"IPv4");

              break;
            } else if (DevicePathSubType (TempDevicePath) == MSG_IPv6_DP) {

              UnicodeSPrint (
                *Description,
                DescriptionSize,
                L"EFI Network (Wi-Fi)(%s)",
                L"IPv6");

              break;
            }
          } else if (IsUsb == TRUE) {
            if (DevicePathSubType (TempDevicePath) == MSG_IPv4_DP) {

              UnicodeSPrint (
                *Description,
                DescriptionSize,
                L"EFI Network (USB)(%s)",
                L"IPv4");

              break;
            } else if (DevicePathSubType (TempDevicePath) == MSG_IPv6_DP) {

              UnicodeSPrint (
                *Description,
                DescriptionSize,
                L"EFI Network (USB)(%s)",
                L"IPv6");

              break;
            }
          } else {
            if (DevicePathSubType (TempDevicePath) == MSG_IPv4_DP) {

              UnicodeSPrint (
                *Description,
                DescriptionSize,
                L"EFI Network (%s)",
                L"IPv4");

              break;
            } else if (DevicePathSubType (TempDevicePath) == MSG_IPv6_DP) {

              UnicodeSPrint (
                *Description,
                DescriptionSize,
                L"EFI Network (%s)",
                L"IPv6");

              break;
            }
          }
        }

        TempDevicePath = NextDevicePathNode (TempDevicePath);
      } // While
    }

    return TRUE;
  }

  DPRINTF_DEV_CHECK (" return FALSE\n");
  return FALSE;
} // IsHttpDevice

//
// FUNCTION NAME.
//      IsNonRemovableMediaBootableDevices - Is device bootable with non-removable media.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path is created to stand for a
//      bootable device.
//
//      With LOAD_FILE_PROTOCOL or EFI_SIMPLE_FILE_SYSTEM_PROTOCOL attached but
//      not a removable device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Description     - Pointer points to description string.
//

BOOLEAN
IsNonRemovableMediaBootableDevices (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PCHAR16 *Description OPTIONAL
  )
{
  BOOLEAN Ret;
  PCHAR16 Str;
  UINTN StringLength;
  UINTN MaxDisplay;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV_CHECK ("IsNonRemovableMediaBootableDevices\n");
  if (DevicePath == NULL) {
    return FALSE;
  }

  *Description = NULL;
  Ret = FALSE;
  MaxDisplay = 28;

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Need to match full device path.
  //

  if (!IsDevicePathEnd (RemainingDevicePath)) {
    return FALSE;
  }

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiBlockIoProtocolGuid,
                  (VOID **) &BlockIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    if (BlockIo->Media->RemovableMedia) {
      return FALSE;
    }
  }

  //
  // Check if EFI_SIMPLE_FILE_SYSTEM_PROTOCOL and EFI_LOAD_FILE_PROTOCOL
  // attached.
  //

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiLoadFileProtocolGuid,
                  NULL,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    Ret = TRUE;
  }

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    Ret = TRUE;
  }

  if (Description != NULL) {

    //
    // Build the description string for this device.
    //

    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);

    if (Str != NULL) {
      StringLength = StrLen (Str);
      *Description = AllocateZeroPool (MaxDisplay * sizeof (CHAR16));

      if (*Description != NULL) {
        if (StringLength < MaxDisplay) {

          StrCpyS (*Description, MaxDisplay, Str);
        } else {

          //
          // Description string will be [xxxxxxxxxxxx...].
          //

          StrnCatS (*Description, MaxDisplay, Str, (MaxDisplay - 4));
          StrCatS (*Description, MaxDisplay, L"...");
        }
      }

      SafeFreePool (Str);
    }
  }
  return Ret;
} // IsNonRemovableMediaBootableDevices


#if OPTION_SYSTEM_CONNECT_USB_HC_BY_SPEED || \
    OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND
//
// FUNCTION NAME.
//      ConnectAllUsbHostController - Connect all USB Host Controllers.
//
// FUNCTIONAL DESCRIPTION.
//      This function will connect each USB host controller in the list.
//      The device paths of USB host controllers needs to be well pre-defined by
//      platform owner.
//
//      EHCI Host controller learns device speed. If device is low/full speed and
//      the hub is an EHCI root hub, the port will be released to its companion
//      controllers.
//
//      To reduce the redundant time, platform needs to prepare the proper
//      connectList in the following order: XHCI->EHCI->UHCI/OHCI.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConnectAllUsbHostController (VOID)
{
  SCT_STATUS Status;
  EFI_PCI_IO_PROTOCOL *PciIo;
  USB_CLASSC UsbClassCReg;
  UINTN NumberOfHandles;
  EFI_HANDLE *HandleBuffer;
  UINTN UsbIndex;
  UINT16 HandleIndex;
  UINT16 UsbIP[] = {PCI_IF_XHCI,
                    PCI_IF_EHCI,
                    PCI_IF_OHCI,
                                    PCI_IF_UHCI};

  DPRINTF_DEV ("ConnectAllUsbHostController:\n");

  //
  // Connect first layer of PCI device.
  //

  ConnectAllPciDevices ();

  Status = gBS->LocateHandleBuffer (
                ByProtocol,
                &gEfiPciIoProtocolGuid,
                NULL,
                &NumberOfHandles,
                &HandleBuffer);

  //
  // Connect USB device path according to its type, the ordering is:
  // 1.XHCI 2.EHCI 3.OHCI 4.UHCI
  //

  for (UsbIndex = 0; UsbIndex < sizeof (UsbIP)/sizeof (UINT16); UsbIndex++) {

        HandleIndex = 0;
    while (HandleIndex < NumberOfHandles) {
      Status = gBS->HandleProtocol (
                      HandleBuffer [HandleIndex],
                      &gEfiPciIoProtocolGuid,
                      (VOID **) &PciIo);
      if (EFI_ERROR (Status)) {
        HandleIndex++;
            continue;
      }

      Status = PciIo->Pci.Read (
                        PciIo,
                        EfiPciIoWidthUint8,
                        PCI_CLASSCODE_OFFSET,
                        sizeof (USB_CLASSC) / sizeof (UINT8),
                        &UsbClassCReg);
      if (EFI_ERROR (Status)) {
        HandleIndex++;
            continue;
      }

      //
      // Test whether the controller belongs to USB type.
      //

      if ((UsbClassCReg.BaseCode == PCI_CLASS_SERIAL) &&
          (UsbClassCReg.SubClassCode == PCI_CLASS_SERIAL_USB) &&
          (UsbClassCReg.PI == UsbIP[UsbIndex])) {

          DPRINTF_DEV (" Handle 0x%x belongs to %x Type USB device Path.\n",
                   HandleBuffer [HandleIndex], UsbIP[UsbIndex]);
          Status = gBS->ConnectController (
                          HandleBuffer [HandleIndex],
                          mContextOverrideDriver,
                          NULL,
                          TRUE);
          if (!EFI_ERROR(Status)) {
            DPRINTF_DEV ("  Connection success.\n");
          }
          }

      HandleIndex++;
    }
  }

  SafeFreePool (HandleBuffer);

  return SCT_STATUS_SUCCESS;
} // ConnectAllUsbHostController

#endif // (OPTION_SYSTEM_CONNECT_USB_HC_BY_SPEED)


//
// FUNCTION NAME.
//      GetUsbHcProperStallTime - Get the proper stall time for USB HC.
//
// FUNCTIONAL DESCRIPTION.
//      This function will calculate the proper stall time (millisecond) for USB HC.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Milliseconds    - Milliseconds to stall.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
GetUsbHcProperStallTime (OUT PUINT16 Milliseconds)
{
  UINTN i;
  UINT16 StallTime;
  SCT_STATUS Status;
  EFI_HANDLE *UsbHcHandles;
  UINTN UsbHcHandlesCount;
  EFI_USB2_HC_PROTOCOL *Usb2Hc;

  //
  // Initialize local variables.
  //

  Usb2Hc = NULL;
  StallTime = 0;
  *Milliseconds = 0;
  UsbHcHandles = NULL;
  UsbHcHandlesCount = 0;

  DPRINTF_DEV ("CalculateUsbHostControllerStall:\n");

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiUsb2HcProtocolGuid,
                  NULL,
                  &UsbHcHandlesCount,
                  &UsbHcHandles);
  if (EFI_ERROR (Status)) {
    UsbHcHandles = NULL;
    UsbHcHandlesCount = 0;
    return SCT_STATUS_NOT_FOUND;
  }


  if (mUsbHcCount == UsbHcHandlesCount) {
    return EFI_SUCCESS;
  }

  mUsbHcCount = UsbHcHandlesCount;

  for (i = 0; i < UsbHcHandlesCount; i++) {
    Usb2Hc = NULL;
    Status = gBS->OpenProtocol (
                    UsbHcHandles [i],
                    &gEfiUsb2HcProtocolGuid,
                    (VOID **) &Usb2Hc,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status) || Usb2Hc == NULL) {
      continue;
    }

    switch (Usb2Hc->MajorRevision) {
      case 0:
        StallTime = CONFIG_SYSTEM_BOOT_MANAGER_USB_HC_STALL_REV0;
        break;

      case 1:
        StallTime = CONFIG_SYSTEM_BOOT_MANAGER_USB_HC_STALL_REV1;
        break;

      //
      // EHCI Host Controller.
      //

      case 2:
        StallTime = CONFIG_SYSTEM_BOOT_MANAGER_USB_HC_STALL_REV2;
        break;

      //
      // XHCI Host Controller.
      //

      case 3:
        StallTime = CONFIG_SYSTEM_BOOT_MANAGER_USB_HC_STALL_REV3;
        break;

      default:
        StallTime = CONFIG_SYSTEM_BOOT_MANAGER_USB_HC_STALL_DEFAULT;
    }

    if (StallTime >= *Milliseconds) {
      *Milliseconds = StallTime;
    }
  }

  //
  // Finally, freed the resource.
  //

  SafeFreePool (UsbHcHandles);

  return SCT_STATUS_SUCCESS;

} // GetUsbHcProperStallTime

//#if OPTION_CSM_OPTION_OUT

//
// FUNCTION NAME.
//      PrepareContextOverrideDriver - Prepare the ordered image handles for Context Override.
//
// FUNCTIONAL DESCRIPTION.
//      This function will prepare the an ordered image handles list for ConnectController.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
PrepareContextOverrideDriver (VOID)
{
  SCT_STATUS Status;
  UINTN NumberOfHandles;
  EFI_HANDLE *HandleBuffer;

  HandleBuffer = NULL;
  NumberOfHandles = 0;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctVgaOverrideGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer);
  if (EFI_ERROR (Status)) {

    //
    // If there is no gSctVgaOverrideGuid, maybe code is not sync.
    // So do original behavior.
    //

    HandleBuffer = NULL;
    NumberOfHandles = 0;
    Status = gBS->LocateHandleBuffer (
                    ByProtocol,
                    &gEfiLegacyBiosGuid,
                    NULL,
                    &NumberOfHandles,
                    &HandleBuffer);

    if (EFI_ERROR (Status)) {
      return EFI_NOT_FOUND;
    }
  }

  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  sizeof (EFI_HANDLE) * (NumberOfHandles + 1),
                  (VOID **)&mContextOverrideDriver);

  if (!EFI_ERROR (Status)) {
    CopyMem (
      mContextOverrideDriver,
      HandleBuffer,
      sizeof (EFI_HANDLE) * NumberOfHandles);
    mContextOverrideDriver [NumberOfHandles] = NULL;
  }

  SafeFreePool (HandleBuffer);

  return Status;

} // PrepareContextOverrideDriver


//
// FUNCTION NAME.
//      FreeContextOverrideDriver - Free the resource allocated by PrepareContextOverrideDriver.
//
// FUNCTIONAL DESCRIPTION.
//      This function will release the resource of Context Override driver image handles.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
FreeContextOverrideDriver (VOID)
{

  SafeFreePool (mContextOverrideDriver);
  mContextOverrideDriver = NULL;
  return EFI_SUCCESS;

} // FreeContextOverrideDriver

//#endif // OPTION_CSM_OPTION_OUT


//
// FUNCTION NAME.
//      PrepareContextOverrideDriverForEssential - Prepare the ordered essential image handles for Context Override.
//
// FUNCTIONAL DESCRIPTION.
//      This function will prepare the an ordered image handles list for ConnectController.
//      This ordered image handles list is provided for the mEssentialConnectList. If there
//      is any driver that needs the context override connection policy, please add its image
//      handle into this function.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
PrepareContextOverrideDriverForEssential (VOID)
{
  SCT_STATUS Status;
  UINTN NumberOfHandles;
  UINTN NewNumberOfHandles;
  EFI_HANDLE *HandleBuffer;
  UINTN OriginalNumberOfHandles;
  EFI_HANDLE *ContextOverrideDriverTemp;

  HandleBuffer = NULL;
  NumberOfHandles = 0;
  OriginalNumberOfHandles = 0;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctAhciBusGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer);
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  if (mContextOverrideDriver != NULL) {

    while (mContextOverrideDriver [OriginalNumberOfHandles] != NULL) {
      OriginalNumberOfHandles ++;
    }

    NewNumberOfHandles = OriginalNumberOfHandles + NumberOfHandles;

    Status = (gBS->AllocatePool) (
                    EfiBootServicesData,
                    sizeof (EFI_HANDLE) * (NewNumberOfHandles + 1),
                    (VOID **)&ContextOverrideDriverTemp);

    if (!EFI_ERROR (Status)) {
      CopyMem (
        ContextOverrideDriverTemp,
        mContextOverrideDriver,
        sizeof (EFI_HANDLE) * OriginalNumberOfHandles);

      CopyMem (
        &ContextOverrideDriverTemp [OriginalNumberOfHandles],
        HandleBuffer,
        sizeof (EFI_HANDLE) * NumberOfHandles);
      ContextOverrideDriverTemp [NewNumberOfHandles] = NULL;
    }

    SafeFreePool (mContextOverrideDriver);
    mContextOverrideDriver = ContextOverrideDriverTemp;

  } else {

    Status = (gBS->AllocatePool) (
                    EfiBootServicesData,
                    sizeof (EFI_HANDLE) * (NumberOfHandles + 1),
                    (VOID **)&mContextOverrideDriver);

    if (!EFI_ERROR (Status)) {
      CopyMem (
        mContextOverrideDriver,
        HandleBuffer,
        sizeof (EFI_HANDLE) * NumberOfHandles);
      mContextOverrideDriver [NumberOfHandles] = NULL;
    }

  }

  SafeFreePool (HandleBuffer);

  return Status;

} // PrepareContextOverrideDriverForEssential


//
// FUNCTION NAME.
//      IsUsbSuperSpeedHubPresent - Is USB super speed HUB present in the system.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if there is any super speed USB HUB present in the
//      system now.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN.
//

BOOLEAN
IsSuperSpeedUsbHubPresent (VOID)
{
  UINTN i;
  SCT_STATUS Status;
  UINTN HandleCount;
  BOOLEAN IsUsb_3_0_Hub;
  EFI_HANDLE *HandleBuffer;
  EFI_USB_IO_PROTOCOL *UsbIo;
  EFI_USB_DEVICE_DESCRIPTOR UsbDeviceDescriptor;
  EFI_USB_INTERFACE_DESCRIPTOR UsbInterfaceDescriptor;

  IsUsb_3_0_Hub = FALSE;
  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiUsbIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  if (EFI_ERROR (Status) || HandleCount == 0) {
    return FALSE;
  }

  for (i = 0 ; i < HandleCount; i++) {

    //
    // Get the UsbIo protocol instance for this handle.
    //

    Status = gBS->OpenProtocol(
                    HandleBuffer [i],
                    &gEfiUsbIoProtocolGuid,
                    (VOID **) &UsbIo,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status) || UsbIo == NULL) {
      continue;
    }

    //
    // Get the USB Device Descriptor.
    //

    Status = UsbIo->UsbGetDeviceDescriptor (UsbIo, &UsbDeviceDescriptor);
    if (EFI_ERROR (Status)) {
      continue;
    }

    //
    // Get the USB Interface Descriptor.
    //

    Status = UsbIo->UsbGetInterfaceDescriptor (UsbIo, &UsbInterfaceDescriptor);
    if (EFI_ERROR (Status)) {
      continue;
    }

    DPRINTF_DEV ("USB IO Found\n\n");
    DPRINTF_DEV ("  InterfaceClass = 0x%x\n", UsbInterfaceDescriptor.InterfaceClass);
    DPRINTF_DEV ("  MaxPacketSize0 = 0x%x\n", UsbDeviceDescriptor.MaxPacketSize0);
    DPRINTF_DEV ("  DeviceClass    = 0x%x\n", UsbDeviceDescriptor.DeviceClass);
    DPRINTF_DEV ("  DeviceProtocol = 0x%x\n", UsbDeviceDescriptor.DeviceProtocol);

    if (UsbInterfaceDescriptor.InterfaceClass == 0x09 &&
      UsbDeviceDescriptor.MaxPacketSize0 == 0x09 &&
      UsbDeviceDescriptor.DeviceProtocol == 0x03) {
      IsUsb_3_0_Hub = TRUE;
      break;
    }
  }

  //
  // Freed the allocated resources.
  //

  SafeFreePool (HandleBuffer);
  return IsUsb_3_0_Hub;
} // IsSuperSpeedUsbHubPresent


//
// FUNCTION NAME.
//      GetPciDeviceClassCode - Get class and subclass code of a PCI device.
//
// FUNCTIONAL DESCRIPTION.
//      This function will read the PCI configuration space to get class and
//      subClass code.
//
// ENTRY PARAMETERS.
//      PciHandle       - PCI controller.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//      ClassCode       - class code.
//      SubClassCode    - subClass code.
//

EFI_STATUS
EFIAPI
GetPciDeviceClassCode (
  IN EFI_HANDLE *PciHandle,
  OUT UINT8 *ClassCode,
  OUT UINT8 *SubClassCode
  )
{
  EFI_STATUS Status;
  UINT16 Data;
  EFI_PCI_IO_PROTOCOL *PciIo;

  if (PciHandle == NULL || ClassCode == NULL || SubClassCode == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->OpenProtocol (
                  PciHandle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **)&PciIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint16, 0x0a, 2, &Data);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DPRINTF_DEV_CHECK ("  Class = 0x%x.\n", ((UINT8 *)&Data) [1]);
  DPRINTF_DEV_CHECK ("  SubClass = 0x%x.\n", ((UINT8 *)&Data) [0]);

  *ClassCode = ((UINT8 *)&Data) [1];
  *SubClassCode = ((UINT8 *)&Data) [0];

  return EFI_SUCCESS;

} // GetPciDeviceClassCode

//
// FUNCTION NAME.
//      GetUsbMsdDeviceType - Get USB device type.
//
// FUNCTIONAL DESCRIPTION.
//      Get USB device type and return corresponding BBS device type.
//
// ENTRY PARAMETERS.
//      UsbMsdHandle      - USB mass storage handle.
//
// EXIT PARAMETERS.
//      Function Return - USB device type.
//

UINT8
EFIAPI
GetUsbMsdDeviceType (
  IN EFI_HANDLE UsbMsdHandle
  )
{
  EFI_STATUS Status;
  UINT8 DeviceType;
  UINT32 InfoSize;
  EFI_HANDLE ParentDevice;
  USB_MASS_INQUIRY_DATA Info;
  EFI_USB_IO_PROTOCOL *UsbIo;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  EFI_USB_INTERFACE_DESCRIPTOR UsbInterfaceDesc;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_DEV ("\n");
  if (UsbMsdHandle == NULL) {
    return BM_USB_MSD_UNKNOWN;
  }

  Status = gBS->OpenProtocol (
                  UsbMsdHandle,
                  &gEfiBlockIoProtocolGuid,
                  (VOID **)&BlockIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Fail to get BLOCK_IO\n");
    return BM_USB_MSD_UNKNOWN;
  }

  Status = gBS->OpenProtocol (
                  UsbMsdHandle,
                  &gEfiDiskInfoProtocolGuid,
                  (VOID **)&DiskInfo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Fail to get Disk_Info\n");
    return BM_USB_MSD_UNKNOWN;
  }

  //
  // Get USB_IO to retrieve interface descriptor.
  //

  UsbIo = NULL;
  Status = gBS->OpenProtocol (
                  UsbMsdHandle,
                  &gEfiUsbIoProtocolGuid,
                  (VOID **)&UsbIo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Fail to get USB_IO\n");

    //
    // This device might be a child of target USB MSD, try to get parent's USB_IO.
    //

    DevicePath = NULL;
    ParentDevice = NULL;
    DevicePath = DevicePathFromHandle (UsbMsdHandle);
    RemainingDevicePath = DevicePath;

    DPRINTF_DEV ("  Try to get parent's USB_IO\n");

    Status = gBS->LocateDevicePath (
                    &gEfiUsbIoProtocolGuid,
                    &RemainingDevicePath,
                    &ParentDevice);

    if (!EFI_ERROR (Status)) {
      Status = gBS->OpenProtocol (
                      ParentDevice,
                      &gEfiUsbIoProtocolGuid,
                      (VOID **)&UsbIo,
                      mImageHandle,
                      NULL,
                      EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    }
  }

  if (EFI_ERROR (Status) || UsbIo == NULL) {
    return BM_USB_MSD_UNKNOWN;
  }
  Status = UsbIo->UsbGetInterfaceDescriptor (UsbIo, &UsbInterfaceDesc);
  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Fail to get interface descriptor\n");
    return BM_USB_MSD_UNKNOWN;
  }

  //
  // Check if the interface class is USB_MASS_STORE_CLASS.
  //

  if (UsbInterfaceDesc.InterfaceClass != 0x08) {
    return BM_USB_MSD_UNKNOWN;
  }

  InfoSize = sizeof (USB_MASS_INQUIRY_DATA);
  Status = DiskInfo->Inquiry (DiskInfo, &Info, &InfoSize);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Fail to Inquiry data\n");
    return BM_USB_MSD_UNKNOWN;
  }

  if ((Info.Pdt == USB_PDT_DIRECT_ACCESS) &&
      (UsbInterfaceDesc.InterfaceSubClass == USB_MASS_STORE_UFI)) {
    DPRINTF_DEV ("  FLOPPY because of the interface.\n");

    DeviceType = BM_USB_MSD_FDD;
  } else if (Info.Pdt == USB_PDT_CDROM) {
    DPRINTF_DEV ("  CDROM because Peripheral Device Type is USB_PDT_CDROM\n");
    DeviceType = BM_USB_MSD_CDROM;

  } else {
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
    if (IsDeviceInFddEmulationMode (BlockIo)) {
      DPRINTF_DEV ("  Floppy because it is in emulation mode.\n");
      DeviceType = BM_USB_MSD_FDD;
    } else {
      DPRINTF_DEV ("  Hdd because it is nothing else.\n");
      DeviceType = BM_USB_MSD_HDD;
    }
#else  // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
    DPRINTF_DEV ("  Hdd because it is nothing else.\n");
    DeviceType = BM_USB_MSD_HDD;
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  }

  return DeviceType;
} // GetUsbMsdDeviceType

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
EFIAPI
GetUsbMsdDeviceName (
  IN EFI_HANDLE UsbHandle,
  OUT CHAR16 **UsbDeviceName
  )
{
  EFI_STATUS Status;
  UINT32 InfoSize;
  CHAR8 DeviceName [USB_MSD_DEVICE_LEN + 1];
  CHAR8 VendorId [USB_VENDOR_ID_LEN + 1];
  CHAR8 ProductId [USB_PRODUCT_ID_LEN + 1];
  USB_MASS_INQUIRY_DATA Info;
  EFI_DISK_INFO_PROTOCOL *DiskInfo;

  if (UsbDeviceName == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *UsbDeviceName = NULL;

  Status = gBS->OpenProtocol (
                  UsbHandle,
                  &gEfiDiskInfoProtocolGuid,
                  (VOID **)&DiskInfo,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Fail to get Disk_Info\n");
    return Status;
  }

  InfoSize = sizeof (USB_MASS_INQUIRY_DATA);
  Status = DiskInfo->Inquiry (DiskInfo, &Info, &InfoSize);

  if (EFI_ERROR (Status)) {
    DPRINTF_DEV ("  Fail to Inquiry data\n");
    return Status;
  }

  //
  // Copy Vendor ID.
  //

  CopyMem (VendorId, Info.VendorID, USB_VENDOR_ID_LEN);
  VendorId [USB_VENDOR_ID_LEN] = '\0';
  DPRINTF_DEV ("  Vendor ID = %a\n", VendorId);
  BmAsciiStrTrim (VendorId, ' ');

  //
  // Copy Product ID.
  //

  CopyMem (ProductId, Info.ProductID, USB_PRODUCT_ID_LEN);
  ProductId [USB_PRODUCT_ID_LEN] = '\0';
  DPRINTF_DEV ("  Product ID = %a\n", ProductId);
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

  DPRINTF_DEV ("  DeviceName = %a\n", DeviceName);

  //
  // Convert to Unicode string.
  //

  *UsbDeviceName = (CHAR16 *)AllocateZeroPool (sizeof (CHAR16) * (USB_MSD_DEVICE_LEN + 1));
  AsciiStrToUnicodeStrS (DeviceName, *UsbDeviceName, (USB_MSD_DEVICE_LEN + 1));

  DPRINTF_DEV ("  USB Device Name = %s\n", *UsbDeviceName);
  return EFI_SUCCESS;
} // GetUsbMsdDeviceName

//
// FUNCTION NAME.
//      GetUsbDeviceTypeFromDevicePath - Get the device type.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes a device path determines the type of the USB device
//      that the device path represents.
//
//      This function locates the handle with this device path, then opens the
//      Block IO Protocol on that handle. From this protocol this function
//      rewinds to the private data of our Usb Mass Storage driver to determine
//      the device type.
//
//      This function also checks the last node of the device path to make
//      sure that this is a USB device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path for the device type to boot.
//      DeviceType      - BBS device node type.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
GetUsbDeviceTypeFromDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PUINT8 DeviceType
  )
{
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UINT8 UsbDeviceType;
  UINTN DevicePathBootType;
#endif

  DPRINTF_DEV ("\n");

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  DevicePathBootType = GetBootTypeFromDevicePath (DevicePath);

  if (DevicePathBootType != BDS_EFI_MESSAGE_USB_DEVICE_BOOT) {
    DPRINTF_DEV ("  The device path is not a bootable USB device path .\n");
    return SCT_STATUS_NOT_FOUND;
  }
#endif

  //
  // Get the Handle for this device path.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &Handle);

  if (EFI_ERROR (Status)) {
    return SCT_STATUS_NOT_FOUND;
  }

  if (!IsDevicePathEnd (RemainingDevicePath)) {
    return SCT_STATUS_NOT_FOUND;
  }

  //
  // Get the BlockIo protocol for this handle.
  //

  Status = gBS->HandleProtocol (Handle, &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
  DPRINTF_DEV ("  Get BlockIo protocol %r\n", Status);
  if (EFI_ERROR (Status)) {
    DUMP_ALL_PROTOCOLS (Handle);
    return SCT_STATUS_NOT_FOUND;
  }

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UsbDeviceType = GetUsbBbsDeviceType (BlockIo);

  if (UsbDeviceType == BBS_FLOPPY) {
    *DeviceType = BM_USB_MSD_FDD;
  } else if (UsbDeviceType == BBS_HARDDISK) {
    *DeviceType = BM_USB_MSD_HDD;
  } else if (UsbDeviceType == BBS_CDROM) {
    *DeviceType = BM_USB_MSD_CDROM;
  } else {
    *DeviceType = BM_USB_MSD_UNKNOWN;
    Status = EFI_UNSUPPORTED;
  }
#else //OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  *DeviceType = GetUsbMsdDeviceType (Handle);
#endif //OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  return Status;
} // GetUsbDeviceTypeFromDevicePath

//
// FUNCTION NAME.
//      IsFvFileExist - Test if a specific FV file is existent in one firmware volume.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if a FV file resides in a specific firmware volume.
//
// ENTRY PARAMETERS.
//      FvHandle        - Handle of firmware volume.
//      FileName        - Name of FV file.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN.
//

BOOLEAN
IsFvFileExist (
  IN EFI_HANDLE FvHandle,
  IN EFI_GUID *FileName
  )
{
  VOID *Buffer;
  UINTN Size;
  EFI_STATUS Status;
  EFI_FV_FILETYPE FileType;
  EFI_FV_FILE_ATTRIBUTES Attributes;
  UINT32 AuthenticationStatus;
  EFI_FIRMWARE_VOLUME2_PROTOCOL *FirmwareVolume;


  DPRINTF_DEV ("IsFvFileExist:\n");
  Buffer = NULL;
  Size = 0;

  if (FvHandle == NULL || FileName == NULL) {
    return FALSE;
  }

  Status = gBS->HandleProtocol (
                  FvHandle,
                  &gEfiFirmwareVolume2ProtocolGuid,
                  (VOID **) &FirmwareVolume);

  if (EFI_ERROR (Status)) {
    return FALSE;
  }
  Status = FirmwareVolume->ReadFile (
                             FirmwareVolume,
                             FileName,
                             &Buffer,
                             &Size,
                             &FileType,
                             &Attributes,
                             &AuthenticationStatus);

  if (!EFI_ERROR (Status) && Size > 0) {
    return TRUE;
  }

  return FALSE;
} // IsFvFileExist

//
// FUNCTION NAME.
//      FindOptionalFvHandle - Find target firmware volume handle of specific FV file.
//
// FUNCTIONAL DESCRIPTION.
//      This function will search each firmware volume to find the target firmware volume handle which contain
//      the input FV file.
//
// ENTRY PARAMETERS.
//      FileName        - Name of the FV file to be found.
//
// EXIT PARAMETERS.
//      TargetHandle    - Target firmware volume handle.
//      Function Return - EFI Status Code.
//

EFI_STATUS
FindOptionalFvHandle (
  IN EFI_GUID *FileName,
  OUT EFI_HANDLE *TargetHandle
  )
{
  UINTN Index;
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  UINTN HandleCount;
  VOID *Buffer;
  UINTN Size;
  EFI_FV_FILETYPE FileType;
  EFI_FV_FILE_ATTRIBUTES Attributes;
  UINT32 AuthenticationStatus;
  EFI_FIRMWARE_VOLUME2_PROTOCOL *FirmwareVolume;
  FV_MEMMAP_DEVICE_PATH *FvDp;

  if (TargetHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *TargetHandle = NULL;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiFirmwareVolume2ProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  if (EFI_ERROR (Status) || HandleCount == 0) {
    return Status;
  }

  DPRINTF_DEV ("FileName = %g\n", FileName);
  DPRINTF_DEV ("FindOptionalFvHandle  Number of FV = %d\n", HandleCount);
  for (Index = 0; Index < HandleCount; Index++) {

    //
    // Get the Firmware Volume Protocol.
    //

    Status = gBS->HandleProtocol (
                    HandleBuffer [Index],
                    &gEfiFirmwareVolume2ProtocolGuid,
                    (VOID **)&FirmwareVolume);
    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = gBS->HandleProtocol (
                    HandleBuffer [Index],
                    &gEfiDevicePathProtocolGuid,
                    (VOID **)&FvDp);

    DPRINTF_DEV ("FvDp StartingAddress 0x%x \n", FvDp->MemMapDevPath.StartingAddress);
    DPRINTF_DEV ("FvDp EndingAddress   0x%x \n", FvDp->MemMapDevPath.EndingAddress);

    //
    // Passing NULL buffer to request size only.
    //

    Buffer = NULL;
    Size = 0;
    Status = FirmwareVolume->ReadFile (
                               FirmwareVolume,
                               FileName,
                               &Buffer,
                               &Size,
                               &FileType,
                               &Attributes,
                               &AuthenticationStatus);

    DPRINTF_DEV (" ReadFile returned %r\n", Status);
    if (!EFI_ERROR (Status) && Size > 0) {
      DPRINTF_DEV ("FindOptionalFvHandle: FOUND it ,size = 0x%x\n", Size);
      *TargetHandle = HandleBuffer [Index];
      break;
    }
  }

  gBS->FreePool (HandleBuffer);
  return (*TargetHandle != NULL) ? EFI_SUCCESS : EFI_NOT_FOUND;

} // FindOptionalFvHandle

//
// FUNCTION NAME.
//      DecompressOptionalFirmwareVolume - Decompress firmware volumes by type.
//
// FUNCTIONAL DESCRIPTION.
//      This function will decompress firmware volumes based on input type.
//
// ENTRY PARAMETERS.
//      Type            - Type of optional firmware volume to be decompressed.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
DecompressOptionalFirmwareVolume (IN UINTN Type) {

  EFI_STATUS Status;

  //
  // Decompress optional firmware volumes according to driver type.
  //

  if (mFirmwareVolumeLoader == NULL) {
    Status = gBS->LocateProtocol (
                    &gSctFirmwareVolumeLoaderProtocolGuid,
                    NULL,
                    (VOID **) &mFirmwareVolumeLoader);
    if (EFI_ERROR(Status)) {
      return Status;
    }
  }

  Status = mFirmwareVolumeLoader->LoadOptionalFirmwareVolume (mFirmwareVolumeLoader, Type);
  return Status;

} // DecompressOptionalFirmwareVolume


//
// FUNCTION NAME.
//      IsPciRootDevice - Test if a DevicePath is PciRoot.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check the DevicePath is PciRoot.
//
// ENTRY PARAMETERS.
//      DevicePath      - a pointer to DevicePath.
//      DeviceHandle    - Handle.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN.
//

BOOLEAN
EFIAPI
IsPciRootDevice (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN EFI_HANDLE DeviceHandle
  )
{
  UINTN i;
  EFI_HANDLE Handle;
  EFI_STATUS Status;
  BOOLEAN IsPciRoot;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  IsPciRoot = FALSE;
  Handle = NULL;
  HandleCount = 0;
  if (DevicePath == NULL && DeviceHandle == NULL) {
    DPRINTF_DEV ("DevicePath == NULL & DeviceHandle=NULL\n");
    DPRINTF_DEV ("IsPciRoot = [%a]\n", IsPciRoot ? "TRUE" :"FALSE");
    return IsPciRoot;
  }
  if (DevicePath == NULL) {

    DPRINTF_DEV ("DevicePath == NULL. DeviceHandle=0x%x\n", DeviceHandle);
    Handle = DeviceHandle;
  } else {
    RemainingDevicePath = DevicePath;
    Status = gBS->LocateDevicePath (
                    &gEfiDevicePathProtocolGuid,
                    &RemainingDevicePath,
                    &Handle);
    DPRINTF_DEV ("LocateDevicePath. Status = %r, Handle = 0x%x\n",Status,Handle);
    if (!EFI_ERROR (Status)) {
      DEBUG_DEV ({
        PCHAR16 Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (RemainingDevicePath, FALSE, TRUE);
        DPRINTF_DEV ("  RemainingDevicePath = %s\n", Str);
        SafeFreePool (Str);
      });
    } else {
      DPRINTF_DEV ("IsPciRoot = [%a]\n", IsPciRoot ? "TRUE" :"FALSE");
      return IsPciRoot;
    }
  } // if (DevicePath == NULL) {
  gBS->LocateHandleBuffer (
         ByProtocol,
         &gEfiPciRootBridgeIoProtocolGuid,
         NULL,
         &HandleCount,
         &HandleBuffer);

  if (HandleCount != 0) {
    for (i = 0; i < HandleCount; i++) {
      DPRINTF_DEV ("PciRootDevice Handle = 0x%x\n", HandleBuffer [i]);
      if (HandleBuffer [i] == Handle) {

        DPRINTF_DEV ("HandleBuffer [i] == Handle. Is PciRoot\n");
        IsPciRoot = TRUE;
        break;
      } // if (HandleBuffer [i] == Handle) {
    } // for (i = 0; i < HandleCount; i++) {
  } // if (HandleCount != 0) {

  DPRINTF_DEV ("IsPciRoot = [%a]\n", IsPciRoot ? "TRUE" :"FALSE");
  return IsPciRoot;

}

