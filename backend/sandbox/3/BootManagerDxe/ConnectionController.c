//
// FILENAME.
//      ConnectionController.c - SecureCore Technology(TM) Boot Manager Connection Controller.
//
// FUNCTIONAL DESCRIPTION.
//      This file defines a connection controller that only allows authorized
//      devices to be connected in order to prevent DMA from being enabled
//      when rogue devices are attached to the system through an expansion
//      slot such as a PCIe slot or a Thunderbolt connector.
//
//      By design, when a new device is attached to the system, a Boot####
//      entry is created for it, and is initialized to not be active.  If
//      the user wishes to enable the device for boot purposes, they can go
//      to setup and enable the device.  Otherwise, all attempts to connect
//      to that device will fail, as will all attempts to enable DMA via the
//      Attributes command.
//
// NOTICE.
//      Copyright (C) 2017-2024 Phoenix Technologies.  All Rights Reserved.
//

#include "Meta.h"

//
// Prototypes of public functions declared in other modules within this driver.
//


//
// Private data structures owned by this module.
//

STATIC EFI_CONNECT_CONTROLLER mOldConnectController = NULL;

STATIC SCT_CONNECT_RESTRICTION mConnectRestrictionArray [] = { CONFIG_BmConnectRestrictionList };

typedef struct _DENIED_PCI_DEVICE {
  struct _DENIED_PCI_DEVICE *Next;
  EFI_PCI_IO_PROTOCOL *RejectInstance;
  EFI_PCI_IO_PROTOCOL_ATTRIBUTES mOldPciIoAttributes;
} DENIED_PCI_DEVICE;

STATIC DENIED_PCI_DEVICE *mDeniedPciDevice = NULL;

//
// Prototypes of private functions defined within this driver.
//

STATIC
EFI_STATUS
EFIAPI
PciIoAttributesFilter (
  IN EFI_PCI_IO_PROTOCOL                       *This,
  IN  EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION  Operation,
  IN  UINT64                                   Attributes,
  OUT UINT64                                   *Result OPTIONAL
  );

//
// FUNCTION NAME.
//      FindPciDeviceInstance - Find PCI IO Device Instance.
//
// FUNCTIONAL DESCRIPTION.
//      This function is used to both add a PCI IO instance to the banned
//      instance list (to prevent writes to attributes that enable DMA), and
//      by the filtering function to locate a specific banned PCI IO instance.
//
// ENTRY PARAMETERS.
//      PciIo           - PciIo protocol instance to search for.
//      AddItem         - TRUE if PciIo should be added to the instance list (if not found).  FALSE if not.
//
// EXIT PARAMETERS.
//      Function Return - located denied PCI device instance, or NULL if not found or added.
//

STATIC
DENIED_PCI_DEVICE*
FindPciDeviceInstance (
  IN EFI_PCI_IO_PROTOCOL *PciIo,
  IN BOOLEAN AddItem
  )
{
  DENIED_PCI_DEVICE **Item;
  EFI_STATUS Status;

  //
  // Scan the denied PCI device instance list for a pointer to a banned
  // instance that matches PciIo.
  //

  for (Item = &mDeniedPciDevice; (*Item) != NULL; Item = &((*Item)->Next)) {
    if ((*Item)->RejectInstance == PciIo) {
      return (*Item);
    }
  }

  //
  // Don't add this PciIo instance if AddItem is FALSE.
  //

  if (AddItem == FALSE) {
    return NULL;
  }

  //
  // Create a new denied PCI device instance, and hook Attributes.
  //

  Status = gBS->AllocatePool (
                  EfiBootServicesData,
                  sizeof (DENIED_PCI_DEVICE),
                  (VOID**)Item);
  if (EFI_ERROR (Status)) {
    return NULL;
  }
  (*Item)->Next = NULL;
  if (PciIo->Attributes != PciIoAttributesFilter) {
    (*Item)->mOldPciIoAttributes = PciIo->Attributes;
    PciIo->Attributes = PciIoAttributesFilter;
  }
  (*Item)->RejectInstance = PciIo;
  return (*Item);
} // FindPciDeviceInstance

//
// FUNCTION NAME.
//      PciIoAttributesFilter - Filter calls to PciIo->Attributes.
//
// FUNCTIONAL DESCRIPTION.
//      This function prevents attempts to enable DMA or bus mastering on
//      devices that are in the blocked connection array, when such devices
//      have been disabled.
//
// ENTRY PARAMETERS.
//      This            - PCI IO protocol instance.
//      Operation       - attribute operation to perform.
//      Attributes      - attribute value.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      Result          - returned result when supported or current value requested.
//

STATIC
EFI_STATUS
EFIAPI
PciIoAttributesFilter (
  IN EFI_PCI_IO_PROTOCOL                       *This,
  IN  EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION  Operation,
  IN  UINT64                                   Attributes,
  OUT UINT64                                   *Result OPTIONAL
  )
{
  DENIED_PCI_DEVICE *Item;

  //
  // Validate input parameters.
  //

  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Find This PciIo instance in the denied PCI device list.
  //

  Item = FindPciDeviceInstance (This, FALSE); // Scan the ban list for This, but don't add it if not found.
  if (Item == NULL) {
    return EFI_UNSUPPORTED; // Just report unsupported if not found.
  }

  //
  // Check for prohibited operation.
  //

  if (Operation == EfiPciIoAttributeOperationEnable) {
    if (Attributes & EFI_PCI_IO_ATTRIBUTE_BUS_MASTER) {

      //
      // Denied.
      //

      return EFI_UNSUPPORTED;
    }
  }

  //
  // Otherwise, allow operation to continue.
  //

  return Item->mOldPciIoAttributes (This, Operation, Attributes, Result);
} // PciIoAttributesFilter

//
// FUNCTION NAME.
//      RelevantDpLength - Determine Relevant Device Path Length.
//
// FUNCTIONAL DESCRIPTION.
//      This function scans a device path to find out how long it is, up to the
//      terminating EFI_DEVICE_PATH_PROTOCOL structure.  This length is in
//      bytes and does not include the terminator.  We use this length when
//      comparing device paths.
//
// ENTRY PARAMETERS.
//      DevicePath      - pointer to EFI_DEVICE_PATH_PROTOCOL to find length of.
//
// EXIT PARAMETERS.
//      Function Return - relevant length of device path for compare.
//

STATIC
UINTN
RelevantDpLength (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  UINTN Length = 0;

  //
  // Validate input parameters.
  //

  if (DevicePath == NULL) {
    return 0;
  }

  //
  // Scan device path to find end of device path.
  //

  while ((DevicePath->Type & END_DEVICE_PATH_TYPE) != END_DEVICE_PATH_TYPE) {
    Length += DevicePath->Length [0];
    DevicePath = (EFI_DEVICE_PATH_PROTOCOL*)((UINTN)DevicePath + DevicePath->Length [0]);
  }

  //
  // Return length of device path.
  //

  return Length;
} // RelevantDpLength

//
// FUNCTION NAME.
//      BuildLoadOption - Build a Load Option (Boot####) Variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function generated sample contents for a boot variable that can be
//      used to find or generate a Boot#### variable for a banned device path.
//      This allows us to easily find or create new Boot#### variable instances.
//
// ENTRY PARAMETERS.
//      Restriction     - connect restriction list object.
//      DevicePath      - device path for this restriction.
//      DevicePathLength- Length of device path.
//
// EXIT PARAMETERS.
//      Function Return - EFI status of attempt to create new sample variable.
//      OptionLength    - length of new Boot#### variable contents.
//      Option          - buffer with newly created Boot#### variable contents.
//

STATIC
EFI_STATUS
BuildLoadOption (
  IN SCT_CONNECT_RESTRICTION *Restriction,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINTN DevicePathLength,
  OUT UINTN *OptionLength,
  OUT VOID **Option
  )
{
  EFI_STATUS Status;
  UINT32 *Attributes;
  UINT16 *FilePathListLength;
  CHAR16 *Description;
  EFI_DEVICE_PATH_PROTOCOL *FilePathList;
  UINTN DescriptionSize;

  //
  // Validate input parameters.
  //

  if ((OptionLength == NULL) || (Option == NULL) || (Restriction == NULL) || (DevicePath == NULL) || (DevicePathLength == 0)) {
    return EFI_INVALID_PARAMETER;
  }
  if (Restriction->SetupText == NULL) {
    return EFI_UNSUPPORTED;
  }

  //
  // Determine final length of option.
  //

  DescriptionSize = StrSize (Restriction->SetupText);
  *OptionLength = sizeof (*Attributes) +
                  sizeof (*FilePathListLength) +
                  DescriptionSize +
                  DevicePathLength;

  //
  // Allocate new option object from pool.
  //

  Status = gBS->AllocatePool (
                  EfiBootServicesData,
                  *OptionLength,
                  (VOID**)Option);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Calculate offsets of each field for this EFI boot object.
  //

  Attributes = (UINT32*)(*Option);
  FilePathListLength = (UINT16*)(Attributes + 1);
  Description = (CHAR16*)(FilePathListLength + 1);
  FilePathList = (EFI_DEVICE_PATH_PROTOCOL*)((UINTN)Description + DescriptionSize);

  //
  // Populate the entire object appropriately.
  //

  *Attributes = LOAD_OPTION_CATEGORY_BOOT;
  *FilePathListLength = (UINT16)DevicePathLength;
  CopyMem (Description, Restriction->SetupText, DescriptionSize);
  CopyMem (FilePathList, DevicePath, DevicePathLength);
  return EFI_SUCCESS;
} // BuildLoadOption

//
// FUNCTION NAME.
//      AddToBootOrder - Add Specified Index to BootOrder variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function adds the specified Boot#### index to a boot order
//      variable.  Without this step, the Boot#### variable won't be
//      referenced by the boot manager or show up in setup.
//
// ENTRY PARAMETERS.
//      VarName         - name of boot order variable to add index to.
//      VarGuid         - GUID of boot order variable to add index to.
//      NewEntry        - index of boot order variable to add to list.
//
// EXIT PARAMETERS.
//      Function Return - EFI status of attempt to add entry.
//

STATIC
EFI_STATUS
AddToBootOrder (
  IN CHAR16 *VarName,
  IN EFI_GUID *VarGuid,
  IN UINT16 NewEntry
  )
{
  EFI_STATUS Status;
  UINTN i;
  UINTN VarSize;
  UINT16 *Buffer;
  UINT32 Attributes;

  //
  // Determine size of boot order variable.
  //

  Buffer = NULL;
  VarSize = 0;
  Status = gRT->GetVariable (
                  VarName,
                  VarGuid,
                  &Attributes,
                  &VarSize,
                  Buffer);

  //
  // Allocate proper buffer for boot order variable.
  //

  if (Status == EFI_BUFFER_TOO_SMALL) {
    Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    VarSize + sizeof (UINT16),
                    (VOID**)&Buffer);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else {
    return EFI_UNSUPPORTED;
  }

  //
  // Get current boot order.
  //

  Status = gRT->GetVariable (
                  VarName,
                  VarGuid,
                  &Attributes,
                  &VarSize,
                  Buffer);
  if (EFI_ERROR (Status)) {
    gBS->FreePool (Buffer);
    return Status;
  }

  //
  // Scan to see if NewEntry is already in the list.
  //

  for (i = 0; i < VarSize / sizeof (UINT16); i++) {
    if (Buffer [i] == NewEntry) {
      gBS->FreePool (Buffer);
      return EFI_SUCCESS;
    }
  }

  //
  // Add NewEntry to the end of the list.
  //

  Buffer [VarSize / sizeof (UINT16)] = NewEntry;
  Status = gRT->SetVariable (
                  VarName,
                  VarGuid,
                  Attributes,
                  VarSize + sizeof (UINT16),
                  Buffer);
  gBS->FreePool (Buffer);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  return EFI_SUCCESS;
} // AddToBootOrder

STATIC
VOID GenerateBootVarName (
  IN UINTN Index,
  OUT CHAR16 *NameBuffer
  )
{
  static CHAR16 *Hex = L"0123456789ABCDEF";
  NameBuffer [0] = L'B';
  NameBuffer [1] = L'o';
  NameBuffer [2] = L'o';
  NameBuffer [3] = L't';
  NameBuffer [4] = Hex [(Index & 0xf000) >> 12];
  NameBuffer [5] = Hex [(Index & 0xf00) >> 8];
  NameBuffer [6] = Hex [(Index & 0xf0) >> 4];
  NameBuffer [7] = Hex [Index & 0xf];
  NameBuffer [8] = 0;
} // GenerateBootVarName

//
// FUNCTION NAME.
//      CheckForAuthorization - Check for User Authorization of Boot Device.
//
// FUNCTIONAL DESCRIPTION.
//      This function verifies that a user has authorized use of a
//      restricted device by checking to see if there is an enabled
//      Boot#### variable associated with that device.  Note that if
//      no Boot#### variable is found, this function attempts to
//      create a new variable.  This function also takes measures to
//      be sure that the Boot#### variable is in the boot order, so
//      it will show up in setup, and the user can enable or disable
//      the device in the boot order.
//
// ENTRY PARAMETERS.
//      Restriction     - restriction object associated with the device.
//      DevicePath      - device path associated with the restricted device.
//      DevicePathLength- length of the device path.
//
// EXIT PARAMETERS.
//      Function Return - EFI_SUCCESS if device is authorized, fail otherwise.
//

STATIC
EFI_STATUS
CheckForAuthorization (
  IN SCT_CONNECT_RESTRICTION *Restriction,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINTN DevicePathLength
  )
{
  EFI_STATUS Status;
  VOID *LoadOption = NULL;
  VOID *VarBuffer = NULL;
  UINTN LoadOptionSize;
  UINTN VarBufferSize;
  UINTN i;
  CHAR16 VarName [9];

  //
  // Build a sample load option so we know how large the build option is,
  // and what to look for specifically.
  //

  Status = BuildLoadOption (
             Restriction,
             DevicePath,
             DevicePathLength,
             &LoadOptionSize,
             &LoadOption);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Allocate a buffer for the Boot#### option search.
  //

  Status = gBS->AllocatePool (
                  EfiBootServicesData,
                  LoadOptionSize,
                  (VOID**)&VarBuffer);
  if (EFI_ERROR (Status)) {
    gBS->FreePool (LoadOption);
    return Status;
  }

  //
  // Scan boot options until we find a matching Boot#### option variable.
  //

  Status = EFI_SECURITY_VIOLATION;
  for (i = CONFIG_SYSTEM_BOOT_MANAGER_RESTRICTION_FIRST_BOOT_VAR; i < 0x10000; i++) {

    //
    // Generate the variable name.
    //

    GenerateBootVarName (i, VarName);

    //
    // Attempt to read the Boot#### variable.
    //

    VarBufferSize = LoadOptionSize;
    Status = gRT->GetVariable (
                    VarName,
                    &gEfiGlobalVariableGuid,
                    NULL,
                    &VarBufferSize,
                    VarBuffer);

    //
    // Process results of attempt.
    //

    if ((Status == EFI_BUFFER_TOO_SMALL) || (VarBufferSize != LoadOptionSize)) {

      //
      // This is not the variable instance we are looking for.
      //

      continue;
    } else if (Status == EFI_NOT_FOUND) {

      //
      // Create a new boot option for this device filter, so users can enable
      // this device via the boot menu.
      //

      CreateOption (
        (UINT16)i,
        SCT_BM_LO_BOOT,
        0,
        Restriction->SetupText,
        DevicePath,
        0,
        NULL,
        NULL);

      AddToBootOrder (EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid, (UINT16)i);
      AddToBootOrder (L"BootOrderDefault", &gSctBdsServicesProtocolGuid, (UINT16)i);

      Status = gRT->SetVariable (
                      VarName,
                      &gEfiGlobalVariableGuid,
                      EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                      LoadOptionSize,
                      LoadOption);
      if (EFI_ERROR (Status)) {
        break;
      }
      Status = EFI_SECURITY_VIOLATION;
      break;
    }

    //
    // Compare, excluding attributes and device path.
    //

    if (CompareMem (
          (VOID*)((UINTN)LoadOption + sizeof (UINT32)),
          (VOID*)((UINTN)VarBuffer + sizeof (UINT32)),
          LoadOptionSize - (sizeof (UINT32) + DevicePathLength)) != 0) {
      continue;
    }

    //
    // We found a match.  Our boot variable may get pulled if we don't keep it
    // in the boot order lists.
    //

    AddToBootOrder (EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid, (UINT16)i);
    AddToBootOrder (L"BootOrderDefault", &gSctBdsServicesProtocolGuid, (UINT16)i);

    //
    // Verify that device path is correct for this boot option and adjust
    // device path if not.
    //

    if (CompareMem (
          (VOID*)((UINTN)LoadOption + sizeof (UINT32)),
          (VOID*)((UINTN)VarBuffer + sizeof (UINT32)),
          LoadOptionSize - sizeof (UINT32)) != 0) {
      *((UINT32*)LoadOption) = *((UINT32*)VarBuffer);
      gRT->SetVariable (
             VarName,
             &gEfiGlobalVariableGuid,
             EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
             LoadOptionSize,
             LoadOption);
    }

    //
    // Check to see if the boot option is "active", and return authorization
    // indication if it is.
    //

    if (*(UINT32*)(VarBuffer) & LOAD_OPTION_ACTIVE) {
      Status = EFI_SUCCESS;
    } else {
      Status = EFI_SECURITY_VIOLATION;
    }
    break;
  }

  //
  // Cleanup and return result.
  //

  gBS->FreePool (LoadOption);
  gBS->FreePool (VarBuffer);
  return Status;
} // CheckForAuthorization

//
// FUNCTION NAME.
//      CallAllSctBootRestrictionProtocols - Call all instances of SctBootRestrictionProtocol.
//
// FUNCTIONAL DESCRIPTION.
//      This function calls all instances of the SCT_BOOT_RESTRICTION_PROTOCOL
//      in order to give other parts of SCT such as the platform or board
//      specific code a chance to modify the boot restriction array.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

STATIC
VOID
CallAllSctBootRestrictionProtocols (VOID)
{
  SCT_BOOT_RESTRICTION_PROTOCOL *BootRestrictionProtocol;
  EFI_HANDLE *HandleBuffer;
  UINTN BufferSize;
  EFI_STATUS Status;
  UINTN i;
  STATIC BOOLEAN ArrayUpdated = FALSE;

  //
  // Only handle this once.
  //

  if (ArrayUpdated) {
    return;
  }
  ArrayUpdated = TRUE;

  //
  // Call every boot restriction protocol instance.
  //

  BufferSize = 0;
  HandleBuffer = NULL;
  while (TRUE) {

    //
    // Build list of handles for boot restriction protocols.
    //

    Status = gBS->LocateHandle (
                    ByProtocol,
                    &gSctBootRestrictionProtocol,
                    NULL,
                    &BufferSize,
                    (VOID*)HandleBuffer);
    if (EFI_ERROR (Status)) {
      if (Status == EFI_BUFFER_TOO_SMALL) {
        Status = gBS->AllocatePool (
                    EfiBootServicesData,
                    BufferSize,
                    (VOID**)&HandleBuffer);
        if (EFI_ERROR (Status)) {
          return;
        }
        continue;
      }
      break;
    }

    //
    // Call every instance of the boot restriction protocol.
    //

    for (i = 0; i < BufferSize / sizeof (EFI_HANDLE); i++) {
      Status = gBS->HandleProtocol (HandleBuffer [i], &gSctBootRestrictionProtocol, (VOID**)&BootRestrictionProtocol);
      if (EFI_ERROR (Status)) {
        continue;
      }
      BootRestrictionProtocol->UpdatePolicy (
                                 BootRestrictionProtocol,
                                 mConnectRestrictionArray,
                                 sizeof (mConnectRestrictionArray),
                                 sizeof (mConnectRestrictionArray [0]));
    }
    gBS->FreePool (HandleBuffer);
    break;
  }
} // CallAllSctBootRestrictionProtocols

//
// FUNCTION NAME.
//      ConnectControllerFilter - Filter Calls to gBS->ConnectController.
//
// FUNCTIONAL DESCRIPTION.
//      When the BIOS attempts to connect to a controller via the
//      gBS->ConnectController interface, this function verifies that the
//      controller is an authorized controller by checking a black list
//      to see if the controller may be restricted, and then verifying
//      that the controller is authorized for connection by checking a
//      Boot#### variable to see if it is marked as Active.
//
// ENTRY PARAMETERS.
//      ControllerHandle- handle to the controller to connect to.
//      DriverImageHandle- optional list of handles to drivers that support binding protocol.
//      RemainingDevicePath- optional device path of a child of the controller being connected to.
//      Recursive       - TRUE to recursively connect all children of this controller.
//
// EXIT PARAMETERS.
//      Function Return - EFI_SUCCESS if device is authorized, fail otherwise.
//

STATIC
EFI_STATUS
EFIAPI
ConnectControllerFilter (
  IN  EFI_HANDLE                    ControllerHandle,
  IN  EFI_HANDLE                    *DriverImageHandle,   OPTIONAL
  IN  EFI_DEVICE_PATH_PROTOCOL      *RemainingDevicePath, OPTIONAL
  IN  BOOLEAN                       Recursive
  )
{
  EFI_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath = NULL, *TargetPath;
  EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *PciRootBridgeIo;
  UINTN i, TargetPathLength;
  EFI_PCI_IO_PROTOCOL *PciIo;

  if (ControllerHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check to see if this is a PCI root bridge, and if it is, connect it first.
  // That way, busses will be assigned to bridges prior to any filtering calls
  // that need to check for stuff beyond a bridge in a boot restriction
  // protocol instance.
  //

  Status = gBS->HandleProtocol (ControllerHandle, &gEfiPciRootBridgeIoProtocolGuid, (VOID**)&PciRootBridgeIo);
  if (!EFI_ERROR (Status)) {
    Status = mOldConnectController (ControllerHandle, DriverImageHandle, RemainingDevicePath, Recursive);

    //
    // Update connection restriction array.
    //

    CallAllSctBootRestrictionProtocols ();
    return Status;
  }

  //
  // Locate the device path associated with this controller.
  //

  Status = gBS->HandleProtocol (ControllerHandle, &gEfiDevicePathProtocolGuid, (VOID**)&TargetPath);
  if (EFI_ERROR (Status)) {
    return mOldConnectController (ControllerHandle, DriverImageHandle, RemainingDevicePath, Recursive);
  }
  TargetPathLength = RelevantDpLength (TargetPath);

  //
  // Scan this list of restricted device paths to see if this controller is in
  // the restriction list.
  //

  for (i = 0; i < sizeof (mConnectRestrictionArray) / sizeof (mConnectRestrictionArray [0]); i++) {
    UINTN DevicePathLength;

    //
    // Does this restriction apply to this connection attempt?
    //

    if (mConnectRestrictionArray [i].DevicePath == NULL) {
      continue;
    }
    DevicePath = ConvertTextToDevicePath (mConnectRestrictionArray [i].DevicePath);
    if (DevicePath == NULL) {
      break;
    }
    DevicePathLength = RelevantDpLength (DevicePath);
    if (DevicePathLength > TargetPathLength) {
      gBS->FreePool (DevicePath);
      DevicePath = NULL;
      continue;
    }
    if (CompareMem (DevicePath, TargetPath, DevicePathLength) == 0) {

      //
      // Check to see if there is an active Boot#### action created for the
      // user to indicate that the user has authorized connecting to this
      // particular device.
      //

      Status = CheckForAuthorization (
                 &(mConnectRestrictionArray [i]),
                 DevicePath,
                 DevicePathLength + sizeof (EFI_DEVICE_PATH_PROTOCOL));

      if (EFI_ERROR (Status)) {

        //
        // Make sure there's no way that DMA will be enabled for this
        // particular device, so sneaky code that enables the device outside
        // a connection attempt can't violate the security policy we're trying
        // to enforce by accident.
        //

        Status = gBS->HandleProtocol (ControllerHandle, &gEfiPciIoProtocolGuid, (VOID**)&PciIo);
        if (!EFI_ERROR (Status) && (PciIo != NULL)) {
          FindPciDeviceInstance (PciIo, TRUE);  // Scan the ban list, and add this instance if not found.
        }
        gBS->FreePool (DevicePath);
        DevicePath = NULL;
        return EFI_SECURITY_VIOLATION;
      }
      break;
    }
  }
  if (DevicePath != NULL) {
    gBS->FreePool (DevicePath);
  }

  //
  // If no policy found or device is authorized, go ahead and do a connect
  // using the original interface.
  //

  return mOldConnectController (ControllerHandle, DriverImageHandle, RemainingDevicePath, Recursive);
} // ConnectControllerFilter

STATIC
VOID
CreateInitialBootVars (VOID)
{
  EFI_STATUS Status;
  UINTN i;
  UINTN CurrentIndex = CONFIG_SYSTEM_BOOT_MANAGER_RESTRICTION_FIRST_BOOT_VAR;

  for (i = 0; i < sizeof (mConnectRestrictionArray) / sizeof (mConnectRestrictionArray [0]); i++) {
    EFI_DEVICE_PATH_PROTOCOL *DevicePath = NULL;
    UINTN DevicePathLength;
    CHAR16 VarName [9];
    VOID *LoadOption;
    UINTN LoadOptionSize;
    UINTN LoadOptionSize2;
    UINT32 Attributes;

    if ((mConnectRestrictionArray [i].DevicePath == NULL) ||
        (mConnectRestrictionArray [i].SetupText == NULL)) {
      continue;
    }

    DevicePath = ConvertTextToDevicePath (mConnectRestrictionArray [i].DevicePath);
    if (DevicePath == NULL) {
      return;
    }
    DevicePathLength = RelevantDpLength (DevicePath) + sizeof (EFI_DEVICE_PATH_PROTOCOL);
    Status = BuildLoadOption (
               &mConnectRestrictionArray [i],
               DevicePath,
               DevicePathLength,
               &LoadOptionSize,
               &LoadOption);
    if (EFI_ERROR (Status)) {
      gBS->FreePool (DevicePath);
      continue;
    }
    GenerateBootVarName (CurrentIndex++, VarName);
    LoadOptionSize2 = LoadOptionSize;
    Status = gRT->GetVariable (
                    VarName,
                    &gEfiGlobalVariableGuid,
                    &Attributes,
                    &LoadOptionSize2,
                    LoadOption);
    if ((Status != EFI_NOT_FOUND) && (LoadOptionSize2 >= LoadOptionSize)){
      gBS->FreePool (LoadOption);
      gBS->FreePool (DevicePath);
      continue;
    }
    gRT->SetVariable (
           VarName,
           &gEfiGlobalVariableGuid,
           EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
           LoadOptionSize,
           LoadOption);
    gBS->FreePool (LoadOption);
    gBS->FreePool (DevicePath);
  }
} // CreateInitialBootVars

//
// FUNCTION NAME.
//      HookConnectController - Hook gBS->ConnectController.
//
// FUNCTIONAL DESCRIPTION.
//      This function initializes the connect controller filtering code and
//      hooks connect controller to allow detection of attempts to connect to
//      restricted devices such as PCIe slots.  This allows us to actively
//      filter attempts to connect to PCIe and Firewire slots during POST to
//      prevent drivers from enabling DMA on those slots unless authorized by
//      the end user through setup.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - status of initialization.
//

EFI_STATUS
EFIAPI
HookConnectController (
  VOID
  )
{
  CreateInitialBootVars ();
  if (mOldConnectController == NULL) {
    mOldConnectController = gBS->ConnectController;
    gBS->ConnectController = ConnectControllerFilter;
  }
  return EFI_SUCCESS;
} // HookConnectController