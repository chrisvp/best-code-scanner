//
// FILENAME.
//      BdsServices.c - SecureCore Technology(TM) BDS Services Protocol.
//
// FUNCTIONAL DESCRIPTION.
//      This module implements the BDS Services Protocol.
//
//      This protocol can be used by the Boot Manager or by other applications
//      that run in the BDS phase, typically a Boot Menu application and a
//      Setup application.
//
//      There can be only one instance of this protocol, which is why none of
//      the functions have This pointers. These functions are expected to be
//      stateful, meaning that the results for a given input may be different
//      at different times.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
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
// Prototypes for functions in other modules that are a part of this component.
//

extern
SCT_STATUS
EFIAPI
SetEfiGlobalVariable (
  IN PCHAR16 VariableName,
  IN UINT32 Attributes,
  IN UINTN DataSize,
  IN PVOID Data);

extern
SCT_STATUS
EFIAPI
GetBootOptionListHead (OUT PLOAD_OPTION_OBJECT *BootOptionListHead);

extern
SCT_STATUS
EFIAPI
GetHotkeyListHead (OUT PHOTKEY_OBJECT *HotkeyListHead);

extern
SCT_STATUS
RemoveHotKey (IN PHOTKEY_OBJECT HotKey);

extern
SCT_STATUS
DeleteHotKey (IN UINT16 KeyOptionNumber);

extern
SCT_STATUS
EFIAPI
GetHotkey (
  IN UINT16 KeyOptionNumber,
  OUT PHOTKEY_OBJECT *HotKey OPTIONAL);

extern
SCT_STATUS
GetNewHotKeyNumber (OUT PUINT16 KeyNumber);

extern
SCT_STATUS
CreateOrUpdateHotKey (
  IN UINT16 KeyOptionNumber,
  IN UINTN KeyOptionSize,
  IN EFI_KEY_OPTION *KeyOptionData,
  IN PHOTKEY_DESCRIPTION_DATA DescriptionData,
  IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *TextInEx OPTIONAL);

extern
SCT_STATUS
EFIAPI
EnumerateAllLoadOptions (VOID);

extern
SCT_STATUS
HddDevicePathExpansion (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

//
// Data shared with other modules *within* this component.
//

//
// Data defined in other modules and used by this module.
//

extern DRIVER_OBJECT mBootManager;
extern BOOT_REORDER mBootReorder;
extern BOOT_MANAGER_CONFIGURATION mBootManagerConfigurationTable [];

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

SCT_STATUS
ConstructBdsServicesNodeNoChildren (
  IN PLOAD_OPTION_OBJECT Option,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BdsServicesNode);

SCT_STATUS
ConstructBdsServicesNode (
  IN PLOAD_OPTION_OBJECT Option,
  IN PSCT_BOOT_OPTION_NODE Child,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BdsServicesNode);

SCT_STATUS
DestroyBopChildList (IN PSCT_BOOT_OPTION_NODE ChildList);

SCT_STATUS
DestroyBdsBootList (IN PSCT_BDS_SERVICES_BOOT_OPTION BootListHead);

SCT_STATUS
ConstructBdsHotKeyObject (
  IN UINT16 KeyOptionNumber,
  IN UINTN KeyOptionSize,
  IN EFI_KEY_OPTION *KeyOptionData,
  IN PSCT_BDS_SERVICES_HOTKEY_DESCRIPTION_DATA DescriptionData, OPTIONAL
  OUT SCT_BDS_SERVICES_HOTKEY_OBJECT **HotKeyObject);

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_HIDE_INVALID_BOOT_OPTION
SCT_STATUS
AddOsBootOptionIntoBootOrder (
  IN OUT PUINT16 *CurrentBootOrder,
  IN OUT UINTN *CurrentBootOrderCount);
#endif

//
// Public API functions implemented by this component.
//

EFI_STATUS
EFIAPI
BdsServicesLaunch (
  IN UINT16 OptionNumber);

EFI_STATUS
EFIAPI
BdsServicesLaunchDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN UINT16 OptionNumber, OPTIONAL
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength,
  IN UINT32 LaunchFlags);

EFI_STATUS
EFIAPI
BdsServicesGetBootListNames (
  OUT PCHAR16 **BootListNames,
  OUT PUINTN NumberOfBootLists);

EFI_STATUS
EFIAPI
BdsServicesGetBootList (
  IN CONST PCHAR16 BootListName,
  OUT PCHAR16 *BootListDescription,
  OUT PCHAR16 *BootListHelp,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootListHead);

EFI_STATUS
EFIAPI
BdsServicesSetBootList (
  IN CONST PCHAR16 BootListName,
  IN PSCT_BDS_SERVICES_BOOT_OPTION BootListHead);

EFI_STATUS
EFIAPI
BdsServicesGetBootOptionList (OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootOptionList);

EFI_STATUS
EFIAPI
BdsServicesGetBootOption (
  IN UINT16 OptionNumber,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootOption);

EFI_STATUS
EFIAPI
BdsServicesGetDefaultBootOption (
  IN UINT16 OptionNumber,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootOption);

EFI_STATUS
EFIAPI
BdsServicesSetBootOption (IN OUT PSCT_BDS_SERVICES_BOOT_OPTION BootOption);

EFI_STATUS
EFIAPI
BdsServicesGetHotkeyList (OUT PSCT_BDS_SERVICES_HOTKEY_OBJECT *HotkeyList);

EFI_STATUS
EFIAPI
BdsServicesGetHotkey (
  IN UINT16 KeyOptionNumber,
  OUT PSCT_BDS_SERVICES_HOTKEY_OBJECT *Hotkey);

EFI_STATUS
EFIAPI
BdsServicesSetHotkey (IN PSCT_BDS_SERVICES_HOTKEY_OBJECT Hotkey);

EFI_STATUS
EFIAPI
BdsServicesGetDeviceType (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_GUID **TypeGuid
  );

EFI_STATUS
GroupEnumeratedBootOptionsIntoType (IN SCT_BDS_SERVICES_BOOT_OPTION *SctBootOption);

SCT_BDS_SERVICES_PROTOCOL mSctBdsServicesProtocol = {

  sizeof (SCT_BDS_SERVICES_PROTOCOL),

  BdsServicesLaunch,
  BdsServicesLaunchDevicePath,

  //
  // Boot List related services.
  //

  BdsServicesGetBootListNames,
  BdsServicesGetBootList,
  BdsServicesSetBootList,

  //
  // Load Option related services. Note that these Load Options can be either
  // Boot Load Options or Application Load Options.
  //

  BdsServicesGetBootOptionList,
  BdsServicesGetBootOption,
  BdsServicesGetDefaultBootOption,
  BdsServicesSetBootOption,

  //
  // Hotkey related services.
  //

  BdsServicesGetHotkeyList,
  BdsServicesGetHotkey,
  BdsServicesSetHotkey,

  //
  // Device services.
  //

  BdsServicesGetDeviceType

};

//
// FUNCTION NAME.
//      InitializeBdsServices - Initialize the BdsServices module.
//
// FUNCTIONAL DESCRIPTION.
//      This function installs BDS Services Protocol. We install on the same
//      handle as the BDS Arch Protocol since these services belong to Boot
//      Manager.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
EFIAPI
InitializeBdsServices (VOID)
{
  SCT_STATUS Status;

  DPRINTF_INIT ("InitializeBdsServices.\n");

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mBootManager.Handle,
                  &gSctBdsServicesProtocolGuid,
                  &mSctBdsServicesProtocol,
                  NULL);

  return Status;
} // InitializeBdsServices

//
// FUNCTION NAME.
//      Launch - Launch a Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function launches a Boot Option. This includes any expansion of
//      device paths and the appending of the default file path if the Option's
//      type is Boot (rather than application) and the Option refers to a
//      handle with the simple file system installed on it (with no remaining
//      path).
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value, the option number of the Boot Option.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesLaunch (IN UINT16 OptionNumber)
{
  UINT32 Crc;
  SCT_STATUS Status;

  DPRINTF_BDS ("BdsServicesLaunch:\n");

  GetLoadOptionCrc (OptionNumber, SCT_BM_LO_BOOT, &Crc);
  Status = LaunchBootOption (OptionNumber, Crc);

  return Status;
} // BdsServicesLaunch

//
// FUNCTION NAME.
//      LaunchDevicePath - Launch a Device Path.
//
// FUNCTIONAL DESCRIPTION.
//      This function launches a Device Path. This includes any expansion of
//      the device path and the appending of the default file path if the
//      Device Path refers to a handle with the simple file system installed on
//      it (with no remaining path).
//
//      This function can launch the device path as using the policy defined at
//      build time or in setup, depending on how this component was built. That
//      is booting the device path as legacy or uefi and in which order is
//      determined by the appropriate setup options.
//
//      BDS_SERVICES_FLAG_APPLICATION
//              Launch as an application instead of as a Boot Option.
//              There are many differences between launching as a Boot Option
//              and launching as an application. The Boot Option Protocols and
//              recursive expansion are only used for Boot Options. Applications
//              are only expanded one level and never for Boot Option Protocol.
//              Also, Boot Options will "Prepare to Boot" which does work
//              specific to passing control to the OS, including signalling the
//              ReadyToBoot event.
//
// ENTRY PARAMETERS.
//      FilePathList    - Pointer to a UEFI Device Path.
//      OptionNumber    - UINT16 value, the Option Number to Launch as.
//      OptionalData    - Pointer to optional data.
//      OptionalDataLength - UNINT32 value, the number of bytes in the buffer
//                      whose address is OptionalData.
//      LaunchFlags     - UINT32 value, flags for this function.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesLaunchDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN UINT16 OptionNumber, OPTIONAL
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength,
  IN UINT32 LaunchFlags
  )
{
  DPRINTF_BDS ("BdsServicesLaunchDevicePath:\n");

  if (LaunchFlags & BDS_SERVICES_FLAG_APPLICATION) {
    return LaunchApplicationOption (
             FilePathList,
             OptionalData,
             OptionalDataLength);
  }

  return LaunchDevicePaths (
           FilePathList,
           1,
           OptionNumber,
           OptionalData,
           OptionalDataLength);
} // BdsServicesLaunchDevicePath

//
// FUNCTION NAME.
//      GetBootListNames - Get All The Available Boot Lists.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets all the Boot Lists that are visible to the user.
//      This function will be used by User Interface applications to get all
//      the Boot Lists that should be displayed to the user.
//
//      The Boot Lists are returned in an array of pointers to strings. The
//      strings provided are the names of the lists to be used in a call to
//      GetBootList or SetBootList.
//
//      The memory for the strings and for the array of pointers to the strings
//      is allocated by this function from Pool and should be freed by the
//      caller.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      BootListNames   - the address of an array of pointers to strings.
//      NumberOfBootLists - the number of elements in the array pointer to by
//                          BootListNames.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesGetBootListNames (
  OUT PCHAR16 **BootListNames,
  OUT PUINTN NumberOfBootLists
  )
{
  UINTN BootOrderStrSize;
  PCHAR16 BootOrderStr;

  DPRINTF_BDS ("BdsServicesGetBootListNames:\n");

  if ((BootListNames == NULL) || (NumberOfBootLists == NULL)) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Currently we only support BootOrder and BootOrderDefault.
  //

  *NumberOfBootLists = 2;
  *BootListNames = AllocateZeroPool (sizeof (PCHAR16) * 2);
  if (*BootListNames == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  //
  // Add BootOrder.
  //

  BootOrderStrSize = StrSize (EFI_BOOT_ORDER_VARIABLE_NAME);
  BootOrderStr = AllocateCopyPool (BootOrderStrSize, EFI_BOOT_ORDER_VARIABLE_NAME);
  if (BootOrderStr == NULL) {
    SafeFreePool (*BootListNames);
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
  (*BootListNames) [0] = BootOrderStr;

  //
  // Add BootOrderDefault.
  //

  BootOrderStrSize = StrSize (L"BootOrderDefault");
  BootOrderStr = AllocateCopyPool (BootOrderStrSize, L"BootOrderDefault");
  if (BootOrderStr == NULL) {
    SafeFreePool ((*BootListNames) [0]);
    SafeFreePool (*BootListNames);
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
  (*BootListNames) [1] = BootOrderStr;

  return SCT_STATUS_SUCCESS;
} // BdsServicesGetBootListNames

//
// FUNCTION NAME.
//      BdsServicesGetBootList - Get a Boot List.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets the list of Boot Options for a Boot List.
//
//      Memory is allocated by this function from Pool for each
//      SCT_BDS_SERVICES_BOOT_OPTION. It is the caller's responsibility to free the
//      node as well as the memory pointed to by fields in the node. The list
//      of pointers to free is:
//              SCT_BDS_SERVICES_BOOT_OPTION
//              SCT_BDS_SERVICES_BOOT_OPTION.Description
//              SCT_BDS_SERVICES_BOOT_OPTION.DevicePath
//      Also, the strings at *BootListDescription and *BootListHelp must be
//      freed.
//
// ENTRY PARAMETERS.
//      BootListName    - the string pointer for the name of the Boot List.
//
// EXIT PARAMETERS.
//      BootListDescription - the address of a string that describes this Boot
//                            List. Note that there may not be a string, the
//                            pointer will be NULL in this case.
//      BootListHelp    - the address of a string that is help text for this
//                        Boot List. Note that there may not be a string, the
//                        pointer will be NULL in this case.
//      BootListHead    - the address of a pointer to the first
//                        SCT_BDS_SERVICES_BOOT_OPTION object.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesGetBootList (
  IN CONST PCHAR16 BootListName,
  OUT PCHAR16 *BootListDescription,
  OUT PCHAR16 *BootListHelp,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootListHead
  )
{
  UINTN i;
  SCT_STATUS Status;
  PUINT16 OptionOrder;
  UINTN OptionOrderSize;
  PSCT_BDS_SERVICES_BOOT_OPTION *p;
  SCT_BDS_SERVICES_BOOT_OPTION  *q;
  PLOAD_OPTION_OBJECT Option;
  PCHAR16 ThisBootListName;
  EFI_GUID *VariableGuid;
#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_HIDE_INVALID_BOOT_OPTION
  UINTN NumberOfDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *ExpandDevicePath;
#endif

  DPRINTF_BDS ("BdsServicesGetBootList:\n");

  if ((BootListDescription == NULL) || (BootListHelp == NULL) || (BootListHead == NULL)) {
    DPRINTF_BDS ("  An output parameter was NULL.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Currently we only support two Boot Lists, those are BootOrder and BootOrderDefault.
  // If the Boot List requested is anything else just return error.
  // Note, NULL also refers to BootOrder.
  //

  VariableGuid = &gEfiGlobalVariableGuid;
  if (BootListName == NULL || StrCmp (BootListName, EFI_BOOT_ORDER_VARIABLE_NAME) == 0) {
    ThisBootListName = EFI_BOOT_ORDER_VARIABLE_NAME;

  } else if (StrCmp (BootListName, L"BootOrderDefault") == 0) {
    ThisBootListName = BootListName;
    VariableGuid = &gSctBdsServicesProtocolGuid;
  } else {
    return EFI_UNSUPPORTED;
  }

  DPRINTF_BDS ("  ThisBootListName = %s.\n", ThisBootListName);

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  if (StrCmp (ThisBootListName, EFI_BOOT_ORDER_VARIABLE_NAME) == 0) {
    EnumerateAllLoadOptions ();
  }
#endif

  //
  // Get the BootOrder variable.
  //

  OptionOrder = NULL;
  OptionOrderSize = 0;
  OptionOrder = (PUINT16) SctLibGetVariableAndSize (
                           ThisBootListName,
                           VariableGuid,
                           &OptionOrderSize);

  if (OptionOrder == NULL || OptionOrderSize == 0) {
    DPRINTF_BDS ("  Fail to get %s variable\n", ThisBootListName);
    return EFI_NOT_FOUND;
  }

  //
  // NEWREL: cu 09/12/03, Create a configuration table which connects a
  // BootListName, BootListDescription and BootListHelp through the DEF
  // language.
  //

  *BootListDescription = NULL;
  *BootListHelp = NULL;

  //
  // Expand each Option to create the tree of SCT_BDS_SERVICES_BOOT_OPTIONs.
  //

  p = BootListHead;
  for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {
    Status = GetBootOption (OptionOrder [i], &Option);
    DPRINTF_BDS ("  GetOption Option [%d] = 0x%x, returned %r.\n",
      i, OptionOrder [i], Status);
    if (EFI_ERROR(Status)) {
      continue;
    }

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_HIDE_INVALID_BOOT_OPTION

    //
    // If the FilePathList is HDD Media Device Path, validate it first.
    //

    if (Option->FilePathList->Type == MEDIA_DEVICE_PATH &&
      Option->FilePathList->SubType == MEDIA_HARDDRIVE_DP) {

      Status = HddDevicePathExpansion (
                 Option->FilePathList,
                 &ExpandDevicePath,
                 &NumberOfDevicePath);

      DPRINTF_BDS ("  HddDevicePathExpansion Returned %r\n", Status);
      if (EFI_ERROR (Status) || NumberOfDevicePath == 0) {
        Option->Attributes |= LOAD_OPTION_HIDDEN;
      } else {
        SafeFreePool (ExpandDevicePath);
      }
    }

#endif

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

    Status = ConstructBdsServicesNodeNoChildren (Option, p);
    DPRINTF_BDS (
      "  ConstructBdsServicesNode [0x%04x] returned %r.\n",
      OptionOrder [i],
      Status);

#else

    Status = ConstructBdsServicesNode (Option, NULL, p);
    DPRINTF_BDS (
      "  ConstructBdsServicesNode [0x%04x] returned %r.\n",
      OptionOrder [i],
      Status);

#endif

    if (EFI_ERROR (Status)) {
      return Status;
    }

    q = *p;
    p = &(q->Next);

  }

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS && \
   (CONFIG_BBS_MULTIBOOT_TYPE == BBS_MULTIBOOT_TYPE_3)

  GroupEnumeratedBootOptionsIntoType (*BootListHead);

#endif

  SafeFreePool (OptionOrder);
  return SCT_STATUS_SUCCESS;
} // BdsServicesGetBootList

//
// FUNCTION NAME.
//      SetBootList - Change the order or elements in a boot list.
//
// FUNCTIONAL DESCRIPTION.
//      This function changes a Boot List. The expected usage is that the
//      GetBootList function will be called and then the list returned by that
//      function would be modified and passed back to this function.
//
//      Options can be reordered, deleted or added to the list with this
//      function. Note that the Boot Options cannot be added in this function.
//      The Boot Option must already exist before an attempt to add it to a
//      Boot List with this function.
//
//      Option attributes cannot be modified with this function.
//
//      A Boot List can be created or deleted with this function. If the Boot
//      List does not already exist it will be created. If this function is
//      called with the BootListHead parameter set to NULL the Boot List will
//      be deleted. In the case of the UEFI defined boot list, deleting the
//      list will cause the Boot Manager to load the default list on the next
//      boot. For other Boot Lists the behavior depend on the owners of those
//      lists.
//
//      The BootListName parameter may be set to NULL. In this case the Boot
//      List being referenced is the UEFI Specification defined Boot List
//      which is saved in the BootOrder variable. See Chapter 3 of the UEFI
//      Specification for more details on the BootOrder variable.
//
//      For the purposes of this function the Child pointers in the
//      SCT_BDS_SERVICES_BOOT_OPTION objects will be ignored. Boot Lists only
//      refer to the first level of the Boot Option tree.
//
// ENTRY PARAMETERS.
//      BootListName    - the string pointer for the name of the Boot List.
//      BootListHead    - a pointer to the start of a linked list of
//                        SCT_BDS_SERVICES_BOOT_OPTION objects.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesSetBootList (
  IN CONST PCHAR16 BootListName,
  IN PSCT_BDS_SERVICES_BOOT_OPTION BootListHead
  )
{
  UINTN i;
  EFI_STATUS Status;
  PUINT16 BootListVariable;
  PCHAR16 LocalBootListName;
  PSCT_BDS_SERVICES_BOOT_OPTION p;
  PUINT16 ProtectedBootOptions;
  UINTN ProtectedBootOptionsSize;
  BOOLEAN OptionIsPresent;
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS && \
   (CONFIG_BBS_MULTIBOOT_TYPE == BBS_MULTIBOOT_TYPE_3)
  PSCT_BDS_SERVICES_BOOT_OPTION Child;
#endif

  DPRINTF_BDS ("BdsServicesSetBootList:\n");

  if (BootListName != NULL) {
    if (StrCmp (BootListName, EFI_BOOT_ORDER_VARIABLE_NAME) != 0) {
      DPRINTF_BDS ("  BootListName \"%s\", not found.\n", BootListName);
      return SCT_STATUS_NOT_FOUND;
    }
  }
  LocalBootListName = EFI_BOOT_ORDER_VARIABLE_NAME;

  //
  // Determine if this BootList is attempting to remove a ProtectedBootOption
  // from the BootList.
  //

  ProtectedBootOptions = NULL;
  ProtectedBootOptions = SctLibGetVariableAndSize (
                           L"ProtectedBootOptions",
                           &gSctBdsServicesProtocolGuid,
                           &ProtectedBootOptionsSize);

  if (ProtectedBootOptions == NULL) {
    return EFI_NOT_FOUND;
  }

  //
  // Walk the list of protected options and make sure each exists in the new
  // BootList.
  //

  for (i = 0; i < (ProtectedBootOptionsSize / sizeof (UINT16)); i++) {
    p = BootListHead;
    OptionIsPresent = FALSE;
    while (TRUE) {
      if (p == NULL) {
        break;
      }
      if (p->OptionNumber == ProtectedBootOptions [i]) {
        OptionIsPresent = TRUE;
        break;
      }
      p = p->Next;
    }
    if (!OptionIsPresent) {
      SafeFreePool (ProtectedBootOptions);
      return SCT_STATUS_ACCESS_DENIED;
    }
  }

  //
  // Count the number of Nodes in the Boot List.
  //

  p = BootListHead;
  i = 0;
  while (TRUE) {
    if (p == NULL) {
      break;
    }
    i++;
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS && \
   (CONFIG_BBS_MULTIBOOT_TYPE == BBS_MULTIBOOT_TYPE_3)
    //
    // Count the child.
    //

    if (p->Child != NULL) {
      Child = p->Child;
      while (Child != NULL) {
        i++;
        Child = Child->Next;
      }
    }
#endif
    p = p->Next;
  }

  //
  // Allocate Space for the variable.
  //

  BootListVariable = AllocateZeroPool (i * sizeof (UINT16));

  //
  // Fill out the variable based on the Boot List.
  //

  p = BootListHead;
  i = 0;
  while (TRUE) {
    if (p == NULL) {
      break;
    }
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS && \
   (CONFIG_BBS_MULTIBOOT_TYPE == BBS_MULTIBOOT_TYPE_3)
    if (p->Child != NULL) {
      Child = p->Child;
      while (Child != NULL) {
        BootListVariable [i] = Child->OptionNumber;
        Child = Child->Next;
        i++;
      }
    } else {
      BootListVariable [i] = p->OptionNumber;
      i++;
    }
#else
    BootListVariable [i] = p->OptionNumber;
    i++;
#endif
    p = p->Next;
  }

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_HIDE_INVALID_BOOT_OPTION
  AddOsBootOptionIntoBootOrder (&BootListVariable, &i);
#endif

  if (i > CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  //
  // Save the variable.
  //

  Status = SetEfiGlobalVariable (
             LocalBootListName,
             EFI_VARIABLE_NON_VOLATILE|
             EFI_VARIABLE_BOOTSERVICE_ACCESS|
             EFI_VARIABLE_RUNTIME_ACCESS,
             i * sizeof (UINT16),
             BootListVariable);

  SafeFreePool (BootListVariable);
  return Status;
} // BdsServicesSetBootList

//
// FUNCTION NAME.
//      DestroyBdsBootList - Free the Memory for a BDS Services Boot List.
//
// FUNCTIONAL DESCRIPTION.
//      This function walks a list of BDS Services Nodes and frees all the
//      memory associated with each node.
//
// ENTRY PARAMETERS.
//      BootListHead    - pointer to the first node in the list.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
DestroyBdsBootList (IN PSCT_BDS_SERVICES_BOOT_OPTION BootListHead)
{
  PSCT_BDS_SERVICES_BOOT_OPTION p, q;

  DPRINTF_BDS_MM ("DestroyBdsBootList @ 0x%x.\n", BootListHead);

  p = BootListHead;
  while (TRUE) {
    if (p == NULL) {
      break;
    }
    DPRINTF_BDS_MM ("  Node @ 0x%x.\n", p);

    DPRINTF_BDS_MM ("  Node->Description @ 0x%x.\n", p->Description);
    SafeFreePool (p->Description);

    DPRINTF_BDS_MM ("  Node->FilePathList @ 0x%x.\n", p->FilePathList);
    SafeFreePool (p->FilePathList);

    DPRINTF_BDS_MM ("  Node->OptionalData @ 0x%x.\n", p->OptionalData);
    SafeFreePool (p->OptionalData);

    DPRINTF_BDS_MM ("  Step into child @ 0x%x.\n", p->Child);
    DestroyBdsBootList (p->Child);

    q = p->Next;        // Save the next pointer so we can free p.
    DPRINTF_BDS_MM ("  Free Node.\n");
    SafeFreePool (p);
    p = q;                              // restore the saved next pointer.
  }
  return SCT_STATUS_SUCCESS;
} // DestroyBdsBootList

//
// FUNCTION NAME.
//      DestroyBopChildList - Free the Memory for a BOP Child List.
//
// FUNCTIONAL DESCRIPTION.
//      This function walks a list of Boot Option Protocol nodes and frees all
//      the memory associated with each node.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
DestroyBopChildList (IN PSCT_BOOT_OPTION_NODE ChildList)
{
  PSCT_BOOT_OPTION_NODE p, q;

  DPRINTF_BDS_MM ("DestroyBopChildList @ 0x%x.\n", ChildList);

  p = ChildList;
  while (TRUE) {
    if (p == NULL) {
      break;
    }
    DPRINTF_BDS_MM ("  Node @ 0x%x.\n", p);
    q = p->Next;                        // save the next pointer so we can free p.

    DPRINTF_BDS_MM ("  Node->Description @ 0x%x.\n", p->Description);
    SafeFreePool (p->Description);

    DPRINTF_BDS_MM ("  Node->FilePathList @ 0x%x.\n", p->FilePathList);
    SafeFreePool (p->FilePathList);

    DPRINTF_BDS_MM ("  Free Node.\n");
    SafeFreePool (p);

    p = q;                              // restore the saved next pointer.
  }

  return SCT_STATUS_SUCCESS;
} // DestroyBopChildList

//
// FUNCTION NAME.
//      BdsServicesGetBootOptionList - Get a List of All Boot Options.
//
// FUNCTIONAL DESCRIPTION.
//      This function returns a linked list of all Boot Options.
//
//      This function uses the SCT_BDS_SERVICES_BOOT_OPTION object to return
//      the data, but the list in one dimensional. The Child field is never
//      used to point to nested nodes and will always be set to NULL.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      BootOptionList  - the address of a pointer to the first Boot Option in
//                        the returned list of Boot Options.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesGetBootOptionList (OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootOptionList)
{
  SCT_STATUS Status;
  PLOAD_OPTION_OBJECT p;
  PSCT_BDS_SERVICES_BOOT_OPTION *q;

  DPRINTF_BDS ("BdsServicesGetBootOptionList.\n");

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  EnumerateAllLoadOptions ();
#endif

  p = NULL;
  Status = GetBootOptionListHead (&p);
  if ((EFI_ERROR (Status)) || (p == NULL)) {
    DPRINTF_BDS ("  GetBootOptionListHead returned %r.\n");
    return SCT_STATUS_NOT_FOUND;
  }

  //
  // Convert from Boot Manager private data into BdsServices Boot Option
  // objects.
  //

  q = BootOptionList;
  while (TRUE) {
    if (p == NULL) {
      break;
    }

    Status = ConstructBdsServicesNodeNoChildren (p, q);
    if (EFI_ERROR (Status)) {
      DPRINTF_BDS ("  ConstructBdsServicesNodeNoChildren returned %r.\n");
      DestroyBdsBootList (*BootOptionList);
      return Status;
    }

    //
    // Advance both pointers. q to the address of the next destination pointer,
    // and p to the address of the next source object.
    //

    q = &((*q)->Next);
    p = p->Next;
  }

  return SCT_STATUS_SUCCESS;
} // BdsServicesGetBootOptionList

//
// FUNCTION NAME.
//      BdsServicesGetBootOption - Get a Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets a single boot option by number.
//
//      This function uses the SCT_BDS_SERVICES_BOOT_OPTION object to return
//      the data, but there is no list. The Child and Next nodes will be set
//      to NULL.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 number representing the Option.
//
// EXIT PARAMETERS.
//      BootOption      - the address of a pointer to the Boot Option.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesGetBootOption (
  IN UINT16 OptionNumber,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootOption)
{
  SCT_STATUS Status;
  PLOAD_OPTION_OBJECT p;

  DPRINTF_BDS ("BdsServicesGetBootOption.\n");

  Status = GetBootOption (OptionNumber, &p);
  if (EFI_ERROR (Status)) {
    DPRINTF_BDS ("  GetOption returned %r.\n", Status);
    return Status;
  }

  Status = ConstructBdsServicesNodeNoChildren (p, BootOption);
  if (EFI_ERROR (Status)) {
    DPRINTF_BDS ("  ConstructBdsServicesNodeNoChildren returned %r.\n");
    return Status;
  }

  return SCT_STATUS_SUCCESS;
} // BdsServicesGetBootOption

//
// FUNCTION NAME.
//      BdsServicesGetDefaultBootOption - Get a Default Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets a single default boot option by number. It uses the
//      FilePathList of input boot option as the index, and searchs its matched
//      boot option definition in the boot manager configuration file.
//
//      This function uses the SCT_BDS_SERVICES_BOOT_OPTION object to return
//      the data, but there is no list. The Child and Next nodes will be set
//      to NULL.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 number representing the Option.
//
// EXIT PARAMETERS.
//      BootOption      - the address of a pointer to the Boot Option.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
BdsServicesGetDefaultBootOption (
  IN UINT16 OptionNumber,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BootOption
  )
{
  UINT8 Index;
  SCT_STATUS Status;
  UINTN DevicePathSize;
  PLOAD_OPTION_OBJECT p;
  PBOOT_MANAGER_CONFIGURATION q;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *DevicePathInstance;

  DPRINTF_BDS ("BdsServicesGetBootOption.\n");

  if (BootOption == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = GetBootOption (OptionNumber, &p);
  if (EFI_ERROR (Status)) {
    DPRINTF_BDS ("  GetOption returned %r.\n", Status);
    return Status;
  }

  DevicePath = NULL;
  Index = 0;
  while (TRUE) {

    if (mBootReorder.IsReOrdered == 'Y') {
      q = &mBootManagerConfigurationTable [mBootReorder.ReOrder [Index]];
    } else {
      q = &mBootManagerConfigurationTable [Index];
    }

    if (q->Flags & SCT_BM_FLAGS_END) {
      DPRINTF_BDS ("  mBootManagerConfigurationTable End.\n");
      return SCT_STATUS_NOT_FOUND;
    }
    DPRINTF_BDS ("  q @ 0x%x, q->TextDevicePath @ 0x%x = 0x%x.\n",
      q,
      &(q->TextDevicePath),
      q->TextDevicePath);

    DPRINTF_BDS ("  Processing %s.\n", q->TextDevicePath);
    DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (q->TextDevicePath);
    if (DevicePath != NULL) {
      if (!CompareMem (p->FilePathList, DevicePath, p->FilePathListLength)) {
        break;
      }
      SafeFreePool (DevicePath);
      DevicePath = NULL;
    }

    //
    // Check if the prefix of description is the same.
    //

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
    if (StrnCmp (p->Description, q->Description, StrLen (q->Description)) == 0) {
      break;
    }
#endif
    Index++;
  }

  //
  // Create a new BdsServices Boot Option object.
  //

  *BootOption = AllocateZeroPool (sizeof (SCT_BDS_SERVICES_BOOT_OPTION));
  if (*BootOption == NULL) {
    SafeFreePool (DevicePath);
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  //
  // Fill out the immediate fields in the object.
  //

  (*BootOption)->OptionNumber = p->OptionNumber;
  (*BootOption)->Attributes = q->OptionAttributes;
  (*BootOption)->DescriptionLength = StrSize (q->Description);
  (*BootOption)->FilePathListLength = (UINT16) GetDevicePathSize (DevicePath);

  //
  // Count the number of device paths in FilePathList.
  //

  (*BootOption)->NumberOfFilePaths = 1;

  if (IsDevicePathMultiInstance (DevicePath)) {
    DevicePathInstance = DevicePath;
    while (TRUE) {
      GetNextDevicePathInstance (&DevicePathInstance, &DevicePathSize);
      if (DevicePathInstance == NULL) {
        break;
      }
      (*BootOption)->NumberOfFilePaths++;
    }
  }

  if (q->OptionData == NULL) {
    (*BootOption)->OptionalDataLength = 0;
  } else {
    (*BootOption)->OptionalDataLength = (UINT32) StrSize (q->OptionData);
  }
  (*BootOption)->ChildIndex = SCT_BOOT_OPTION_NODE_INVALID_CHILD_INDEX;

  //
  // Copy over the data that this object points to.
  //

  if ((*BootOption)->DescriptionLength > 0) {
    (*BootOption)->Description = AllocateCopyPool (
                                   (*BootOption)->DescriptionLength,
                                   q->Description);
    if ((*BootOption)->Description == NULL) {
      SafeFreePool (*BootOption);
      *BootOption = NULL;
      SafeFreePool (DevicePath);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  if ((*BootOption)->FilePathListLength > 0) {
    (*BootOption)->FilePathList = AllocateCopyPool (
                                    (*BootOption)->FilePathListLength,
                                    DevicePath);
    if ((*BootOption)->FilePathList == NULL) {
      SafeFreePool (*BootOption);
      *BootOption = NULL;
      SafeFreePool (DevicePath);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  if ((*BootOption)->OptionalDataLength > 0) {
    (*BootOption)->OptionalData = AllocateCopyPool (
                                    (*BootOption)->OptionalDataLength,
                                    q->OptionData);
    if ((*BootOption)->OptionalData == NULL) {
      SafeFreePool (*BootOption);
      *BootOption = NULL;
      SafeFreePool (DevicePath);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  SafeFreePool (DevicePath);
  return SCT_STATUS_SUCCESS;
} // BdsServicesGetDefaultBootOption

//
// FUNCTION NAME.
//      BdsServicesSetBootOption - Set Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function sets a single boot option.
//
//      This function uses the SCT_BDS_SERVICES_BOOT_OPTION object to define
//      the data, but there is no list. The Child and Next nodes will be
//      ignored by BdsServices.
//
//      With this function a boot option can be created, an existing boot
//      option can modified and an existing boot option can be deleted.
//
//      To create a new boot option the OptioNumber field must either refer to
//      an OptionNumber not currently in use or the special value 0xFFFF, which
//      indicates to BdsServices that a new OptionNumber should be assigned by
//      BdsServices.
//
//      To modify an existing boot option the OptionNumber field is set to the
//      existing option's value and the other fields are set to the new data.
//
//      To delete an existing boot option the OptionNumber field is set to the
//      existing option's value, the Description, FilePathList and OptionalData
//      fields are set to NULL, and the DescriptionLength, FilePathListLength,
//      NumberOfFilePaths and OptionalDataLength fields are set to zero.
//
// ENTRY PARAMETERS.
//      BootOption      - a pointer to the Boot Option to set.
//
// EXIT PARAMETERS.
//      BootOption      - if a new OptionNumber was requested the
//                        BootOption->OptionNumber value will be updated with
//                        the assigned option number.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesSetBootOption (IN OUT PSCT_BDS_SERVICES_BOOT_OPTION BootOption)
{
  SCT_STATUS Status;
  PLOAD_OPTION_OBJECT p;

  DPRINTF_BDS ("BdsServicesSetBootOption.\n");

  //
  // The input option must be properly constructed. This means that the pointer
  // will not be NULL.
  //

  if (BootOption == NULL) {
    DPRINTF_BDS ("  Invalid parameter.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Check for the Delete case. The only field that will be non-NULL is the
  // OptionNumber.
  //


  if ((BootOption->OptionNumber != SCT_BDS_SERVICES_BOOT_OPTION_INVALID_OPTION_NUMBER) &&
      (BootOption->Attributes == 0) &&
      (BootOption->DescriptionLength == 0) &&
      (BootOption->Description == NULL) &&
      (BootOption->FilePathListLength == 0) &&
      (BootOption->FilePathList == NULL) &&
      (BootOption->NumberOfFilePaths == 0) &&
      (BootOption->OptionalDataLength == 0) &&
      (BootOption->OptionalData == NULL)) {
    DPRINTF_BDS ("  Delete this option.\n");

    //
    // If this option exists in the database, remove it.
    //

    Status = GetBootOption (BootOption->OptionNumber, &p);
    if (!EFI_ERROR (Status)) {
      RemoveOption (p);
    }

    //
    // In any case try to delete the variable. Always return success.
    //

    if (BootOption != NULL) {
        DeleteBootOption (BootOption->OptionNumber);
    } else {
        DPRINTF_BDS ("  Error: A NULL pointer pass to DeleteBootOption()!\n");
    }

    return SCT_STATUS_SUCCESS;
  }

  if (BootOption->OptionNumber == SCT_BDS_SERVICES_BOOT_OPTION_INVALID_OPTION_NUMBER) {
    DPRINTF_BDS ("  Assign a new option number.\n");

    //
    // Create a new node with a new option number.
    //

    Status = GetNewOptionNumber (&(BootOption->OptionNumber), SCT_BM_LO_BOOT);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  DPRINTF_BDS ("  Create the option.\n");
  return CreateOption (
           BootOption->OptionNumber,
           SCT_BM_LO_BOOT,
           BootOption->Attributes,
           BootOption->Description,
           BootOption->FilePathList,
           BootOption->OptionalDataLength,
           BootOption->OptionalData,
           NULL);
} // BdsServicesSetBootOption

//
// FUNCTION NAME.
//      DestroyBdsHotkeyList - Free the Memory for a BDS Services Hotkey List.
//
// FUNCTIONAL DESCRIPTION.
//      This function walks a list of BDS Services Hotkey Nodes and frees all
//      the memory associated with each node.
//
// ENTRY PARAMETERS.
//      HotkeyListHead  - pointer to the first node in the list.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
DestroyBdsHotkeyList (IN PSCT_BDS_SERVICES_HOTKEY_OBJECT HotkeyListHead)
{
  PSCT_BDS_SERVICES_HOTKEY_OBJECT p, q;

  DPRINTF_BDS_MM ("DestroyBdsHotkeyList @ 0x%x.\n", HotkeyListHead);
  p = HotkeyListHead;

  while (TRUE) {
    if (p == NULL) {
      break;
    }

    SafeFreePool (p->DescriptionData->BootString);
    SafeFreePool (p->DescriptionData->ActiveString);
    SafeFreePool (p->DescriptionData->KeyString);
    SafeFreePool (p->DescriptionData->OptionData);
    SafeFreePool (p->DescriptionData);
    SafeFreePool (p->KeyOptionData);

    q = p->Next;
    SafeFreePool (p);
    p = q;
  }
  return SCT_STATUS_SUCCESS;

} // DestroyBdsHotkeyList

//
// FUNCTION NAME.
//      BdsServicesGetHotkeyList - Get a List of All the Hotkeys.
//
// FUNCTIONAL DESCRIPTION.
//      This function returns a list of all hotkeys.
//
//      This function returns a linked list of SCT_BDS_SERVICES_HOTKEY_OBJECT
//      objects.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      HotkeyList      - The address of a pointer to the first Hotkey object in
//                        the list of Hotkeys.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesGetHotkeyList (OUT PSCT_BDS_SERVICES_HOTKEY_OBJECT *HotkeyList)
{
  SCT_STATUS Status;
  PSCT_BDS_SERVICES_HOTKEY_OBJECT *p;
  PHOTKEY_OBJECT HotkeyListHead;

  DPRINTF_BDS ("BdsServicesGetHotkeyList.\n");

  HotkeyListHead = NULL;

  if (HotkeyList == NULL) {
    DPRINTF_BDS (" An output parameter was NULL.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  p = HotkeyList;
  GetHotkeyListHead (&HotkeyListHead);

  while (TRUE) {

    if (HotkeyListHead == NULL) {
      break;
    }

    Status = ConstructBdsHotKeyObject (
               HotkeyListHead->KeyOptionNumber,
               HotkeyListHead->KeyOptionSize,
               HotkeyListHead->KeyOptionData,
               (PSCT_BDS_SERVICES_HOTKEY_DESCRIPTION_DATA) HotkeyListHead->DescriptionData,
               p);
    if (EFI_ERROR (Status)) {

      //
      // Free all created hotkey object in list.
      //

      DestroyBdsHotkeyList (*HotkeyList);
      *HotkeyList = NULL;
      return Status;
    }

    (*p)->State = &(HotkeyListHead->State);
    p = &((*p)->Next);
    HotkeyListHead = HotkeyListHead->Next;

  }

  return SCT_STATUS_SUCCESS;
} // BdsServicesGetHotkeyList

//
// FUNCTION NAME.
//      BdsServicesGetHotkey - Get a Single Hotkey Object.
//
// FUNCTIONAL DESCRIPTION.
//      This function returns a single hotkey based on the KeyOptionNumber.
//
// ENTRY PARAMETERS.
//      KeyOptionNumber - a UINT16 value representing the hotkey requested.
//
// EXIT PARAMETERS.
//      Hotkey          - the address of a pointer to the hotkey object.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesGetHotkey (
  IN UINT16 KeyOptionNumber,
  OUT PSCT_BDS_SERVICES_HOTKEY_OBJECT *Hotkey)
{
  SCT_STATUS Status;
  PHOTKEY_OBJECT HotkeyListHead;

  if (Hotkey == NULL) {
    DPRINTF_BDS (" An output parameter was NULL.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  GetHotkeyListHead (&HotkeyListHead);

  while (TRUE) {
    if (HotkeyListHead == NULL) {
      return SCT_STATUS_NOT_FOUND;
    }
    if (HotkeyListHead->KeyOptionNumber == KeyOptionNumber) {
      break;
    }
    HotkeyListHead = HotkeyListHead->Next;
  }

  Status = ConstructBdsHotKeyObject (
             HotkeyListHead->KeyOptionNumber,
             HotkeyListHead->KeyOptionSize,
             HotkeyListHead->KeyOptionData,
             (PSCT_BDS_SERVICES_HOTKEY_DESCRIPTION_DATA) HotkeyListHead->DescriptionData,
             Hotkey);

  if (!EFI_ERROR (Status)) {
    (*Hotkey)->State = &(HotkeyListHead->State);
  }

  return Status;

} // BdsServicesGetHotkey

//
// FUNCTION NAME.
//      BdsServicesSetHotkey - Set the Values of a Hotkey Object.
//
// FUNCTIONAL DESCRIPTION.
//      This function sets a single hotkey.
//
//      This function uses the SCT_BDS_SERVICES_HOTKEY_OBJECT object to define
//      the data, but there is no list. The Next node will be ignored by
//      BdsServices.
//
//      With this function a hotkey can be created, an existing hotkey
//      can modified and an existing hotkey can be deleted.
//
//      To create a new hotkey the KeyOptionNumber field must either refer to
//      an KeyOptionNumber not currently in use or the special value 0xFFFF,
//      which indicates to BdsServices that a new KeyOptionNumber should be
//      assigned by BdsServices.
//
//      To modify an existing hotkey the KeyOptionNumber field is set to
//      the existing option's value and the other fields are set to the new
//      data.
//
//      To delete an existing boot option the KeyOptionNumber field is set to
//      the existing option's value, the KeyOptionData and DescriptionData
//      fields are set to NULL.
//
// ENTRY PARAMETERS.
//      Hotkey          - a pointer to a hotkey object.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
BdsServicesSetHotkey (IN PSCT_BDS_SERVICES_HOTKEY_OBJECT Hotkey)
{
  HOTKEY_OBJECT *p;
  SCT_STATUS Status;
  UINTN KeyOptionDataSize;
  EFI_BOOT_KEY_DATA_EX BootKeyData;

  KeyOptionDataSize = 0;

  DPRINTF_BDS ("BdsServicesSetHotkey.\n");

  //
  // The input object must be properly constructed. This means that the pointer
  // will not be NULL.
  //

  if (Hotkey == NULL) {
    DPRINTF_BDS ("  Invalid parameter.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Check for the Delete case. The only field that will be non-NULL is the
  // OptionNumber.
  //

  if ((Hotkey->KeyOptionNumber != SCT_BDS_SERVICES_BOOT_OPTION_INVALID_OPTION_NUMBER) &&
      (Hotkey->KeyOptionData == NULL) &&
      (Hotkey->DescriptionData == NULL)) {

    DPRINTF_BDS ("  Delete this Hotkey.\n");

    //
    // If this option exists in the database, remove it.
    //

    Status = GetHotkey (Hotkey->KeyOptionNumber, &p);
    if (!EFI_ERROR (Status)) {
      RemoveHotKey (p);
    }

    //
    // In any case try to delete the variable. Always return success.
    //

    DeleteHotKey (Hotkey->KeyOptionNumber);
    return SCT_STATUS_SUCCESS;
  }

  if (Hotkey->KeyOptionNumber == SCT_BDS_SERVICES_BOOT_OPTION_INVALID_OPTION_NUMBER) {
    DPRINTF_BDS (" Assign a new Hot key number.\n");

    //
    // Create a new HotKey with a new KeyOptionNumber.
    //

    Status = GetNewHotKeyNumber (&(Hotkey->KeyOptionNumber));
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  DPRINTF_BDS (" Create or update the HotKey.\n");

  CopyMem (
    (VOID *)&BootKeyData,
    (VOID *)&(Hotkey->KeyOptionData->KeyData),
    sizeof (EFI_BOOT_KEY_DATA));

  KeyOptionDataSize = sizeof (EFI_KEY_OPTION) +
      BootKeyData.Options.InputKeyCount * sizeof (EFI_INPUT_KEY);

  return CreateOrUpdateHotKey (
           Hotkey->KeyOptionNumber,
           KeyOptionDataSize,
           Hotkey->KeyOptionData,
           (PHOTKEY_DESCRIPTION_DATA) Hotkey->DescriptionData,
           NULL);

} // BdsServicesSetHotkey

//
// Private (static) routines used by this component.
//

//
// FUNCTION NAME.
//      ConstructBdsServicesNodeNoChildren - Allocate and Set a BdsServicesNode.
//
// FUNCTIONAL DESCRIPTION.
//      This function allocates all memory required for a BDS Services Node
//      and fills out all the fields in the node.
//
//      This function does not expand the nodes to produce children.
//
// ENTRY PARAMETERS.
//      Option          - Pointer to an LOAD_OPTION_OBJECT.
//
// EXIT PARAMETERS.
//      BdsServicesNode - The address of a pointer to an SCT_BDS_SERVICES_BOOT_OPTION.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
ConstructBdsServicesNodeNoChildren (
  IN PLOAD_OPTION_OBJECT Option,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BdsServicesNode
  )
{
  DPRINTF_BDS (
    "ConstructBdsServicesNodeNoChildren: Option @ 0x%x, BdsServicesNode @@ 0x%x.\n",
    Option,
    BdsServicesNode);

  //
  // Create a new BdsServices Boot Option object.
  //

  *BdsServicesNode = AllocateZeroPool (sizeof (SCT_BDS_SERVICES_BOOT_OPTION));
  if (*BdsServicesNode == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  //
  // Fill out the immediate fields in the object.
  //

  (*BdsServicesNode)->OptionNumber = Option->OptionNumber;
  (*BdsServicesNode)->Attributes = Option->Attributes;
  (*BdsServicesNode)->DescriptionLength = Option->DescriptionLength;
  (*BdsServicesNode)->FilePathListLength = Option->FilePathListLength;
  (*BdsServicesNode)->NumberOfFilePaths = Option->NumberOfFilePaths;
  (*BdsServicesNode)->OptionalDataLength = Option->OptionalDataLength;
  (*BdsServicesNode)->ChildIndex = SCT_BOOT_OPTION_NODE_INVALID_CHILD_INDEX;

  //
  // Copy over the data that this object points to.
  //

  if (Option->DescriptionLength > 0) {
    (*BdsServicesNode)->Description = AllocateCopyPool (
                                        Option->DescriptionLength,
                                        Option->Description);
    if ((*BdsServicesNode)->Description == NULL) {
      DestroyBdsBootList (*BdsServicesNode);
      *BdsServicesNode = NULL;
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  if (Option->FilePathListLength > 0) {
    (*BdsServicesNode)->FilePathList = AllocateCopyPool (
                                         Option->FilePathListLength,
                                         Option->FilePathList);
    if ((*BdsServicesNode)->FilePathList == NULL) {
      DestroyBdsBootList (*BdsServicesNode);
      *BdsServicesNode = NULL;
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  if (Option->OptionalDataLength > 0) {
    (*BdsServicesNode)->OptionalData = AllocateCopyPool (
                                         Option->OptionalDataLength,
                                         Option->OptionalData);
    if ((*BdsServicesNode)->OptionalData == NULL) {
      DestroyBdsBootList (*BdsServicesNode);
      *BdsServicesNode = NULL;
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  return SCT_STATUS_SUCCESS;
} // ConstructBdsServicesNodeNoChildren

//
// FUNCTION NAME.
//      ConstructBdsServicesNode - Allocate and Set a BdsServicesNode.
//
// FUNCTIONAL DESCRIPTION.
//      This function allocates all memory required for a BDS Services Node
//      and fills out all the fields in the node.
//
//      After populating the fields this function checks the device path to see
//      if it can be expanded with a Boot Option Protocol. If it can be
//      expanded this function will use the GetChildren function of the Boot
//      Option Protocol instance to find all the child nodes, recursing through
//      the children.
//
// ENTRY PARAMETERS.
//      Option          - Pointer to an LOAD_OPTION_OBJECT, the root parent.
//      Child           - Point to he child node information PSCT_BOOT_OPTION_NODE.
//
// EXIT PARAMETERS.
//      BdsServicesNode - the address of a pointer to an
//                        SCT_BDS_SERVICES_BOOT_OPTION.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
ConstructBdsServicesNode (
  IN PLOAD_OPTION_OBJECT Option,
  IN PSCT_BOOT_OPTION_NODE Child,
  OUT PSCT_BDS_SERVICES_BOOT_OPTION *BdsServicesNode
  )
{
  SCT_STATUS Status;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *BopDp;
  PSCT_BOOT_OPTION_PROTOCOL BootOptionProtocol;
  PSCT_BOOT_OPTION2_PROTOCOL BootOption2Protocol;
  PSCT_BOOT_OPTION_NODE Children, p;
  UINTN DescriptionLength;
  PCHAR16 Description;
  UINT16 FilePathListLength;
  EFI_DEVICE_PATH_PROTOCOL *FilePathList;
  UINTN NumberOfFilePaths;
  PVOID Context;
  UINTN ContextSize;
  UINT8 ChildIndex;
  PSCT_BDS_SERVICES_BOOT_OPTION *q;
  UINT32 Attributes;

  DPRINTF_BDS (
    "ConstructBdsServicesNode: Option @ 0x%x, Child @ 0x%x, BdsServicesNode @@ 0x%x.\n",
    Option,
    Child,
    BdsServicesNode);

  //
  // Child nodes inherit some fields from the parent. Those that are not
  // inherited need to be used from the Child pointer instead of from the
  // Option pointer.
  //

  if (Child == NULL) {

    //
    // Not a child node. Set all the fields to the Option parameters.
    //

    DescriptionLength = Option->DescriptionLength;
    Description = Option->Description;
    FilePathListLength = Option->FilePathListLength;
    FilePathList = Option->FilePathList;
    NumberOfFilePaths = Option->NumberOfFilePaths;
    ChildIndex = SCT_BOOT_OPTION_NODE_INVALID_CHILD_INDEX;
    Attributes = Option->Attributes;
  } else {

    //
    // Is a child node. Set the child related fields to the Child parameters.
    //

    if (Child->Description != NULL) {
      DescriptionLength = StrSize (Child->Description);
    } else {
      DescriptionLength = 0;
    }

    Description = Child->Description;
    FilePathListLength = Child->FilePathListLength;
    FilePathList = Child->FilePathList;
    NumberOfFilePaths = Child->NumberOfFilePaths;
    ChildIndex = Child->ChildIndex;
    Attributes = Child->Attributes;
  }
  DPRINTF_BDS (
    "  DescriptionLength = 0x%x, Description = %s.\n",
    DescriptionLength,
    Description);
  DPRINTF_BDS (
    "  FilePathListLength = 0x%x, FilePathList @ 0x%x, NumberOfFilePaths = 0x%x.\n",
    FilePathListLength,
    FilePathList,
    NumberOfFilePaths);

  //
  // Create a new SCT_BDS_SERVICES_BOOT_OPTION, attach it to the list. p is the
  // address of the next point, so de-reference it to get the pointer to the
  // SCT_BDS_SERVICES_BOOT_OPTION.
  //

  *BdsServicesNode = AllocateZeroPool (sizeof (SCT_BDS_SERVICES_BOOT_OPTION));
  if (*BdsServicesNode == NULL) {
    DPRINTF_BDS ("  Failed to allocate SCT_BDS_SERVICES_BOOT_OPTION.\n");
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
  DPRINTF_BDS (
    "  New BdsServicesNode 0x%x:0x%x\n",
    BdsServicesNode,
    *BdsServicesNode);

  //
  // Copy the fields from this LOAD_OPTION_OBJECT (Option) to this
  // SCT_BDS_SERVICES_BOOT_OPTION (*BdsServicesNode).
  //

  (*BdsServicesNode)->OptionNumber = Option->OptionNumber;
  (*BdsServicesNode)->Attributes = Attributes;

  (*BdsServicesNode)->DescriptionLength = DescriptionLength;
  if (DescriptionLength > 0) {
    (*BdsServicesNode)->Description = AllocateCopyPool (
                                        DescriptionLength,
                                        Description);
    if ((*BdsServicesNode)->Description == NULL) {
      DPRINTF_BDS ("  Failed to allocate Description.\n");
      SafeFreePool (*BdsServicesNode);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }


  (*BdsServicesNode)->FilePathListLength = FilePathListLength;
  (*BdsServicesNode)->NumberOfFilePaths = NumberOfFilePaths;
  if (FilePathListLength > 0) {
    (*BdsServicesNode)->FilePathList = AllocateCopyPool (
                                         FilePathListLength,
                                         FilePathList);
    if ((*BdsServicesNode)->FilePathList == NULL) {
      DPRINTF_BDS ("  Failed to allocate FilePathList.\n");
      SafeFreePool ((*BdsServicesNode)->Description);
      SafeFreePool (*BdsServicesNode);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  (*BdsServicesNode)->OptionalDataLength = Option->OptionalDataLength;
  if ((*BdsServicesNode)->OptionalDataLength > 0) {
    (*BdsServicesNode)->OptionalData = AllocateCopyPool (
                           Option->OptionalDataLength,
                           Option->OptionalData);
    if ((*BdsServicesNode)->OptionalData == NULL) {
      DPRINTF_BDS ("  Failed to allocate OptionalData.\n");
      SafeFreePool ((*BdsServicesNode)->FilePathList);
      SafeFreePool ((*BdsServicesNode)->Description);
      SafeFreePool (*BdsServicesNode);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  (*BdsServicesNode)->ChildIndex = ChildIndex;

  //
  // Check for Boot Option Protocol. If this device path is for BOP locate
  // the protocol instance and call the GetChildren to populate the
  // (*BdsServicesNode)->Child pointer.
  //

  if (IsDeviceNodeBootOptionProtocol (FilePathList)) {
    DPRINTF_BDS ("  Found a Boot Option Protocol device path.\n");

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
    DPRINTF_BDS ("  Found %d bytes of context.\n", ContextSize);

    Status = gBS->LocateProtocol (
                    &(BopDp->ProtocolGuid),
                    NULL,
                    (VOID **) &BootOptionProtocol);

    if (EFI_ERROR (Status)) {
      DPRINTF_BDS ("  Failed to LocateProtocol, %r.\n", Status);
      return SCT_STATUS_SUCCESS;
    }

    //
    // Check if it is SCT_BOOT_OPTION_PROTOCOL or SCT_BOOT_OPTION2_PROTOCOL by checking the size,
    // then assign the original DevicePath back, so the HttpBop driver could transfer the BOP
    // DevicePath to the physical DevicePath which include the assigned URI.
    //

    if (BootOptionProtocol->Size == SCT_BOOT_OPTION_PROTOCOL2_SIZE) {
      BootOption2Protocol = (PSCT_BOOT_OPTION2_PROTOCOL) BootOptionProtocol;
      BootOption2Protocol->OriginalPathList = DuplicateDevicePath (FilePathList);
    }

    Children = NULL;
    Status = BootOptionProtocol->GetChildren (
                                   BootOptionProtocol,
                                   Context,
                                   ContextSize,
                                   &Children);
    DPRINTF_BDS (
      "  BootOptionProtocol->GetChildren returned %r.\n",
      Status);
    if (EFI_ERROR (Status)) {
      return SCT_STATUS_SUCCESS;
    }

    //
    // Walk through the child nodes and recurse into each.
    //

    p = Children;
    q = &((*BdsServicesNode)->Child);
    while (TRUE) {
      if (p == NULL) {
        break;
      }

      Status = ConstructBdsServicesNode (Option, p, q);
      if (EFI_ERROR (Status)) {
        DestroyBopChildList (Children);
        return Status;
      }
      p = p->Next;
      q = &((*q)->Next);
    }
    DestroyBopChildList (Children);
  }

  return SCT_STATUS_SUCCESS;
} // ConstructBdsServicesNode

//
// FUNCTION NAME.
//      ConstructBdsHotKeyObject - Allocate memory and fill in parameters.
//
// FUNCTIONAL DESCRIPTION.
//      This function will allocate memory needed for a new option
//      and copy the parameters provided into the new structure.
//
// ENTRY PARAMETERS.
//      KeyOptionNumber - the number to use as KeyOptionNumber.
//      KeyOptionSize   - the number of bytes in the data buffer pointed to by
//                        KeyOptionData.
//      KeyOptionData   - ptr to the key option data.
//      DescriptionData - information about how to display this hotkey.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      HotKeyObject    - the address of a pointer that will be updated with
//                        the address of the newly created key option.
//
// WARNINGS.
//      None.
//

SCT_STATUS
ConstructBdsHotKeyObject (
  IN UINT16 KeyOptionNumber,
  IN UINTN KeyOptionSize,
  IN EFI_KEY_OPTION *KeyOptionData,
  IN PSCT_BDS_SERVICES_HOTKEY_DESCRIPTION_DATA DescriptionData, OPTIONAL
  OUT SCT_BDS_SERVICES_HOTKEY_OBJECT **HotKeyObject
  )
{
  SCT_STATUS Status;
  UINTN BootStringSize, ActiveStringSize;
  UINTN KeyStringSize, OptionDataSize;

  DPRINTF_BDS ("ConstructBdsHotKeyObject.\n");

  //
  // Allocate for the main object.
  //

  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  sizeof (SCT_BDS_SERVICES_HOTKEY_OBJECT),
                  (VOID **) HotKeyObject);
  if (EFI_ERROR (Status)) {
    DPRINTF_BDS ("  Couldn't allocate for BdsHotKeyObject, %r.\n", Status);
    return Status;
  }

  //
  // Allocate for our copy of the key data.
  //

  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  KeyOptionSize,
                  (VOID **) &((*HotKeyObject)->KeyOptionData));
  if (EFI_ERROR (Status)) {
    DPRINTF_BDS ("  Couldn't allocate HotKeyObject->KeyOptionData, %r.\n", Status);
    SafeFreePool (*HotKeyObject);
    return Status;
  }

  //
  // Now setup the data structure per the input parameters.
  //

  (*HotKeyObject)->KeyOptionNumber = KeyOptionNumber;

  CopyMem (
    (*HotKeyObject)->KeyOptionData,
    KeyOptionData,
    KeyOptionSize);

  (*HotKeyObject)->Next = NULL;

  //
  // Allocate memory and copy the description data.
  //

  if (DescriptionData == NULL) {
    DPRINTF_BDS ("  DescriptionData is NULL.\n");
    (*HotKeyObject)->DescriptionData = NULL;
  } else {
    Status = (gBS->AllocatePool) (
                    EfiBootServicesData,
                    sizeof (SCT_BDS_SERVICES_HOTKEY_DESCRIPTION_DATA),
                    (VOID **) &((*HotKeyObject)->DescriptionData));
    if (EFI_ERROR (Status)) {
      DPRINTF_BDS ("  Couldn't allocate KeyOption->DescriptionData, %r.\n", Status);
      SafeFreePool ((*HotKeyObject)->KeyOptionData);
      SafeFreePool (*HotKeyObject);
      return Status;
    }

    //
    // Allocate memory for the BootString and copy it over.
    //

    if (DescriptionData->BootString != NULL) {
      BootStringSize = StrSize (DescriptionData->BootString);
      DPRINTF_BDS ("  BootStringSize = 0x%x\n", BootStringSize);
      Status = (gBS->AllocatePool) (
                      EfiBootServicesData,
                      BootStringSize,
                      (VOID **) &((*HotKeyObject)->DescriptionData->BootString));
      if (EFI_ERROR (Status)) {
        DPRINTF_BDS (
          "  Couldn't allocate 0x%x bytes for the BootString, %r.\n",
          BootStringSize,
          Status);
        SafeFreePool ((*HotKeyObject)->DescriptionData);
        SafeFreePool ((*HotKeyObject)->KeyOptionData);
        SafeFreePool (*HotKeyObject);
      }
      DPRINTF_BDS ("  DescriptionData->BootString @ 0x%x\n", DescriptionData->BootString);
      CopyMem (
        (*HotKeyObject)->DescriptionData->BootString,
        DescriptionData->BootString,
        BootStringSize);
    } else {
      (*HotKeyObject)->DescriptionData->BootString = NULL;
    }

    //
    // Allocate memory for the ActiveString and copy it over.
    //

    if (DescriptionData->ActiveString != NULL) {
      ActiveStringSize = StrSize (DescriptionData->ActiveString);
      DPRINTF_BDS ("  ActiveStringSize = 0x%x\n", ActiveStringSize);
      Status = (gBS->AllocatePool) (
                      EfiBootServicesData,
                      ActiveStringSize,
                      (VOID **) &((*HotKeyObject)->DescriptionData->ActiveString));
      if (EFI_ERROR (Status)) {
        DPRINTF_BDS (
          "  Couldn't allocate 0x%x bytes for the ActiveString, %r.\n",
          ActiveStringSize,
          Status);
        SafeFreePool ((*HotKeyObject)->DescriptionData->BootString);
        SafeFreePool ((*HotKeyObject)->DescriptionData);
        SafeFreePool ((*HotKeyObject)->KeyOptionData);
        SafeFreePool (*HotKeyObject);
      }
      DPRINTF_BDS ("  DescriptionData->ActiveString @ 0x%x\n", DescriptionData->ActiveString);
      CopyMem (
        (*HotKeyObject)->DescriptionData->ActiveString,
        DescriptionData->ActiveString,
        ActiveStringSize);
    } else {
      (*HotKeyObject)->DescriptionData->ActiveString = NULL;
    }

    //
    // Allocate memory for the KeyString and copy it over.
    //

    if (DescriptionData->KeyString != NULL) {
      KeyStringSize = StrSize (DescriptionData->KeyString);
      DPRINTF_BDS ("  KeyStringSize = 0x%x\n", KeyStringSize);
      Status = (gBS->AllocatePool) (
                      EfiBootServicesData,
                      KeyStringSize,
                      (VOID **) &((*HotKeyObject)->DescriptionData->KeyString));
      if (EFI_ERROR (Status)) {
        DPRINTF_BDS (
          "  Couldn't allocate 0x%x bytes for the KeyString, %r.\n",
          KeyStringSize,
          Status);
        SafeFreePool ((*HotKeyObject)->DescriptionData->BootString);
        SafeFreePool ((*HotKeyObject)->DescriptionData->ActiveString);
        SafeFreePool ((*HotKeyObject)->DescriptionData);
        SafeFreePool ((*HotKeyObject)->KeyOptionData);
        SafeFreePool (*HotKeyObject);
      }
      DPRINTF_BDS ("  DescriptionData->KeyString @ 0x%x\n", DescriptionData->KeyString);
      CopyMem (
        (*HotKeyObject)->DescriptionData->KeyString,
        DescriptionData->KeyString,
        KeyStringSize);
    } else {
      (*HotKeyObject)->DescriptionData->KeyString = NULL;
    }

    //
    // Allocate memory for the OptionData and copy it over.
    //

    if (DescriptionData->OptionData != NULL) {
      OptionDataSize = StrSize (DescriptionData->OptionData);
      DPRINTF_HK ("  OptionDataSize = 0x%x\n", OptionDataSize);
      Status = (gBS->AllocatePool) (
                      EfiBootServicesData,
                      OptionDataSize,
                      (VOID **) &((*HotKeyObject)->DescriptionData->OptionData));
      if (EFI_ERROR (Status)) {
        DPRINTF_BDS (
          "  Couldn't allocate 0x%x bytes for the OptionData, %r.\n",
          OptionDataSize,
          Status);
        SafeFreePool ((*HotKeyObject)->DescriptionData->BootString);
        SafeFreePool ((*HotKeyObject)->DescriptionData->ActiveString);
        SafeFreePool ((*HotKeyObject)->DescriptionData->KeyString);
        SafeFreePool ((*HotKeyObject)->DescriptionData);
        SafeFreePool ((*HotKeyObject)->KeyOptionData);
        SafeFreePool (*HotKeyObject);
      }
      DPRINTF_BDS ("  DescriptionData->OptionData @ 0x%x\n", DescriptionData->OptionData);
      CopyMem (
        (*HotKeyObject)->DescriptionData->OptionData,
        DescriptionData->OptionData,
        OptionDataSize);
    } else {
      (*HotKeyObject)->DescriptionData->OptionData = NULL;
    }

    //
    // Copy over the Column and Row data.
    //

    (*HotKeyObject)->DescriptionData->Column = DescriptionData->Column;
    (*HotKeyObject)->DescriptionData->Row = DescriptionData->Row;

    //
    // Copy over the BootDisplayString, BootDisplayImage, BootDisplayAttribs,
    // ActiveDisplayString, ActiveDisplayImage, ActiveDisplayAttribs,
    // ImageDisplayOffsetX and ImageDisplayOffsetY data.
    //

    (*HotKeyObject)->DescriptionData->BootDisplayString = DescriptionData->BootDisplayString;
    (*HotKeyObject)->DescriptionData->BootDisplayImage = DescriptionData->BootDisplayImage;
    (*HotKeyObject)->DescriptionData->BootDisplayAttribs = DescriptionData->BootDisplayAttribs;
    (*HotKeyObject)->DescriptionData->ActiveDisplayString = DescriptionData->ActiveDisplayString;
    (*HotKeyObject)->DescriptionData->ActiveDisplayImage = DescriptionData->ActiveDisplayImage;
    (*HotKeyObject)->DescriptionData->ActiveDisplayAttribs = DescriptionData->ActiveDisplayAttribs;
    (*HotKeyObject)->DescriptionData->ImageDisplayOffsetX = DescriptionData->ImageDisplayOffsetX;
    (*HotKeyObject)->DescriptionData->ImageDisplayOffsetY = DescriptionData->ImageDisplayOffsetY;

  }

  return SCT_STATUS_SUCCESS;
} // ConstructBdsHotKeyObject

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_HIDE_INVALID_BOOT_OPTION

//
// FUNCTION NAME.
//      AddOsBootOptionIntoBootOrder - Add OS BootOption into BootOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function will add those BootOptions that created by OS into BootOrder.
//
// ENTRY PARAMETERS.
//      CurrentBootOrder - current BootOrder buffer.
//      CurrentBootOrderCount - number of BootOption in BootOrder.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
AddOsBootOptionIntoBootOrder (
  IN OUT PUINT16 *CurrentBootOrder,
  IN OUT UINTN *CurrentBootOrderCount)
{
  UINTN i;
  SCT_STATUS Status;
  PLOAD_OPTION_OBJECT p;

  DPRINTF_BDS ("\n");
  p = NULL;
  Status = GetBootOptionListHead (&p);
  if ((EFI_ERROR (Status)) || (p == NULL)) {
    DPRINTF_BDS ("  GetBootOptionListHead returned %r.\n");
    return SCT_STATUS_NOT_FOUND;
  }

  while (TRUE) {
    if (p == NULL) {
      break;
    }

    DPRINTF_BDS ("  Option Number      = 0x%x\n", p->OptionNumber);
    DPRINTF_BDS ("  Option Description = %s\n\n", p->Description);
    if (StrCmp (p->Description, L"Windows Boot Manager") == 0) {
      for (i = 0; i < *CurrentBootOrderCount; i++) {
        if (p->OptionNumber == (*CurrentBootOrder) [i]) {
          break;
        }
      }
      if (i == *CurrentBootOrderCount) {

        //
        // Add into BootOrder.
        //

        DPRINTF_BDS ("  Add BootOption 0x%x into BootOrder", p->OptionNumber);
        *CurrentBootOrder = ReallocatePool (
                              *CurrentBootOrderCount * sizeof (UINT16),
                              (*CurrentBootOrderCount + 1) * sizeof (UINT16),
                              *CurrentBootOrder);
        (*CurrentBootOrderCount)++;

        (*CurrentBootOrder) [*CurrentBootOrderCount - 1] = p->OptionNumber;

      }
    }
    p = p->Next;
  }

  return SCT_STATUS_SUCCESS;

} // AddOsBootOptionIntoBootOrder
#endif

//
// FUNCTION NAME.
//      BdsServicesGetDeviceType - Get bootable device type.
//
// FUNCTIONAL DESCRIPTION.
//      This function will verify the device path and report the type.
//
// ENTRY PARAMETERS.
//      DevicePath - a pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      TypeGuid        - device type.
//

EFI_STATUS
EFIAPI
BdsServicesGetDeviceType (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_GUID **TypeGuid
  )
{
  UINT8 Index;
  EFI_STATUS Status;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *BopDp;

  if (DevicePath == NULL || TypeGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Status = EFI_UNSUPPORTED;
  *TypeGuid = &gAnyDeviceBootOptionProtocolGuid;

  if (IsDeviceNodeBootOptionProtocol (DevicePath)) {

    BopDp = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *)DevicePath;
    *TypeGuid = &(BopDp->ProtocolGuid);
    Status = EFI_SUCCESS;

  } else {

    if (IsSupportedBootDevice (DevicePath, NULL, &Index)) {
      Status = GetDeviceGroupGuid (Index, TypeGuid);
    }
  }
  return Status;

} // BdsServicesGetDeviceType

//
// FUNCTION NAME.
//      CopySctBootOption - Copy a single SCT Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function copies a single SCT Boot Option.
//
// ENTRY PARAMETERS.
//      DestSctBootOption - Points to a pre - allocated buffer.
//      SctBootOption   - Points to a single SCT Boot Option.
//      CopyChild       - Boolean: TRUE- ROOT and Children, FALSE: ROOT Only.
//
// EXIT PARAMETERS.
//      TotalCopied     - Total number of BootOption copied.
//      Function Return - SCT status code.
//
// EXIT PARAMETERS.
//        None.
//

SCT_STATUS
CopySctBootOption (
 IN SCT_BDS_SERVICES_BOOT_OPTION **DestSctBootOption,
 IN SCT_BDS_SERVICES_BOOT_OPTION *SourceSctBootOption)
{
  if (SourceSctBootOption == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  (*DestSctBootOption) = AllocateCopyPool  (
          sizeof (SCT_BDS_SERVICES_BOOT_OPTION),
          SourceSctBootOption);

  (*DestSctBootOption)->Child = NULL;
  (*DestSctBootOption)->Next = NULL;

  //
  // Copy Description.
  //

  DPRINTF_BDS (" Copy BootOption for %s\n", SourceSctBootOption->Description);

  if (SourceSctBootOption->DescriptionLength > 0) {
    (*DestSctBootOption)->Description = AllocateCopyPool (
                          SourceSctBootOption->DescriptionLength,
                          SourceSctBootOption->Description);

    if ((*DestSctBootOption)->Description == NULL) {
      DPRINTF_BDS ("  Failed to allocate Description.\n");
      return EFI_OUT_OF_RESOURCES;
    }
  }

  //
  // Copy FilePathList.
  //

  if (SourceSctBootOption->FilePathListLength > 0) {
    (*DestSctBootOption)->FilePathList = AllocateCopyPool (
                           SourceSctBootOption->FilePathListLength,
                           SourceSctBootOption->FilePathList);

    if ((*DestSctBootOption)->FilePathList == NULL) {
      DPRINTF_BDS ("  Failed to allocate FilePathList.\n");
      SafeFreePool ((*DestSctBootOption)->Description);
      return EFI_OUT_OF_RESOURCES;
    }
  }

  //
  // Copy OptionalData.
  //

  if (SourceSctBootOption->OptionalDataLength > 0) {
    (*DestSctBootOption)->OptionalData = AllocateCopyPool (
                           SourceSctBootOption->OptionalDataLength,
                           SourceSctBootOption->OptionalData);

    if ((*DestSctBootOption)->OptionalData == NULL) {
      DPRINTF_BDS ("  Failed to allocate OptionalData.\n");
      SafeFreePool ((*DestSctBootOption)->FilePathList);
      SafeFreePool ((*DestSctBootOption)->Description);
      return EFI_OUT_OF_RESOURCES;
    }
  }

  return EFI_SUCCESS;
} // CopySctBootOption

EFI_STATUS
GroupEnumeratedBootOptionsIntoType (IN SCT_BDS_SERVICES_BOOT_OPTION *SctBootOption)
{
  IN SCT_BDS_SERVICES_BOOT_OPTION *CurrentBootOption;
  IN SCT_BDS_SERVICES_BOOT_OPTION *ChildBootOption;
  IN SCT_BDS_SERVICES_BOOT_OPTION *PrevBootOption;
  IN SCT_BDS_SERVICES_BOOT_OPTION *Child;
  UINT8 GroupIndex;

  GroupIndex = 0;
  CurrentBootOption = NULL;
  ChildBootOption = NULL;
  PrevBootOption = NULL;
  Child = NULL;

  DPRINTF_BDS  ("Entry\n");

  for (; SctBootOption != NULL; SctBootOption = SctBootOption->Next) {

    if (SctBootOption->OptionalDataLength != sizeof (EFI_GUID)) {
      continue;
    }

    DPRINTF_BDS  ("Check OptionNumber:%d\n", SctBootOption->OptionNumber);
    DPRINTF_BDS  ("Description:%s\n", SctBootOption->Description);
    DPRINTF_BDS  ("Device Group GUID:%g\n", SctBootOption->OptionalData);

    //
    // Go through the rest of SctBootOption list to check if the same group GUID exist.
    //

    CurrentBootOption = SctBootOption->Next;
    PrevBootOption = SctBootOption;
    for (; CurrentBootOption != NULL; CurrentBootOption = CurrentBootOption->Next) {

      if(CompareGuid ((EFI_GUID*)(SctBootOption->OptionalData),
                         (EFI_GUID*)(CurrentBootOption->OptionalData))) {

        //
        // Found out the same Group GUID, and attach it at the end of child list.
        //

        DPRINTF_BDS  (" Find OptionNumber:%d\n", CurrentBootOption->OptionNumber);
        DPRINTF_BDS  ("Description:%s\n", CurrentBootOption->Description);
        DPRINTF_BDS  ("with the same Device Group GUID:%g\n", CurrentBootOption->OptionalData);

        if (SctBootOption->Child == NULL) {

          //
          // Create a fake child for Grouping style UI display.
          //

          CopySctBootOption (&ChildBootOption, SctBootOption);

          if (SctBootOption->Description != NULL) {
            SafeFreePool (SctBootOption->Description);
          }

          //
          // Rename SctBootOption's description for being a Parent node for Grouping style UI display.
          //

          GetDeviceGroupIndex ((EFI_GUID*)(SctBootOption->OptionalData), &GroupIndex);
          SctBootOption->Description = GetDeviceGroupPrefix (GroupIndex);
          SctBootOption->DescriptionLength = StrSize ((PCHAR16)SctBootOption->Description);

          //
          // Add SctBootOption and ChildBootOption into parent's child list.
          //

          SctBootOption->Child = ChildBootOption;
          ChildBootOption->Next = CurrentBootOption;

        } else {

          //
          // Add CurrentBootOption in the end of child list of parent's
          //

          Child = SctBootOption->Child;
          while (TRUE) {
            if (Child == NULL) {
              Child = CurrentBootOption;
              break;
            }
            Child = Child->Next;
          }
        }

        //
        // Remove CurrentBootOption from the SctBootOption list.
        //

        PrevBootOption->Next = CurrentBootOption->Next;
        CurrentBootOption->Next = NULL;

        //
        // PrevBootOption is the same one, continue going through rest of list.
        //
        continue;
      } // Compare GUID

      PrevBootOption = CurrentBootOption;
    } // CurrentBootOption

  } // SctBootOption

  return EFI_SUCCESS;
}

#if OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_TEST

//
// FUNCTION NAME.
//      BdsServicesTest - Test the BDS Services Protocol.
//
// FUNCTIONAL DESCRIPTION.
//      This function exercises the BDS Services.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//
// WARNINGS.
//      None.
//

SCT_STATUS
BdsServicesTest (VOID)
{
  UINTN i;
  SCT_STATUS Status;
  PSCT_BDS_SERVICES_PROTOCOL BdsServices;

  PCHAR16 *BootListNames;
  UINTN NumberOfBootLists;

  PCHAR16 BootListDescription;
  PCHAR16 BootListHelp;
  PSCT_BDS_SERVICES_BOOT_OPTION BootListHead;

  DPRINTF ("\n\n*************** BdsServicesTest ***************\n");
  Status = gBS->OpenProtocol (
                    mBootManager.Handle,
                    &gSctBdsServicesProtocolGuid,
                    (VOID **) &BdsServices,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status)) {
    DPRINTF ("  OpenProtocol returned %r.\n", Status);
    return Status;
  }

  Status = BdsServices->GetBootListNames (
                          &BootListNames,
                          &NumberOfBootLists);
  DPRINTF (
    "*************** BdsServicesTest->GetBootListNames returned %r, NumberOfBootLists = %d.\n",
    Status,
    NumberOfBootLists);
  if (!EFI_ERROR (Status)) {
    for (i = 0; i < NumberOfBootLists; i++) {
      DPRINTF ("    %d:%s\n", i, BootListNames [i]);
    }
  }

  //
  // Get one boot list.
  //

  Status = BdsServices->GetBootList (
                          NULL,
                          &BootListDescription,
                          &BootListHelp,
                          &BootListHead);
  DPRINTF (
    "*************** BdsServicesTest->GetBootList returned %r.\n",
    Status);
  if (!EFI_ERROR (Status)) {
    DPRINTF ("    BootListDescription: %s.\n", BootListDescription);
    DPRINTF ("    BootListHelp: %s.\n", BootListHelp);
    DisplayBdsBootList (BootListHead, 4);
    DestroyBdsBootList (BootListHead);
  }

  //
  // Get all the boot options.
  //

  BootListHead = NULL;
  Status = BdsServices->GetBootOptionList (&BootListHead);
  DPRINTF (
    "*************** BdsServicesTest->GetBootOptionList returned %r.\n",
    Status);
  DisplayBdsBootList (BootListHead, 4);
  DestroyBdsBootList (BootListHead);

  BootListHead = NULL;
  Status = BdsServices->GetBootOption (0, &BootListHead);
  DPRINTF (
    "*************** BdsServices->GetBootOption (0, &BootListHead); returned %r.\n",
    Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  DisplayBdsBootList (BootListHead, 4);

  //
  // Now modify it. Then get it again.
  //

  DPRINTF (
    "*************** Modification Test.\n");

  BootListHead->Description = AllocateCopyPool (sizeof L"BdsTest", L"BdsTest");
  Status = BdsServices->SetBootOption (BootListHead);
  DPRINTF (
    "  BdsServices->SetBootOption returned %r.\n",
    Status);
  if (!EFI_ERROR (Status)) {
    DestroyBdsBootList (BootListHead);
  }

  BootListHead = NULL;
  Status = BdsServices->GetBootOptionList (&BootListHead);
  DPRINTF (
    "  BdsServicesTest->GetBootOptionList returned %r.\n",
    Status);
  DisplayBdsBootList (BootListHead, 4);
  DestroyBdsBootList (BootListHead);

  //
  // Now delete it.
  //

  BootListHead = NULL;
  Status = BdsServices->GetBootOption (0, &BootListHead);
  DPRINTF (
    "*************** BdsServices->GetBootOption (0, &BootListHead); returned %r.\n",
    Status);

  BootListHead->Attributes = 0;
  BootListHead->DescriptionLength = 0;
  BootListHead->Description = NULL;
  BootListHead->FilePathListLength = 0;
  BootListHead->FilePathList = NULL;
  BootListHead->NumberOfFilePaths = 0;
  BootListHead->OptionalDataLength = 0;
  BootListHead->OptionalData = 0;

  Status = BdsServices->SetBootOption (BootListHead);
  DPRINTF (
    "*************** BdsServices->SetBootOption returned %r.\n",
    Status);
  DestroyBdsBootList (BootListHead);

  BootListHead = NULL;
  Status = BdsServices->GetBootOptionList (&BootListHead);
  DPRINTF (
    "*************** BdsServicesTest.GetBootOptionList returned %r.\n",
    Status);
  DisplayBdsBootList (BootListHead, 4);
  DestroyBdsBootList (BootListHead);

  return SCT_STATUS_SUCCESS;
} // BdsServicesTest

#endif // OPTION_DEBUG_SYSTEM_BOOT_MANAGER_BDS_TEST
