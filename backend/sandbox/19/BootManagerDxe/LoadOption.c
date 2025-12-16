//
// FILENAME.
//      LoadOption.c - SecureCore Technology(TM) Load Option Services Supporting the Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      This module provides services for managing load options. There are
//      three kinds of "load options" that are discussed in the UEFI
//      Specification, Boot Load Options, Driver Load Options and Application
//      Load Options. The term "load option" is referring to these three types
//      of data collectively, and these are the three things whose management
//      is provided for in this module.
//
//      Load Options, as implemented in this module, are defined in the UEFI
//      specification version 2.3, section 3.1.3. The following is an excerpt
//      from the specification copied here for reference.
//
//      Each load option variable contains an EFI_LOAD_OPTION descriptor that
//      is a byte packed buffer of variable length fields. Since some of the
//      fields are variable length, an EFI_LOAD_OPTION cannot be described as
//      a standard C data structure. Instead, the fields are listed below in
//      the order that they appear in an EFI_LOAD_OPTION descriptor:
//
//      Attributes      - A UINT32 value specifying the attributes for this
//                        load option entry. All unused bits must be zero and
//                        are reserved by the UEFI specification for future
//                        growth.
//                          LOAD_OPTION_ACTIVE             0x00000001
//                          LOAD_OPTION_FORCE_RECONNECT    0x00000002
//                          LOAD_OPTION_HIDDEN             0x00000008
//                          LOAD_OPTION_CATEGORY           0x00001F00
//                          LOAD_OPTION_CATEGORY_BOOT      0x00000000
//                          LOAD_OPTION_CATEGORY_APP       0x00000100
//
//      FilePathListLength - A UINT16 value specifying the length in bytes of
//                        the FilePathList. OptionalData starts at offset
//                        sizeof(UINT32) + sizeof(UINT16) + StrSize(Description)
//                        + FilePathListLength of the EFI_LOAD_OPTION descriptor.
//
//      Description     - A CHAR16 string specifying the user readable
//                        description for the load option. This field ends with
//                        a Null character.
//
//      FilePathList    - A EFI_DEVICE_PATH_PROTOCOL array. A packed array of
//                        UEFI device paths. The first element of the array is
//                        a device path that describes the device and location
//                        of the Image for this load option. The FilePathList [0]
//                        is specific to the device type. Other device paths may
//                        optionally exist in the FilePathList, but their usage
//                        is OSV specific. Each element in the array is variable
//                        length, and ends at the device path end structure.
//                        Because the size of Description is arbitrary, this
//                        data structure is not guaranteed to be aligned on a
//                        natural boundary. This data structure may have to be
//                        copied to an aligned natural boundary before it is used.
//
//      OptionalData    - A UINT8 array. The remaining bytes in the load option
//                        descriptor are a binary data buffer that is passed to
//                        the loaded image. If the field is zero bytes long, a
//                        NULL pointer is passed to the loaded image. The
//                        number of bytes in OptionalData can be computed by
//                        subtracting the starting offset of OptionalData from
//                        total size in bytes of the EFI_LOAD_OPTION.
//
// NOTICE.
//      Copyright (C) 2013-2025 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

//
// Private data types used by this module are defined here and any
// static items are declared here.
//

static PLOAD_OPTION_OBJECT mDriverOptionListHead = NULL;
static PLOAD_OPTION_OBJECT mSysPrepOptionListHead = NULL;
static BOOLEAN mIsBootOrderChanged = FALSE;
static EFI_RAM_DISK_PROTOCOL *mRam_Disk = NULL;

static CHAR16 *mBootableFilePath [] = {
  CONFIG_SYSTEM_BOOT_MANAGER_BOOT_FILE_PATH
};

//
// Prototypes for functions in other modules that are a part of this component.
//
EFI_STATUS
BmReconnectImagesBinding (
  IN EFI_HANDLE ControllerHandle
  );


extern
EFI_STATUS
EFIAPI
UpdateLoadOptionCrcTable (
  IN UINT32 OrgCrcValue,
  IN UINT32 NewCrcValue
  );

extern
BOOT_MANAGER_CONFIGURATION *
EFIAPI
GetPreDefinedLoadOptionByCrcTable (
  IN UINT32 CrcValue
  );

extern
BOOLEAN
EFIAPI
ValidateLoadOption (
  IN LOAD_OPTION_OBJECT *Option,
  IN BOOLEAN            ForceConnect,
  IN BOOLEAN            IgnoreBbsDevicePath
  );

extern
EFI_STATUS
EFIAPI
GetBootOptionNumberByCrc (
  IN UINT32 Crc,
  OUT PUINT16 OptionNumber
  );

extern
BOOLEAN
EFIAPI
IsOptionVariable (
  IN PCHAR16 Prefix,
  IN PCHAR16 VariableName,
  OUT PUINT16 OptionNumber OPTIONAL
  );

extern
SCT_STATUS
EFIAPI
FindDeviceChildren (
  IN EFI_HANDLE Handle,
  OUT PUINTN NumberOfHandles,
  OUT EFI_HANDLE **ChildHandleBuffer
  );

extern
EFI_DEVICE_PATH_PROTOCOL  *
EFIAPI
GetLastDeviceNode (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT_INT18
EFI_STATUS
LegacyInt18Boot (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN UINT16 OptionNumber,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  );
#endif

extern
BOOLEAN
EFIAPI
UefiBootEnabled (VOID);

BOOLEAN
EFIAPI
RequiresProjectLoad (VOID);

extern
SCT_STATUS
EFIAPI
ExpandDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **ExpandedDevicePaths,
  OUT PUINTN NumberDevicePaths
  );

extern
EFI_DEVICE_PATH_PROTOCOL *
EFIAPI
ExpandOneDevicePath (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

extern
VOID
EFIAPI
ToggleHddUnlockPromptState (IN BOOLEAN Enabled);

extern
VOID
EFIAPI
UnlockAllHdd (VOID);

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
extern
SCT_STATUS
GetBbsEntryByIndex (
  IN UINT16 BbsIndex,
  OUT BBS_TABLE **BbsEntry
  );

extern
EFI_DEVICE_PATH_PROTOCOL
*CreateBbsDevicePath (
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

extern
SCT_STATUS
BuildDescriptionFromBbsEntry (
  IN BBS_TABLE *BbsEntry,
  OUT PCHAR16 *Description
  );
#endif

extern
EFI_STATUS
UpdateKeyOptionCrcData (IN UINT16 BootOptionNumber);

extern
EFI_STATUS
EFIAPI
UpdateKeyOptionDataByCrc (
  IN UINT32 Crc,
  IN UINT16 OptionNumber
  );

extern
SCT_STATUS
EFIAPI
GetUsbHcProperStallTime (OUT PUINT16 Milliseconds);

extern
SCT_STATUS
EFIAPI
GetBmEssentialVariableListHead (IN OUT PBM_VARIABLE *Head);

extern
EFI_STATUS
EFIAPI
AddBootOptionToBootOrder (IN UINT16 OptionNumber);

extern
SCT_STATUS
EFIAPI
ConfigureConOutBeforeBoot (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT BOOLEAN *ClearScreen
  );

#if OPTION_SYSTEM_SCT_ACPI_BGRT
EFI_STATUS
EFIAPI
SetBootLogoInvalid (VOID);
#endif

extern
VOID
EFIAPI
InternalBmEmptyCallbackFunction (
  IN EFI_EVENT Event,
  IN VOID *Context
  );

SCT_STATUS
EFIAPI
LaunchBootMenuApplication (VOID);

//
// Data shared with other modules *within* this component.
//

LOAD_OPTION_OBJECT *mBootOptionListHead = NULL;
SCT_BDS_BOOT_FAILED_PROTOCOL mBootFailedProtocol;

//
// Data defined in other modules and used by this module.
//


//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

SCT_STATUS
PackOption (IN OUT PLOAD_OPTION_OBJECT Option);

SCT_STATUS
ConstructOptionFromRaw (
  IN UINTN RawLength,
  IN PUINT8 Raw,
  IN UINT16 OptionNumber,
  IN UINTN OptionType,
  OUT PLOAD_OPTION_OBJECT *NewOption
  );

SCT_STATUS
EFIAPI
DestroyOption (IN PLOAD_OPTION_OBJECT Option);

SCT_STATUS
AddOption (IN PLOAD_OPTION_OBJECT Option);

SCT_STATUS
SaveOption (IN PLOAD_OPTION_OBJECT Option);

BOOLEAN
OptionCmp (
  IN PLOAD_OPTION_OBJECT p,
  IN PLOAD_OPTION_OBJECT q
  );

SCT_STATUS
EFIAPI
ValidateOrderVariable (
  IN PCHAR16 VariableName,
  IN UINTN OptionType
  );

SCT_STATUS
EFIAPI
GetOption (
  IN UINT16 OptionNumber,
  IN UINTN OptionType,
  OUT PLOAD_OPTION_OBJECT *Option
  );

SCT_STATUS
PrepareToBoot (IN UINT16 OptionNumber);

EFI_STATUS
SignalBootFail (IN UINT8 Type);

SCT_STATUS
GetRemovableBlockIo (
  OUT PUINTN NumberOfHandles,
  OUT EFI_HANDLE **HandleBuffer
  );

SCT_STATUS
GetNonRemovableMediaBootableDevices (
  OUT PUINTN NumberOfHandles,
  OUT EFI_HANDLE **HandleBuffer
  );


#if (OPTION_SYSTEM_ACPI_TIMER_TO_POSTCODE && OPTION_DEBUG_POSTCODE)
SCT_STATUS
SendAcpiTimerToPostcode (IN UINT8 ShiftValue);
#endif

#if OPTION_SUPPORT_SECURE_BOOT
BOOLEAN
IsSecureBootEnabled (VOID);
#endif

#if (OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)
BOOLEAN
IsPureUefiOs (IN VOID *ImageBase);
#endif

//VOID
//STATIC
//CheckWindowsBootManager (
//  VOID
//  );

EFI_STATUS
EFIAPI
UpdateWindowsBootManagerBootOption (
  IN UINT16 OptionNumber,
  OUT EFI_DEVICE_PATH_PROTOCOL **FullBootPath OPTIONAL
  );

BOOLEAN
EFIAPI
IsLoadOptionDuplicated (
  IN LOAD_OPTION_OBJECT *Option,
  OUT UINT16 *OptionNumber OPTIONAL
  );

extern
BOOLEAN
EFIAPI
ValidateOptionVariable (
  UINT8 *Variable,
  UINTN VariableSize
  );

extern
UINT16
EFIAPI
RemoveDuplicatedBootEntry (
  VOID
  );


//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      GetBootOptionListHead - Get the Boot Option List.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets the Boot Option List Head.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      BootOptionListHead - The address of a pointer to a Boot Option Object.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
GetBootOptionListHead (OUT PLOAD_OPTION_OBJECT *BootOptionListHead)
{
  *BootOptionListHead = mBootOptionListHead;
  return SCT_STATUS_SUCCESS;
} // GetBootOptionListHead

//
// FUNCTION NAME.
//      AddProjectLoadOptions - Add Load Options per the project settings.
//
// FUNCTIONAL DESCRIPTION.
//      This function initialized the load option database based on the
//      settings provided in the project.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
AddProjectLoadOptions (VOID)
{
  UINTN i,j,k,m;
  SCT_STATUS Status;
  UINT16 OptionNumber;
  UINT8 Index;
  PUINT8 OptionalData;
  UINT32 OptionalDataLength;
  PLOAD_OPTION_OBJECT NewOption;
  PBOOT_MANAGER_CONFIGURATION p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  UINT16 TempBootOrder [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];
  UINT16 TempDriverOrder [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];
  UINT16 TempSysPrepOrder [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];
  UINT16 ProtectedBootOptions [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  UINT16 PreDefinedBootOptions [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];
  UINT32 LoadOptionCrcTable [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];
  UINTN l;
#endif

  if (!RequiresProjectLoad () && mBootOptionListHead != NULL) {
    return EFI_SUCCESS;
  }

  DPRINTF_LO ("AddProjectLoadOptions:\n");

  i = 0;
  j = 0;
  k = 0;
  m = 0;
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  l = 0;
#endif
  OptionalDataLength = 0;
  OptionalData = NULL;
  Index = 0;
  while (TRUE) {

    if (mBootReorder.IsReOrdered == 'Y') {
      p = &mBootManagerConfigurationTable [mBootReorder.ReOrder [Index]];
    } else {
      p = &mBootManagerConfigurationTable [Index];
    }

    if (p->Flags & SCT_BM_FLAGS_END) {
      DPRINTF_LO ("  mBootManagerConfigurationTable End.\n");
      break;
    }
    DPRINTF_LO ("  p @ 0x%x, p->TextDevicePath @ 0x%x = 0x%x.\n",
      p,
      &(p->TextDevicePath),
      p->TextDevicePath);

    DPRINTF_LO ("  Processing %s.\n", p->TextDevicePath);
    DevicePath = NULL;
    DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (DevicePath != NULL) {

      //
      // Store optional data.
      //

      OptionalDataLength = 0;
      OptionalData = NULL;
      if (p->OptionData != NULL) {
        OptionalDataLength = (UINT32)StrSize (p->OptionData);
        OptionalData = (PUINT8)(p->OptionData);
      }
      NewOption = NULL;
      Status = CreateNewOption (
                 &OptionNumber,         // optionNumber.
                 p->OptionType,         // optionType.
                 p->OptionAttributes,   // attributes.
                 p->Description,        // description.
                 DevicePath,            // devicePath.
                 OptionalDataLength,    // optionalDataLength.
                 OptionalData,          // optionalData.
                 &NewOption);           // option.
      DPRINTF_LO ("  CreateNewOption returned %r.\n", Status);
      if (!EFI_ERROR (Status)) {
        if ((p->OptionType == SCT_BM_LO_BOOT) &&
            ((p->OptionAttributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_BOOT) &&
            (i < CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER) &&
            ((p->OptionAttributes & LOAD_OPTION_HIDDEN) == 0)) {
          DPRINTF_LO ("  TempBootOrder [0x%x] = 0x%x.\n", i, OptionNumber);
          TempBootOrder [i++] = OptionNumber;
        } else if ((p->OptionType == SCT_BM_LO_DRIVER) && (j < CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER)) {
          DPRINTF_LO ("  TempDriverOrder [0x%x] = 0x%x.\n", j, OptionNumber);
          TempDriverOrder [j++] = OptionNumber;
        } else if ((p->OptionType == SCT_BM_LO_SYS_PREP) && (m < CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER)) {
          DPRINTF_LO ("  TempSysPrepOrder [0x%x] = 0x%x.\n", m, OptionNumber);
          TempSysPrepOrder [m++] = OptionNumber;
        }

        CreateLoadOptionNumberVariable (p, OptionNumber, &gSctBdsServicesProtocolGuid);

        if ((p->Flags & SCT_BM_PROTECTED) != 0) {
          DPRINTF_LO ("  0x%x is a protected option.\n", OptionNumber);
          ProtectedBootOptions [k++] = OptionNumber;
        }
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
        if ((p->Flags & SCT_BM_PRE_DEFINED_SLOT) != 0) {
          DPRINTF_LO ("  0x%x is a pre-defined option.\n", OptionNumber);
          LoadOptionCrcTable [l] = NewOption->RawCrc;
          PreDefinedBootOptions [l++] = OptionNumber;
        }
#endif
      }
      SafeFreePool (DevicePath);
    }
    Index++;
  }

  //
  // Update BootOrder and DriverOrder variables.
  //

  DPRINTF_LO ("  BootOrder size is 0x%x.\n", i * sizeof (UINT16));
  SetEfiGlobalVariable (
    EFI_BOOT_ORDER_VARIABLE_NAME,
    EFI_BOOT_ORDER_VARIABLE_ATTR,
    i * sizeof (UINT16),
    TempBootOrder);

  gRT->SetVariable (
         L"BootOrderDefault",
         &gSctBdsServicesProtocolGuid,
         SCT_BDS_BOOT_VARIABLE_ATTR,
         i * sizeof (UINT16),
         TempBootOrder);

  DPRINTF_LO ("  DriverOrder size is 0x%x.\n", j * sizeof (UINT16));
  SetEfiGlobalVariable (
    EFI_DRIVER_ORDER_VARIABLE_NAME,
    EFI_DRIVER_ORDER_VARIABLE_ATTR,
    j * sizeof (UINT16),
    TempDriverOrder);

  DPRINTF_LO ("  SysPrepOrder size is 0x%x.\n", m * sizeof (UINT16));
  Status = SetEfiGlobalVariable (
             EFI_SYS_PREP_ORDER_VARIABLE_NAME,
             EFI_SYS_PREP_ORDER_VARIABLE_ATTR,
             m * sizeof (UINT16),
             TempSysPrepOrder);

  DPRINTF_LO ("  ProtectedBootOptions size is 0x%x.\n", k * sizeof (UINT16));
  gRT->SetVariable (
         L"ProtectedBootOptions",
         &gSctBdsServicesProtocolGuid,
         SCT_BDS_BOOT_VARIABLE_ATTR,
         k * sizeof (UINT16),
         ProtectedBootOptions);

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  DPRINTF_LO ("  PreDefinedBootOptions size is 0x%x.\n", l * sizeof (UINT16));
  gRT->SetVariable (
         L"PreDefinedBootOptions",
         &gSctBdsServicesProtocolGuid,
         SCT_BDS_BOOT_VARIABLE_ATTR,
         l * sizeof (UINT16),
         PreDefinedBootOptions);

  gRT->SetVariable (
         L"LoadOptionCrcTable",
         &gSctBdsServicesProtocolGuid,
         SCT_BDS_BOOT_VARIABLE_ATTR,
         l * sizeof (UINT32),
         LoadOptionCrcTable);

  gRT->SetVariable (
         L"OrgLoadOptionCrcTable",
         &gSctBdsServicesProtocolGuid,
         SCT_BDS_BOOT_VARIABLE_ATTR,
         l * sizeof (UINT32),
         LoadOptionCrcTable);

#endif

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // AddProjectLoadOptions

//
// FUNCTION NAME.
//      InitializeLoadOptions - Initialize LoadOptions Module.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called during driver initialization to initialize
//      the load option database.
//
//      Project defined load options will be added to the database first
//      then load options that are defined by variables will be added.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
InitializeLoadOptions (VOID)
{
  UINTN i;
  PBM_VARIABLE p;
  SCT_STATUS Status;
  UINT32 Attributes;
  PUINT16 BootOrder;
  UINTN BootOrderSize;
  PUINT16 LastBootOrder;
  UINTN LastBootOrderSize;
  PLOAD_OPTION_OBJECT Option;

  DPRINTF_LO ("InitializeLoadOptions:\n");
  FreeOptionList (SCT_BM_LO_BOOT);
  FreeOptionList (SCT_BM_LO_DRIVER);
  FreeOptionList (SCT_BM_LO_SYS_PREP);

  //
  // Process the variable store to retrieve and validate all the load option
  // variables. These variables will be deleted if they are invalid.
  //

  GetBmEssentialVariableListHead (&p);

  while (TRUE) {

    Status = EFI_SUCCESS;
    if (p == NULL) {
      break;
    }

    //
    // The Load Options are divided into two groups, Boot and Driver.
    // The Boot options are further subdivided by the application attribute.
    // In the following two blocks of code we parse this variable to see if
    // it is a Boot or Driver option and add it to the appropriate list.
    //

    if (p->OptionType == BOOT_OPTION_TYPE) {

      DPRINTF_LO ("  %s is Boot Option 0x%x.\n", p->VariableName, p->OptionNumber);

      Status = ConstructOptionFromRaw (
                 p->DataSize,
                 p->DataBuffer,
                 p->OptionNumber,
                 SCT_BM_LO_BOOT,
                 &Option);

      if (!EFI_ERROR (Status) && IsLoadOptionDuplicated (Option, NULL)) {

        //
        // Remove the duplicated one.
        //

        RemoveOption (Option);
        if (Option != NULL)
          DestroyOption (Option);

        Status = EFI_ACCESS_DENIED;

      } else if (!EFI_ERROR (Status)) {

        Status = AddOption (Option);

        if (EFI_ERROR (Status)) {
          DestroyOption (Option);
        }

      }

    } else if (p->OptionType == DRIVER_OPTION_TYPE) {

      DPRINTF_LO ("  %s is Driver Option 0x%x.\n", p->VariableName, p->OptionNumber);

      Status = ConstructOptionFromRaw (
                 p->DataSize,
                 p->DataBuffer,
                 p->OptionNumber,
                 SCT_BM_LO_DRIVER,
                 &Option);
      if (!EFI_ERROR (Status)) {
        Status = AddOption (Option);
        if (EFI_ERROR (Status)) {
          DestroyOption (Option);
        }
      }
    } else if (p->OptionType == SYSPREP_OPTION_TYPE) {

      DPRINTF_LO ("  %s is SysPrep Option 0x%x.\n", p->VariableName, p->OptionNumber);

      Status = ConstructOptionFromRaw (
                 p->DataSize,
                 p->DataBuffer,
                 p->OptionNumber,
                 SCT_BM_LO_SYS_PREP,
                 &Option);
      if (!EFI_ERROR (Status)) {
        Status = AddOption (Option);
        if (EFI_ERROR (Status)) {
          DestroyOption (Option);
        }
      }
    }
    if (EFI_ERROR (Status)) {
      SetEfiGlobalVariable (
        p->VariableName,
        EFI_VARIABLE_NON_VOLATILE|
        EFI_VARIABLE_BOOTSERVICE_ACCESS|
        EFI_VARIABLE_RUNTIME_ACCESS,
        0,
        NULL);
    }
    p = p->Next;
  }

  //
  // Update with project settings, if needed.
  //

  AddProjectLoadOptions ();

  Status = UpdateProjectLoadOptions ( mBootManagerConfigurationTable, mBootManagerConfigurationTableSize );
  DPRINTF_LO ("  UpdateProjectLoadOptions ret Status = [%r]\n", Status);

  //
  // Validate the BootOrder variable.
  //

  Status = ValidateOrderVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             SCT_BM_LO_BOOT);

  //
  // Validate the DriverOrder variable.
  //

  Status = ValidateOrderVariable (
             EFI_DRIVER_ORDER_VARIABLE_NAME,
             SCT_BM_LO_DRIVER);

  //
  // Validate the SysPrepOrder variable.
  //

  Status = ValidateOrderVariable (
             EFI_SYS_PREP_ORDER_VARIABLE_NAME,
             SCT_BM_LO_SYS_PREP);

  //
  // Remove the duplicated option numbers.
  //

  RemoveDuplicatedBootEntry ();

  //
  // Check Windows Boot Manager load option.
  //

//  CheckWindowsBootManager ();

  //
  // Check if the BootOrder has been changed.
  //

  DPRINTF_LO ("  Check if the BootOrder has been changed\n");
  BootOrder = NULL;
  LastBootOrder = NULL;
  BootOrderSize = 0;

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             &Attributes,
             &BootOrderSize,
             (VOID **) &BootOrder);
  if (!EFI_ERROR (Status)) {
    DPRINTF_LO ("   Get BootOrder %r size = 0x%x\n",
      Status,
      BootOrderSize);
    Status = SctLibGetVariable (
               L"LastBootOrder",
               &gSctBdsServicesProtocolGuid,
               NULL,
               &LastBootOrderSize,
               (VOID **) &LastBootOrder);

    DPRINTF_LO ("   Get LastBootOrder %r size = 0x%x\n",
      Status,
      LastBootOrderSize);

    if (!EFI_ERROR (Status)) {
      if (BootOrderSize != LastBootOrderSize) {
        mIsBootOrderChanged = TRUE;
      } else {

        //
        // Compare the content.
        //

        for (i = 0; i < LastBootOrderSize / sizeof (UINT16); i++) {
          if (LastBootOrder [i] != BootOrder [i]) {
            mIsBootOrderChanged = TRUE;
            break;
          }
        }
      }

      SafeFreePool (LastBootOrder);
    }

    DPRINTF_LO ("  BootOrder has been changed ? %s\n",
      mIsBootOrderChanged ? L"Yes" : L"No");

    gRT->SetVariable (
           L"LastBootOrder",
           &gSctBdsServicesProtocolGuid,
           Attributes,
           BootOrderSize,
           BootOrder);

    SafeFreePool (BootOrder);
  }

  return SCT_STATUS_SUCCESS;
} // InitializeLoadOptions

//
// FUNCTION NAME.
//      GetLoadOptionCrc - Get the Crc of this Boot Options Raw Data.
//
// FUNCTIONAL DESCRIPTION.
//      This function will retrieve the current Crc for a Boot Load Option.
//
//      The hotkey module is required to match the Crc for the Boot Load Option
//      it is about to launch with the expected Boot Load Option from when the
//      Load Option was registered with the hotkey.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value corresponding to the load option.
//      OptionType      - SCT_BM_LO_BOOT or SCT_BM_LO_DRIVER.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      OptionCrc       - a pointer to a UINT32 value to be used as storage for
//                        the Crc of the boot option.
//

SCT_STATUS
EFIAPI
GetLoadOptionCrc (
  IN UINT16 OptionNumber,
  IN UINTN OptionType,
  OUT PUINT32 OptionCrc
  )
{
  PLOAD_OPTION_OBJECT p;

  DPRINTF_LO ("GetLoadOptionCrc:\n");

  //
  // Search for the load option, if not found return SCT_STATUS_NOT_FOUND.
  //

  if (OptionType == SCT_BM_LO_BOOT) {
    p = mBootOptionListHead;
    DPRINTF_LO ("  Boot List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_DRIVER) {
    p = mDriverOptionListHead;
    DPRINTF_LO ("  Driver List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_SYS_PREP) {
    p = mSysPrepOptionListHead;
    DPRINTF_LO ("  SysPrep List @ 0x%x.\n", p);
  } else {
    DPRINTF_LO ("  Bad OptionType 0x%x.\n", OptionType);
    return SCT_STATUS_INVALID_PARAMETER;
  }

  while (TRUE) {
    if (p == NULL) {
      DPRINTF_LO ("  Couldn't find Option:0x%x.\n", OptionNumber);
      return SCT_STATUS_NOT_FOUND;
    }
    if (p->OptionNumber == OptionNumber) {
      break;
    }
    p = p->Next;
  }

  *OptionCrc = p->RawCrc;
  DPRINTF_LO ("  Option:0x%x, CRC32:0x%x.\n", OptionNumber, *OptionCrc);
  return SCT_STATUS_SUCCESS;
} // GetLoadOptionCrc

//
// FUNCTION NAME.
//      GetBootOption - Get an Driver Option Object from the database.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches the driver database to find an Option
//      object with the OptionNumber specified.
//
//      The Option parameter is optional. When it is not provided the Status
//      simply indicates if this Option Object exists in the Option database.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value, the number of the option.
//      Option          - the address of a pointer that will be updated with
//                        the address of the Option Object whose OptionNumber
//                        field is the same as the OptionNumber parameter of
//                        this function.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
GetBootOption (
  IN UINT16 OptionNumber,
  OUT PLOAD_OPTION_OBJECT *Option
  )
{
  return GetOption (OptionNumber, SCT_BM_LO_BOOT, Option);
} // GetBootOption

//
// FUNCTION NAME.
//      GetDriverOption - Get an Driver Option Object from the database.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches the driver database to find an Option
//      object with the OptionNumber specified.
//
//      The Option parameter is optional. When it is not provided the Status
//      simply indicates if this Option Object exists in the Option database.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value, the number of the option.
//      Option          - The address of a pointer that will be updated with
//                        the address of the Option Object whose OptionNumber
//                        field is the same as the OptionNumber parameter of
//                        this function.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
GetDriverOption (
  IN UINT16 OptionNumber,
  OUT PLOAD_OPTION_OBJECT *Option
  )
{
  return GetOption (OptionNumber, SCT_BM_LO_DRIVER, Option);
} // GetDriverOption

//
// FUNCTION NAME.
//      GetSysPrepOption - Get an SysPrep Option Object from the database.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches the SysPrep database to find an Option
//      object with the OptionNumber specified.
//
//      The Option parameter is optional. When it is not provided the Status
//      simply indicates if this Option Object exists in the Option database.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value, the number of the option.
//      Option          - The address of a pointer that will be updated with
//                        the address of the Option Object whose OptionNumber
//                        field is the same as the OptionNumber parameter of
//                        this function.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
GetSysPrepOption (
  IN UINT16 OptionNumber,
  OUT PLOAD_OPTION_OBJECT *Option
  )
{
  return GetOption (OptionNumber, SCT_BM_LO_SYS_PREP, Option);
} // GetSysPrepOption


//
// FUNCTION NAME.
//      LaunchBootOption - Launch a boot load option.
//
// FUNCTIONAL DESCRIPTION.
//      This function will make the best possible attempt to launch the load
//      option referenced by option number. The function will look up the
//      option in the option database, then access the option information and
//      attempt to launch the option per the UEFI specification.
//
//      Before attempting to launch the option this function will verify that
//      the CRC for the Option referenced by OptionNumber matches OptionCrc.
//
//      This function is for boot attempts. There are also "Boot Load Options"
//      with the application bit set. Use the LaunchApplication function for
//      those as the logic for handling applications is different.
//
//      In general this operation is file centric. We expect that the device
//      path in the boot option points to a file. There are a few cases where
//      this is not the case. In those cases we need to search for a file on
//      the device specified by the device path.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value indicating which option to launch.
//      OptionCrc       - a  UINT32 value, the expected CRC of the option.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
LaunchBootOption (
  IN UINT16 OptionNumber,
  IN UINT32 OptionCrc
  )
{
  EFI_STATUS Status;
  SCT_BDS_LAUNCH_BOOT_OPTION_DATA MilestoneData;
  UINT32 MilestoneDataSize = sizeof (MilestoneData);

  MilestoneData.OptionNumber = OptionNumber;
  MilestoneData.OptionCrc = OptionCrc;
  MilestoneData.ReturnStatus = EFI_SUCCESS;

  Status = SCT_MILESTONE_TASK (
            BDS_MILESTONE_TASK_LAUNCH_BOOT_OPTION,
            MsTaskLaunchBootOption,
            &MilestoneData,
            MilestoneDataSize);
  DPRINTF_LO ("BDS_MILESTONE_TASK_LAUNCH_BOOT_OPTION Ret_Status = [%r]\n", MilestoneData.ReturnStatus);
  Status = MilestoneData.ReturnStatus;
  return Status;
} // LaunchBootOption

//
// FUNCTION NAME.
//      LaunchApplicationOption - Launch a Boot Option as an Application.
//
// FUNCTIONAL DESCRIPTION.
//      This function loads and starts an image from a load option that is of
//      category application.
//
//      For applications we expect that a connection and a load is all that is
//      required to be able to start the image.
//
// ENTRY PARAMETERS.
//      FilePathList    - Pointer to a device path.
//      OptionalData    - Pointer to an option input data buffer.
//      OptionalDataLength - Length of the data buffer.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//


SCT_STATUS
EFIAPI
LaunchApplicationOption (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  )
{
  SCT_STATUS Status;
  SCT_BDS_LAUNCH_APPLICATION_OPTION_DATA MilestoneData;
  UINT32 MilestoneDataSize= sizeof (MilestoneData);

  MilestoneData.FilePathList = FilePathList;
  MilestoneData.OptionalData = OptionalData;
  MilestoneData.OptionalDataLength = OptionalDataLength;
  MilestoneData.ReturnStatus = EFI_SUCCESS;

  Status = SCT_MILESTONE_TASK (
            BDS_MILESTONE_TASK_LAUNCH_APPLICATION,
            MsTaskLaunchApplicationOption,
            &MilestoneData,
            MilestoneDataSize);
  DPRINTF_LO ("BDS_MILESTONE_TASK_LAUNCH_APPLICATION Ret_Status = [%r]\n", MilestoneData.ReturnStatus);
  Status = MilestoneData.ReturnStatus;
  return Status;
} // LaunchApplicationOption

//
// FUNCTION NAME.
//      LaunchDriverOption - Launch a driver load option.
//
// FUNCTIONAL DESCRIPTION.
//      This function will make the best possible attempt to launch the load
//      option referenced by option number. The function will look up the
//      option in the option database, then access the option information and
//      attempt to launch the option per the UEFI specification.
//
//      Before attempting to launch the option this function will verify that
//      the CRC for the Option referenced by OptionNumber matches OptionCrc.
//
//      This function is very similar to LaunchApplication. There are two
//      differences. First the list head is different since we keep different
//      lists for Driver options. Second this function does not lower TPL to
//      application, since the driver list is processing drivers, the TLP
//      should remain at the driver level.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value indicating which option to launch.
//      OptionCrc       - a  UINT32 value, the expected CRC of the option.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
LaunchDriverOption (
  IN UINT16 OptionNumber,
  IN UINT32 OptionCrc
  )
{
  SCT_STATUS Status;

  EFI_HANDLE ConnectedHandle;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  PLOAD_OPTION_OBJECT p;

  EFI_HANDLE FileImageHandle;
  UINTN ExitDataSize;
  PCHAR16 ExitData;
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;

  DPRINTF_LO ("LaunchDriverOption: Number = 0x%x, Crc = 0x%x\n",
    OptionNumber,
    OptionCrc);

  //
  // Search for the load option, if not found return SCT_STATUS_NOT_FOUND.
  //

  p = mDriverOptionListHead;
  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (p, L"  ");
    });
    if (p == NULL) {
      DPRINTF_LO ("  Couldn't find Option:0x%x.\n", OptionNumber);
      return SCT_STATUS_NOT_FOUND;
    }
    if (p->OptionNumber == OptionNumber) {
      break;
    }
    p = p->Next;
  }

  //
  // Check to see if the CRC was as expected.
  //

  if (p->RawCrc != OptionCrc) {
    return SCT_STATUS_CRC_ERROR;
  }

  //
  // Connect the Device Path.
  //

  Status = ConnectDevicePathWithRemaining (
             p->FilePathList,
             &ConnectedHandle,
             &RemainingDevicePath);
  DPRINTF_LO ("  ConnectDevicePathWithRemaining returned %r.\n", Status);

  //
  // Load the image.
  //

  DEBUG_LO (
    DPRINTF_DEVICE_PATH ("  LoadImage = ", p->FilePathList);
  );
  Status = gBS->LoadImage (
                  TRUE,
                  mImageHandle,
                  p->FilePathList,
                  NULL,
                  0,
                  &FileImageHandle);
  DPRINTF_LO ("  LoadImage returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Fix up the Image Information protocol to pass in any option data.
  //

  if (p->OptionalDataLength != 0) {
    Status = gBS->HandleProtocol (
                    FileImageHandle,
                    &gEfiLoadedImageProtocolGuid,
                    (VOID **) &ImageInfo);
    if (!EFI_ERROR(Status)) {
      ImageInfo->LoadOptionsSize = p->OptionalDataLength;
      ImageInfo->LoadOptions = p->OptionalData;
    }
  }

  //
  // Start the image.
  //

  Status = gBS->StartImage (
                  FileImageHandle,
                  &ExitDataSize,
                  &ExitData);

  return Status;
} // LaunchDriverOption

//
// FUNCTION NAME.
//      LaunchSysPrepOption - Launch a SysPrep load option.
//
// FUNCTIONAL DESCRIPTION.
//      This function will make the best possible attempt to launch the load
//      option referenced by option number. The function will look up the
//      option in the option database, then access the option information and
//      attempt to launch the option per the UEFI specification.
//
//      Before attempting to launch the option this function will verify that
//      the CRC for the Option referenced by OptionNumber matches OptionCrc.
//
//      This function is very similar to LaunchApplication. There are two
//      differences. First the list head is different since we keep different
//      lists for SysPrep options. Second this function does not lower TPL to
//      application, since the driver list is processing drivers, the TLP
//      should remain at the driver level.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value indicating which option to launch.
//      OptionCrc       - a  UINT32 value, the expected CRC of the option.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
LaunchSysPrepOption (
  IN UINT16 OptionNumber,
  IN UINT32 OptionCrc
  )
{

  SCT_STATUS Status;
  PLOAD_OPTION_OBJECT p;
  UINT32 MilestoneDataSize;
  SCT_BDS_LAUNCH_APPLICATION_OPTION_DATA MilestoneData;

  DPRINTF_LO ("LaunchSysPrepOption: Number = 0x%x, Crc = 0x%x\n",
    OptionNumber,
    OptionCrc);

  //
  // Search for the load option, if not found return SCT_STATUS_NOT_FOUND.
  //

  p = mSysPrepOptionListHead;
  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (p, L"  ");
    });
    if (p == NULL) {
      DPRINTF_LO ("  Couldn't find Option:0x%x.\n", OptionNumber);
      return SCT_STATUS_NOT_FOUND;
    }
    if (p->OptionNumber == OptionNumber) {
      break;
    }
    p = p->Next;
  }

  //
  // Check to see if the CRC was as expected.
  //

  if (p->RawCrc != OptionCrc) {
    return SCT_STATUS_CRC_ERROR;
  }
  MilestoneData.FilePathList = p->FilePathList;
  MilestoneData.OptionalData = p->OptionalData;
  MilestoneData.OptionalDataLength = p->OptionalDataLength;
  MilestoneDataSize = sizeof (MilestoneData);

  Status = MsTaskLaunchApplicationOption (&MilestoneData, MilestoneDataSize);

  return Status;
} // LaunchSysPrepOption

//
// FUNCTION NAME.
//      GetLoadOptionNumber - Find a load option in the database.
//
// FUNCTIONAL DESCRIPTION.
//      Search the load option database for a particular load option.
//
// ENTRY PARAMETERS.
//      Description     - a CHAR16 string specifying the user readable
//                        description for the load option. This field ends with
//                        a Null character.
//      DevicePath      - ptr to the EFI_DEVICE_PATH_PROTOCOL instance for this
//                        device.
//      OptionType      - a UINTN value specifying the type, Boot or Driver.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      OptionNumber    - a UINT16 value used to identify the option.
//

SCT_STATUS
EFIAPI
GetLoadOptionNumber (
  IN PCHAR16 Description,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINTN OptionType,
  OUT PUINT16 OptionNumber OPTIONAL
  )
{
  PLOAD_OPTION_OBJECT p;
 #if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  EFI_STATUS      Status;
  PLOAD_OPTION_OBJECT BootOption;
 #endif //OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  //DPRINTF_FUNCTION_ENTRY();

  DPRINTF_LO ("GetLoadOptionNumber %s.\n", Description);

  if (OptionType == SCT_BM_LO_BOOT) {
    p = mBootOptionListHead;
    DPRINTF_LO ("  Boot List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_DRIVER) {
    p = mDriverOptionListHead;
    DPRINTF_LO ("  Driver List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_SYS_PREP) {
    p = mSysPrepOptionListHead;
    DPRINTF_LO ("  SysPrep List @ 0x%x.\n", p);
  } else {
    DPRINTF_LO ("  Bad OptionType 0x%x.\n", OptionType);
    return SCT_STATUS_INVALID_PARAMETER;
  }

 #if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (p, L"  ");
    });
    //
    // Search for the load option, if not found return SCT_STATUS_NOT_FOUND.
    //
    if (p == NULL) {
      DPRINTL_LO (2,("  Couldn't find Option:%s.\n", Description));
      return SCT_STATUS_NOT_FOUND;
    }

    //
    // Check the description.
    //
    if (StrnCmp (Description, p->Description, StrLen (Description)) != 0) {
      p = p->Next;
      continue;
    }

    DEBUG_LO_L (2, {
      CHAR16 *Str = NULL;
      DPRINTL_LO (2,("    Description = [%s]\t", Description));
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
      DPRINTL_LO (2,("     DevicePath = [%s].\n", Str));
      SafeFreePool (Str);

      DPRINTL_LO (2,(" p->Description = [%s]\t", p->Description));
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (p->FilePathList, FALSE, TRUE);
      DPRINTL_LO (2,("p->FilePathList = [%s].\n", Str));
      SafeFreePool (Str);

      DPRINTL_LO (2,(" p->NumberOfFilePaths = [%d]\n", p->NumberOfFilePaths));
      DPRINTL_LO (2,(" p->OptionalDataLength = [%d]\n", p->OptionalDataLength));

      if (p->OptionalDataLength > 0) {
        UINTN i;
        DPRINTL_LO (2,(" p->OptionalData: ("));
        for (i = 0; i < p->OptionalDataLength; i++) {
          DPRINTL_LO (2,("%02x", p->OptionalData [i]));
        }
        DPRINTL_LO (2,(")\n"));
      }
    });

    Status = GetBootOption (p->OptionNumber, &BootOption);
    ASSERT_EFI_ERROR (Status);

    DEBUG_LO_L (2, {
      CHAR16 *Str = NULL;
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (BootOption->FilePathList, FALSE, TRUE);
      DPRINTL_LO (2,("BootOption->FilePathList = [%s].\n", Str));
      SafeFreePool (Str);
    });

    //
    // Check the DevicePath.
    //
    if (!CompareDevicePath(p->FilePathList, BootOption->FilePathList)) {
      DPRINTL_LO (2,("     (CompareDevicePath(p->FilePathList, BootOption->FilePathList)) = FALSE\n"));
      p = p->Next;
      continue;
    } else {
      DPRINTL_LO (2,("     (CompareDevicePath(p->FilePathList, BootOption->FilePathList)) = TRUE\n"));
    }
    DPRINTL_LO (2,("--------------------------------------------\n"));
    //
    // The description, device path and option type match.
    //
    break;
  }

 #else  //OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (p, L"  ");
    });
    //
    // Search for the load option, if not found return SCT_STATUS_NOT_FOUND.
    //
    if (p == NULL) {
      DPRINTF_LO ("  Couldn't find Option:%s.\n", Description);
      return SCT_STATUS_NOT_FOUND;
    }

    //
    // Check the description.
    //
    if (StrCmp (Description, p->Description) != 0) {
      p = p->Next;
      continue;
    }

    //
    // Check the DevicePath.
    //
    if (!CompareDevicePath (DevicePath, p->FilePathList)) {
      p = p->Next;
      continue;
    }
    //
    // The description, device path and option type match.
    //
    break;
  }

 #endif //OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  //
  // Return with success.
  //
  DPRINTF_LO ("  Found it:\n");
  DISPLAY_OPTION_INFORMATION (p, L"    ");
  if (OptionNumber != NULL) {
    *OptionNumber = p->OptionNumber;
  }
  return SCT_STATUS_SUCCESS;
} // GetLoadOptionNumber

//
// Private (static) routines used by this component.
//

//
// FUNCTION NAME.
//      PackOption - Fill in the raw fields of the option.
//
// FUNCTIONAL DESCRIPTION.
//      This function will use all the "unpacked" fields in the option to
//      construct the raw fields of the option. This function is used when
//      we want to create a new option from data or business logic instead
//      of reading an option from a variable.
//
// ENTRY PARAMETERS.
//      Option          - pointer to the LOAD_OPTION_OBJECT to pack.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      Option          - option->RawLength, Option->RawData and Option->RawCrc
//                        are filled out per the other fields in Option.
//

SCT_STATUS
PackOption (IN OUT PLOAD_OPTION_OBJECT Option)
{
  PUINT8 p;
  DEVICE_PATH_PTR q;
  UINTN qEnd;

  DPRINTF_LO ("PackOption:0x%x.\n", Option->OptionNumber);

  //
  // Calculate the total size and create a new buffer of that size for RawData.
  //

  Option->RawLength = sizeof (Option->Attributes)
                    + sizeof (Option->FilePathListLength)
                    + Option->FilePathListLength
                    + Option->DescriptionLength
                    + Option->OptionalDataLength;
  Option->RawData = AllocateZeroPool (Option->RawLength);
  if (Option->RawData == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  //
  // Copy the option data into the RawData buffer.
  //

  p = Option->RawData;
  *((PUINT32)p) = Option->Attributes;
  p += sizeof (UINT32);
  *((PUINT16)p) = Option->FilePathListLength;
  p += sizeof (UINT16);
  CopyMem (p, Option->Description, Option->DescriptionLength);
  p += Option->DescriptionLength;
  CopyMem (p, Option->FilePathList, Option->FilePathListLength);

  //
  // According to UEFI Specification, each element in FilePathList array should end
  // at the device path end structure.
  // So, if the device path has multiple instances, slice it into single device
  // path.
  //

  q.DevPath = (EFI_DEVICE_PATH_PROTOCOL *)p;
  qEnd = q.address + Option->FilePathListLength;

  DPRINTF_LO ("  Slice multi-instance device path into single device path\n");

  while (TRUE) {
    if (q.address >= qEnd) {
      break;
    }

    if (IsDevicePathEndInstance (q.DevPath)) {
      DPRINTF_LO ("  Find one DevicePathEndInstance node\n");

      //
      // Replace the node to END_ENTIRE_DEVICE_PATH_SUBTYPE.
      //

      (q.DevPath)->SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
    }

    q.DevPath = NextDevicePathNode (q.DevPath);
  }

  p += Option->FilePathListLength;
  CopyMem (p, Option->OptionalData, Option->OptionalDataLength);

  //
  // Calculate the Crc of the Raw Data.
  //

  gBS->CalculateCrc32 (Option->RawData, Option->RawLength, &Option->RawCrc);
  return SCT_STATUS_SUCCESS;
} // PackOption

//
// FUNCTION NAME.
//      ConstructOptionFromRaw - Create a LOAD_OPTION_OBJECT from raw data.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes the raw (packed) data that would typically be
//      retrieved from a variable and unpacks it into a new Option object.
//
//      Should an option no longer be needed, it should be de allocated by
//      calling DestroyOption, since there are several sub-buffers used in
//      an Option object.
//
// ENTRY PARAMETERS.
//      RawLength       - the number of bytes in the Raw buffer.
//      Raw             - ptr the raw data.
//      OptionNumber    - a UINT16 value used to identify the option.
//      OptionType      - a UINTN value specifying the type, Boot or Driver.
//
// EXIT PARAMETERS.
//      Option          - address of the pointer to the new Option object.
//      Function Return - SCT status code.
//

SCT_STATUS
ConstructOptionFromRaw (
  IN UINTN RawLength,
  IN PUINT8 Raw,
  IN UINT16 OptionNumber,
  IN UINTN OptionType,
  OUT PLOAD_OPTION_OBJECT *NewOption
  )
{
  PUINT8 p;
  PLOAD_OPTION_OBJECT Option;
  DEVICE_PATH_PTR q;
  UINTN qEnd;
  UINT32 Attributes;
  UINT16 FilePathListLength;
  UINTN DescriptionLength;

  DPRINTF_LO ("ConstructOptionFromRaw:0x%x, RawLength = 0x%x.\n",
    OptionNumber,
    RawLength);

  if ((NewOption == NULL) || (RawLength == 0)) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Validate the raw buffer fields first.
  //

  if (ValidateOptionVariable (Raw, RawLength) == FALSE) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Start to unpack the raw data.
  //

  p = Raw;
  Attributes = *((PUINT32)p);
  p += sizeof (UINT32);
  FilePathListLength = *((PUINT16)p);
  p += sizeof (UINT16);
  DescriptionLength = StrSize ((PCHAR16)p);

  //
  // Initialize the Raw fields.
  //

  Option = AllocateZeroPool (sizeof (LOAD_OPTION_OBJECT));
  if (Option == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  Option->RawLength = RawLength;

  //
  // Save the option number and type.
  //

  Option->OptionNumber = OptionNumber;
  Option->OptionType = OptionType;

  //
  // Copy the previously retrieved values to the Option object.
  //

  Option->Attributes = Attributes;
  Option->FilePathListLength = FilePathListLength;
  Option->DescriptionLength = DescriptionLength;

  Option->Description = AllocateCopyPool (Option->DescriptionLength, p);
  if (Option->Description == NULL) {
    SafeFreePool (Option);
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
  p += Option->DescriptionLength;

  Option->FilePathList = AllocateCopyPool (Option->FilePathListLength, p);
  if (Option->FilePathList == NULL) {
    SafeFreePool (Option->Description);
    SafeFreePool (Option);
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
  p += Option->FilePathListLength;

  //
  // Count the number of device paths in FilePathList.
  //

  Option->NumberOfFilePaths = 0;
  q.DevPath = Option->FilePathList;
  qEnd = q.address + Option->FilePathListLength;
  while (TRUE) {
    if (q.address >= qEnd) {
      break;
    }

    if ((q.DevPath->Type == 0) ||
      DevicePathNodeLength (q.DevPath) < sizeof (EFI_DEVICE_PATH_PROTOCOL)) {
      break;
    }

    if (IsDevicePathEnd (q.DevPath)) {
      Option->NumberOfFilePaths++;
    }
    q.DevPath = NextDevicePathNode (q.DevPath);
  }

  Option->OptionalDataLength = (UINT32)(RawLength - (p - Raw));
  if (Option->OptionalDataLength != 0) {
    Option->OptionalData = AllocateCopyPool (Option->OptionalDataLength, p);
    if (Option->OptionalData == NULL) {
      SafeFreePool (Option->Description);
      SafeFreePool (Option->FilePathList);
      SafeFreePool (Option);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  Option->RawData = AllocateCopyPool (RawLength, Raw);
  if (Option->RawData == NULL) {
    SafeFreePool (Option->Description);
    SafeFreePool (Option->FilePathList);
    SafeFreePool (Option->OptionalData);
    SafeFreePool (Option);
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
  gBS->CalculateCrc32 (Raw, RawLength, &Option->RawCrc);

  //
  // Return with success.
  //

  DISPLAY_OPTION_INFORMATION(Option, L"  ");
  *NewOption = Option;
  return SCT_STATUS_SUCCESS;
} // ConstructOptionFromRaw

//
// FUNCTION NAME.
//      CreateOption - Create a LOAD_OPTION_OBJECT from parameters.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes the parameters and allocates all necessary memory
//      to construct the Option Object.
//
//      This function checks the Option database to see if the Option already
//      exists. If the Option already exists but is the same this function
//      frees all the newly allocated memory and returns with success. If the
//      Option exists but is different, the old Option will be destroyed and
//      the new Option will be added. If the Option did not exist it will be
//      added.
//
//      If the Option was added it will also be saved, which saves the Option
//      to the non-volatile store.
//
//      Should an option no longer be needed, it should be de-allocated by
//      calling DestroyOption, since there are several sub-buffers used in
//      an Option object.
//
//      Note that this function does not support more than one element in the
//      FilePathList. This function will assume that there is exactly one entry
//      in this array, and it will calculate the size of the FilePathList based
//      solely on the size of the Device Path pointed to by the DevicePath
//      parameter. The DevicePath parameter is used as the FilePathList.
//
// ENTRY PARAMETERS.
//      OptionNumber    - A UINT16 number, the Load Option's number.
//      OptionType      - A UINTN value specifying the type, Boot or Driver.
//      Attributes      - A UINT32 value, the attributes field of the Load Option.
//      Description     - A CHAR16 string pointer for the Load Option.
//      DevicePath      - The Device Path for the Load Option.
//      OptionalDataLength - The number of bytes in the OptionalData buffer.
//      OptionalData    - A buffer to be passed to the Image when starting.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//                        EFI_UNSUPPORTED - If the created one is duplicated in DB.
//
//      NewOption       - address of the pointer to the new Option object.
//

SCT_STATUS
CreateOption (
  IN UINT16 OptionNumber,
  IN UINTN OptionType,
  IN UINT32 Attributes,
  IN PCHAR16 Description,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINT32 OptionalDataLength,
  IN PUINT8 OptionalData,
  OUT PLOAD_OPTION_OBJECT *NewOption OPTIONAL
  )
{
  SCT_STATUS Status;
  UINT32 OrgLoadOptionCrc;
  BOOLEAN LoadOptionDuplicated = FALSE;
  PLOAD_OPTION_OBJECT Option;
  PLOAD_OPTION_OBJECT CurrentOption;
  UINTN DevicePathSize;

  DPRINTF_LO ("CreateOption:0x%x %s.\n", OptionNumber, Description);

  Option = AllocateZeroPool (sizeof (LOAD_OPTION_OBJECT));
  if (Option == NULL) {
      return SCT_STATUS_OUT_OF_RESOURCES;
  }

  Option->OptionNumber = OptionNumber;
  Option->OptionType = OptionType;
  Option->Attributes = Attributes;
  Option->FilePathListLength = (UINT16)GetDevicePathSize (DevicePath);
  Option->FilePathList = AllocateCopyPool (
                           Option->FilePathListLength,
                           DevicePath);

  DPRINTF_LO ("    Option->FilePathListLength   = 0x%x\n",
    Option->FilePathListLength);

  DEBUG_LO (
    DPRINTF_DEVICE_PATH ("    Option->FilePathList  = ", Option->FilePathList);
  );

  //
  // Count the number of device paths in FilePathList.
  //

  Option->NumberOfFilePaths = 1;

  if (IsDevicePathMultiInstance (DevicePath)) {
    while (TRUE) {
      GetNextDevicePathInstance (&DevicePath, &DevicePathSize);
      if (DevicePath == NULL) {
        break;
      }
      Option->NumberOfFilePaths++;
    }
  }

  DPRINTF_LO ("  NumberOfFilePaths = %d. \n", Option->NumberOfFilePaths);

  Option->DescriptionLength = StrSize (Description);
  Option->Description = AllocateCopyPool (
                          Option->DescriptionLength,
                          Description);
  Option->OptionalDataLength = OptionalDataLength;
  if (OptionalDataLength > 0 && OptionalData != NULL) {
    Option->OptionalData = AllocateCopyPool (
                             Option->OptionalDataLength,
                             OptionalData);
  }

  PackOption (Option);                  // fill in the Raw fields.
  Status = GetOption (
             Option->OptionNumber,
             Option->OptionType,
             &CurrentOption);
  if (EFI_ERROR (Status))
    CurrentOption = NULL;

  LoadOptionDuplicated = IsLoadOptionDuplicated (Option, NULL);

  if (!LoadOptionDuplicated) {
    if (CurrentOption == NULL) {
      //
      // If the option not duplicated and does not exist, add a new one.
      //
      DPRINTF_LO ("  New Option.\n");
      Status = AddOption (Option);        // add the option to the database.
      if (EFI_ERROR(Status)) {            // if we failed to add it,
        DPRINTF_LO ("  Failed to add Option.\n");
        Status = DestroyOption (Option);  // free all the memory.
        ASSERT_EFI_ERROR (Status);
      } else {                            // otherwise,
        DPRINTF_LO ("  Save Option.\n");
        Status = SaveOption (Option);     // save it to a variable.
        ASSERT_EFI_ERROR (Status);
      } // if AddOption Error.
    } else if (!OptionCmp (Option, CurrentOption)) {
      //
      // If the option not duplicated but exist, Changed Option.
      //
      DPRINTF_LO ("  Changed Option.\n");
      OrgLoadOptionCrc = CurrentOption->RawCrc;
      RemoveOption (CurrentOption);       // delete the current option,

      Status = AddOption (Option);        // and add the new one to the database.
      if (EFI_ERROR(Status)) {            // if we failed to add it,
        DPRINTF_LO ("  Failed to add Option.\n");
        Status = DestroyOption (Option);  // free all the memory.
        ASSERT_EFI_ERROR (Status);
      } else {                            // otherwise,
        DPRINTF_LO ("  Save Option.\n");
        Status = SaveOption (Option);              // save it to a variable.
        ASSERT_EFI_ERROR (Status);
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
        //
        // Update LoadOption CRC table.
        //
        UpdateLoadOptionCrcTable (OrgLoadOptionCrc, Option->RawCrc);
#endif
      } // if AddOption Error.
    }
  } else {
    //
    // LoadOption Duplicated.
    //
    DPRINTF_LO ("  Option already exists.\n");
    FreePool (Option);
    Option = CurrentOption;
    Status = EFI_UNSUPPORTED;
  }

  //
  // If the caller requested the new object return it.
  //

  if (NewOption != NULL) {
    ASSERT (Option != NULL);
    *NewOption = Option;
  }

  return Status;
} // CreateOption

//
// FUNCTION NAME.
//      GetNewOptionNumber - Find an unused option number.
//
// FUNCTIONAL DESCRIPTION.
//      This function examines the Option Database to find an Option Number
//      which is not in use.
//
// ENTRY PARAMETERS.
//      OptionType      - the type of the option that needs the number,
//                        Boot or Driver.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      OptionNumber    - a pointer to the memory locate where the new option
//                        number will be returned.
//

SCT_STATUS
EFIAPI
GetNewOptionNumber (
  OUT PUINT16 OptionNumber,
  IN UINTN OptionType
  )
{
  PLOAD_OPTION_OBJECT p;
  UINT16 NewOptionNumber;

  DPRINTF_LO ("GetNewOptionNumber:\n");

  if (OptionNumber == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  NewOptionNumber = 0;
  if (OptionType == SCT_BM_LO_BOOT) {
    p = mBootOptionListHead;
    NewOptionNumber = CONFIG_SYSTEM_BOOT_MANAGER_LOAD_OPTION_START_NUMBER;
    DPRINTF_LO ("  Boot List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_DRIVER) {
    p = mDriverOptionListHead;
    DPRINTF_LO ("  Driver List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_SYS_PREP) {
    p = mSysPrepOptionListHead;
    DPRINTF_LO ("  SysPrep List @ 0x%x.\n", p);
  } else {
    DPRINTF_LO ("  Bad OptionType 0x%x.\n", OptionType);
    return SCT_STATUS_INVALID_PARAMETER;
  }

  while (TRUE) {
    if (p == NULL) {
      DPRINTF_LO ("  OptionNumber:0x%x.\n", NewOptionNumber);
      break;
    }
    if (p->OptionNumber >= NewOptionNumber) {
      if ((p->OptionNumber + 1) > SCT_BM_MAX_OPTION_NUMBER) {
        DPRINTF_LO ("  Out of options:0x%x.\n", p->OptionNumber + 1);
        return SCT_STATUS_OUT_OF_RESOURCES;
      }
      NewOptionNumber = p->OptionNumber + 1;
    }
    p = p->Next;
  }

  *OptionNumber = NewOptionNumber;
  return SCT_STATUS_SUCCESS;
} // GetNewOptionNumber

//
// FUNCTION NAME.
//      CreateNewOption - Create a new LOAD_OPTION_OBJECT from parameters.
//
// FUNCTIONAL DESCRIPTION.
//      This function takes the parameters and allocates all necessary memory
//      to construct the Option Object.
//
//      This function allocates a new OptionNumber using the GetNewOptionNumber
//      function and then creates the option with the CreateOption function.
//
//      This function checks the Option database to see if the Option already
//      exists. If the Option already exists but is the same, this function
//      frees all the newly allocated memory and returns with success. If the
//      Option exists but is different, the old Option will be destroyed and
//      the new Option will be added. If the Option did not exist it will be
//      added.
//
//      If the Option was added it will also be saved, which saves the Option
//      to the non-volatile store.
//
//      Should an option no longer be needed, it should be de-allocated by
//      calling DestroyOption, since there are several sub-buffers used in
//      an Option object.
//
//      Note that this function does not support more than one element in the
//      FilePathList. This function will assume that there is exactly one entry
//      in this array, and it will calculate the size of the FilePathList based
//      solely on the size of the Device Path pointed to by the DevicePath
//      parameter. The DevicePath parameter is used as the FilePathList.
//
//
// ENTRY PARAMETERS.
//      OptionType      - a UINTN value specifying the type, Boot or Driver.
//      Attributes      - a UINT32 value, the attributes field of the Load Option.
//      Description     - a CHAR16 string pointer for the Load Option.
//      DevicePath      - the Device Path for the Load Option.
//      OptionalDataLength - the number of bytes in the OptionalData buffer.
//      OptionalData    - a buffer to be passed to the Image when starting.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//                        EFI_UNSUPPORTED - If the created one is duplicated in DB.
//
//      OptionNumber    - address of a UINT16 value, the new option.
//      NewOption       - address of the pointer to the new Option object.
//

SCT_STATUS
EFIAPI
CreateNewOption (
  OUT PUINT16 OptionNumber, OPTIONAL
  IN UINTN OptionType,
  IN UINT32 Attributes,
  IN PCHAR16 Description,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINT32 OptionalDataLength,
  IN PUINT8 OptionalData,
  OUT PLOAD_OPTION_OBJECT *NewOption OPTIONAL
  )
{
  SCT_STATUS Status;
  UINT16 NewOptionNumber;
  PUINT16 pNewOptionNumber;

  DPRINTF_LO ("CreateNewOption:\n");

  //
  // The caller may not care what the option number is. If the caller did not
  // provide a pointer to the option number we provide it here.
  //

  if (OptionNumber == NULL) {
    pNewOptionNumber = &NewOptionNumber;
  } else {
    pNewOptionNumber = OptionNumber;
  }

  Status = GetNewOptionNumber (pNewOptionNumber, OptionType);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return CreateOption (
           *pNewOptionNumber,
           OptionType,
           Attributes,
           Description,
           DevicePath,
           OptionalDataLength,
           OptionalData,
           NewOption);
} // CreateNewOption

//
// FUNCTION NAME.
//      DestroyOption - De-allocate an Option object.
//
// FUNCTIONAL DESCRIPTION.
//      This function de-allocates all the memory associated with an Option.
//
// ENTRY PARAMETERS.
//      Option          - pointer to an Option object.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
DestroyOption (
  IN PLOAD_OPTION_OBJECT Option
  )
{

  if (Option == NULL) {
    DPRINTF_LO ("DestroyOption: Error, Option is NULL.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  DPRINTF_LO ("DestroyOption:0x%x.\n", Option->OptionNumber);

  SafeFreePool (Option->OptionalData);
  SafeFreePool (Option->Description);
  SafeFreePool (Option->FilePathList);
  SafeFreePool (Option);

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // DestroyOption

//
// FUNCTION NAME.
//      AddOption - Add an option to the Option object database.
//
// FUNCTIONAL DESCRIPTION.
//      This function adds and Option object to the database.
//
//      The Option object database consists of two lists of options. One list
//      contains boot load options and the other list contains driver load
//      options.
//
//      This function will link the option into the appropriate list, per the
//      OptionType. The list will be scanned to make sure that an option with
//      this OptionNumber does not already exist. No other sanity checks are
//      preformed.
//
//      Note that the memory pointed to by Option will be linked to directly
//      from our database and should not be destroyed. The database owns this
//      memory now and the database will free the memory if the option is
//      removed with a call to RemoveOption.
//
// ENTRY PARAMETERS.
//      Option          - pointer to the Option object to add to the database.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
AddOption (IN PLOAD_OPTION_OBJECT Option)
{
  PLOAD_OPTION_OBJECT *p;

  DPRINTF_LO ("AddOption 0x%x @ 0x%x.\n", Option->OptionNumber, Option);

  if (Option == NULL) {
    DPRINTF_LO ("  Error:NULL Option.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  if (Option->OptionType == SCT_BM_LO_BOOT) {
    p = &mBootOptionListHead;
    DPRINTF_LO ("  Boot List @ 0x%x = 0x%x.\n", p, *p);
  } else if (Option->OptionType == SCT_BM_LO_DRIVER) {
    p = &mDriverOptionListHead;
    DPRINTF_LO ("  Driver List @ 0x%x = 0x%x.\n", p, *p);
  } else if (Option->OptionType == SCT_BM_LO_SYS_PREP) {
    p = &mSysPrepOptionListHead;
    DPRINTF_LO ("  SysPrep List @ 0x%x = 0x%x.\n", p, *p);
  } else {
    DPRINTF_LO ("  Bad OptionType 0x%x.\n", Option->OptionType);
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Find the last node in the list. Make sure along the way that this
  // OptionNumber does not already exist in the list.
  //

  DPRINTF_LO ("  Search for the end of the option list.\n");
  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (*p, L"  ");
    });
    if (*p == NULL) {
      break;
    }
    if ((*p)->OptionNumber == Option->OptionNumber) {
      DPRINTF_LO ("  Duplicate OptionNumber 0x%x.\n", Option->OptionNumber);
      return SCT_STATUS_ACCESS_DENIED;
    }
    p = &((*p)->Next);                  // p is the address of the next pointer.
  }
  DPRINTF_LO ("  Found end of list. p 0x%x:0x%x.\n", p, *p);

  //
  // Append a this option to the list.
  //

  DPRINTF_LO ("  Set p 0x%x:0x%x to 0x%x.\n", p, *p, Option);
  *p = Option;
  (*p)->Next = NULL;                    // make sure the list is still terminated.
  return SCT_STATUS_SUCCESS;
} // AddOption

//
// FUNCTION NAME.
//      RemoveOption - Remove an option from the database.
//
// FUNCTIONAL DESCRIPTION.
//      This function removes an option from the database.
//
//      The option list, per OptionType, will be scanned for the OptionNumber.
//      If the option is found in the list it will be unlinked.
//
//      The memory used by Option will be freed with a call to DestroyOption.
//
//      This function does not assume that the Option you pass in is a pointer
//      to the actual memory structure you want unlinked and destroyed. It is
//      fine to pass in a copy of the Option.
//
// ENTRY PARAMETERS.
//      Option          - pointer to the Option object to remove from the
//                        database.
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
RemoveOption (IN PLOAD_OPTION_OBJECT Option)
{
  PLOAD_OPTION_OBJECT *p;
  PLOAD_OPTION_OBJECT q;
  SCT_STATUS Status;

  DPRINTF_LO ("RemoveOption 0x%x @ 0x%x.\n", Option->OptionNumber, Option);

  if (Option == NULL) {
    DPRINTF_LO ("  Error:NULL Option.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  if (Option->OptionType == SCT_BM_LO_BOOT) {
    p = &mBootOptionListHead;
    DPRINTF_LO ("  Boot List @ 0x%x = 0x%x.\n", p, *p);
  } else if (Option->OptionType == SCT_BM_LO_DRIVER) {
    p = &mDriverOptionListHead;
    DPRINTF_LO ("  Driver List @ 0x%x = 0x%x.\n", p, *p);
  } else if (Option->OptionType == SCT_BM_LO_SYS_PREP) {
    p = &mSysPrepOptionListHead;
    DPRINTF_LO ("  SysPrep List @ 0x%x = 0x%x.\n", p, *p);
  } else {
    DPRINTF_LO ("  Bad OptionType 0x%x.\n", Option->OptionType);
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Find the pointer that is pointing at the Option Object that we want to
  // remove. Point that pointer to whatever the Option Object being removed
  // is currently pointing to.
  //

  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (*p, L"  ");
    });
    if (*p == NULL) {
      return SCT_STATUS_NOT_FOUND;
    }
    if ((*p)->OptionNumber == Option->OptionNumber) {
      DPRINTF_LO ("  Found it @ 0x%x.\n", *p);
      break;
    }
    p = &((*p)->Next);                  // p is the address of the next pointer.
  }

  //
  // p is the now the address of the pointer that points to the object we want.
  // *p will be the address of the object we need to destroy.
  // (*p)->Next is the address of the next object in the list.
  //

  q = *p;                               // The address of the object to destroy.
  *p = (*p)->Next;                      // The address of the next object in the list.
  Status = DestroyOption (q);           // Destroy after unlinking.

  return Status;
} // RemoveOption

//
// FUNCTION NAME.
//      SaveOption - Save an option to an EFI Variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function saves an option to a variable. The name of the variable
//      will be constructed using the OptionType and OptionNumber fields of
//      the Option Object.
//
// ENTRY PARAMETERS.
//      Option          - a pointer to an Option Object.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
SaveOption (IN PLOAD_OPTION_OBJECT Option)
{
  EFI_STATUS Status;
  CHAR16 VariableName [12];             // SysPrep####\0 is longer than Boot####\0.

  DPRINTF_LO ("SaveOption 0x%x @ 0x%x.\n", Option->OptionNumber, Option);

  switch (Option->OptionType)  {
    case SCT_BM_LO_BOOT :
      UnicodeSPrint (VariableName, sizeof (VariableName), L"Boot%04x", Option->OptionNumber);
    break;
    case SCT_BM_LO_DRIVER :
      UnicodeSPrint (VariableName, sizeof (VariableName), L"Driver%04x", Option->OptionNumber);
    break;
    case SCT_BM_LO_SYS_PREP :
      UnicodeSPrint (VariableName, sizeof (VariableName), L"SysPrep%04x", Option->OptionNumber);
    break;
    default :
      DPRINTF_LO ("  Bad OptionType 0x%x.\n", Option->OptionType);
      return SCT_STATUS_INVALID_PARAMETER;
    break;
  }

  UpdateKeyOptionCrcData (Option->OptionNumber);

  //
  // Set the variable and return that status.
  //
  DPRINTF_LO ("  SetEfiGlobalVariable : [%s]. Option->Description = [%s] (%d)\n", VariableName, Option->Description, __LINE__);
  Status = SetEfiGlobalVariable (
           VariableName,
           EFI_VARIABLE_NON_VOLATILE|
           EFI_VARIABLE_BOOTSERVICE_ACCESS|
           EFI_VARIABLE_RUNTIME_ACCESS,
           Option->RawLength,
           Option->RawData);

  return Status;
} // SaveOption

//
// FUNCTION NAME.
//      DeleteBootOption - Remove an option from the variable store.
//
// FUNCTIONAL DESCRIPTION.
//      If there is a variable for this option this function deletes it.
//      This function only processes Boot Options, not Driver Options.
//
// ENTRY PARAMETERS.
//      OptionNumber    - A UINT16 value, the number of the BootOption to
//                        delete.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
DeleteBootOption (IN UINT16 OptionNumber)
{
  CHAR16 VariableName [9];              // Boot####\0.

  UnicodeSPrint (VariableName, sizeof (VariableName), L"Boot%04x", OptionNumber);

  //
  // Set the variable and return that status.
  //

  return SetEfiGlobalVariable (
           VariableName,
           EFI_VARIABLE_NON_VOLATILE|
           EFI_VARIABLE_BOOTSERVICE_ACCESS|
           EFI_VARIABLE_RUNTIME_ACCESS,
           0,
           NULL);
} // DeleteBootOption

//
// FUNCTION NAME.
//      OptionCmp - Compare two options.
//
// FUNCTIONAL DESCRIPTION.
//      This function compares two options to see if they are the same.
//      What "compares two options" means could be many things. In this
//      function we define that to mean that the OptionNumber, OptionType,
//      FilePathList, Description, and OptionalData.
//
// ENTRY PARAMETERS.
//      p               - pointer to an Option Object.
//      q               - pointer to an Option Object.
//
// EXIT PARAMETERS.
//      Function Return - true if they are the same, otherwise false.
//

BOOLEAN
OptionCmp (
  IN PLOAD_OPTION_OBJECT p,
  IN PLOAD_OPTION_OBJECT q
  )
{
  DPRINTF_LO ("OptionCmp 0x%x <-> 0x%x.\n", p, q);
  if ((p != NULL)&&(q == NULL)) return FALSE;
  if ((p == NULL)&&(q != NULL)) return FALSE;
  if ((p == NULL)&&(q == NULL)) ASSERT (FALSE);

  if (p->OptionNumber != q->OptionNumber) {
    DPRINTF_LO ("  OptionNumber 0x%x <-> 0x%x.\n",
      p->OptionNumber, q->OptionNumber);
    return FALSE;
  }

  if (p->OptionType != q->OptionType) {
    DPRINTF_LO ("  OptionType 0x%x <-> 0x%x.\n",
      p->OptionType, q->OptionType);
    return FALSE;
  }

  if (p->Attributes != q->Attributes) {
    DPRINTF_LO ("  Attributes 0x%x <-> 0x%x.\n",
      p->Attributes, q->Attributes);
    return FALSE;
  }

  if (p->FilePathListLength != q->FilePathListLength) {
    DPRINTF_LO ("  FilePathListLength 0x%x <-> 0x%x.\n",
      p->FilePathListLength, q->FilePathListLength);
    return FALSE;
  }
  if (CompareMem (p->FilePathList, q->FilePathList, p->FilePathListLength)) {
    DPRINTF_LO ("  FilePathList mismatch.\n");
    return FALSE;
  }

  if (p->DescriptionLength != q->DescriptionLength) {
    DPRINTF_LO ("  DescriptionLength 0x%x <-> 0x%x.\n",
      p->DescriptionLength, q->DescriptionLength);
    return FALSE;
  }
  if (CompareMem (p->Description, q->Description, p->DescriptionLength)) {
    DPRINTF_LO ("  Description mismatch %s <-> %s.\n",
      p->Description, q->Description);
    return FALSE;
  }

  if (p->OptionalDataLength != q->OptionalDataLength) {
    DPRINTF_LO ("  OptionalDataLength 0x%x <-> 0x%x.\n",
      p->OptionalDataLength, q->OptionalDataLength);
    return FALSE;
  }
  if (CompareMem (p->OptionalData, q->OptionalData, p->OptionalDataLength)) {
    DPRINTF_LO ("  OptionalData mismatch.\n",
      p->Description, q->Description);
    return FALSE;
  }

  return TRUE;
} // OptionCmp

//
// FUNCTION NAME.
//      FreeOptionList - Free internal option list.
//
// FUNCTIONAL DESCRIPTION.
//      Free the allocated resource of each option in the internal list.
//
// ENTRY PARAMETERS.
//      Type            - SCT_BM_LO_BOOT or SCT_BM_LO_DRIVER.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
FreeOptionList (IN UINT8 Type)
{
  PLOAD_OPTION_OBJECT p;
  PLOAD_OPTION_OBJECT q;

  if (Type == SCT_BM_LO_BOOT) {
    p = mBootOptionListHead;
    mBootOptionListHead = NULL;
  } else if (Type == SCT_BM_LO_DRIVER) {
    p = mDriverOptionListHead;
    mDriverOptionListHead = NULL;
  } else if (Type == SCT_BM_LO_SYS_PREP) {
    p = mSysPrepOptionListHead;
    mSysPrepOptionListHead = NULL;
  } else {
    return EFI_INVALID_PARAMETER;
  }

  while (TRUE) {
    if (p == NULL) {
      break;
    }
    q = p;
    p = p->Next;
    DestroyOption (q);
  }

  return EFI_SUCCESS;
} // FreeOptionList

//
// FUNCTION NAME.
//      ValidateOrderVariable - Validate BootOrder or DriverOrder variable.
//
// FUNCTIONAL DESCRIPTION.
//      Validate the BootOrder variable.
//      If there are any options listed in the variable that do not exist,
//      remove them from the variable.
//
// ENTRY PARAMETERS.
//      VariableName    - pointer to a CHAR16 string, the variable name.
//      OptionType      - the Option Type of this Order list.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
ValidateOrderVariable (
  IN PCHAR16 VariableName,
  IN UINTN OptionType
  )
{
  UINTN i;
  UINTN j;
  SCT_STATUS Status;
  PUINT16 TempOrder;
  PUINT16 OptionOrder;
  UINTN OptionOrderSize;
  BOOLEAN FoundWinBootMgr;
  PLOAD_OPTION_OBJECT Option;

  DPRINTF_LO ("ValidateOrderVariable:%s, OptionType = 0x%x.\n",
    VariableName, OptionType);

  //
  // Get the variable.
  //

  Status = SctLibGetEfiGlobalVariable (
             VariableName,
             NULL,                      // don't care about attributes.
             &OptionOrderSize,
             (VOID **) &OptionOrder);
  DPRINTF_LO ("  SctLibGetEfiGlobalVariable returned %r.\n", Status);
  if (EFI_ERROR(Status)) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  DPRINTF_LO ("  OptionOrderSize = 0x%x\n", OptionOrderSize);

  //
  // The variable was found, so now we need to remove any Options listed that
  // are not present in the database.
  //

  TempOrder = AllocateZeroPool (OptionOrderSize);
  if (TempOrder == NULL) {
    SafeFreePool (OptionOrder);
    return SCT_STATUS_OUT_OF_RESOURCES;
  }

  FoundWinBootMgr = FALSE;
  j = 0;                                // j serves as an index and as a count.
  for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {
    DPRINTF_LO ("  Find Option %d = 0x%x\n", i, OptionOrder [i]);
    Status = GetOption (
               OptionOrder [i],
               OptionType,
               &Option);
    if (EFI_ERROR(Status)) {
      DPRINTF_LO (" Fail to find Option [0x%x] = 0x%x, %r.\n",
        i,
        OptionOrder [i],
        Status);
      continue;
    }

    if (SCT_BM_LO_BOOT == OptionType) {

      //
      // Just keep one Windows Boot Manager in the list.
      //

      if (StrCmp (Option->Description, WINDOWS_BOOTMGR_DESCRIPTION) == 0) {
        DPRINTF_LO ("  Find Windows BootMgr in BootOrder\n");
        if (FoundWinBootMgr == FALSE) {
          DPRINTF_LO ("  First one\n");
          FoundWinBootMgr = TRUE;
        } else {
          DPRINTF_LO ("  Duplicated one, remove it from BootOrder\n");
          continue;
        }
      }
      Option->InBootOrder = TRUE;
    }

    TempOrder [j] = OptionOrder [i];
    j++;
  }

  //
  // If the count (j) is not the same as the number of elements in the variable
  // we need to update the variable to remove the extra elements.
  //

  if (j != OptionOrderSize / sizeof (UINT16) &&
      j <= CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER) {
    DPRINTF_LO ("  Option mismatch, save variable again.\n");
    SetEfiGlobalVariable (
      VariableName,
      EFI_VARIABLE_NON_VOLATILE |
      EFI_VARIABLE_BOOTSERVICE_ACCESS |
      EFI_VARIABLE_RUNTIME_ACCESS,
      j * sizeof (UINT16),
      TempOrder);
  }

  SafeFreePool (TempOrder);
  SafeFreePool (OptionOrder);
  DPRINTF_LO ("ValidateOrderVariable:Success.\n");
  return SCT_STATUS_SUCCESS;
} // ValidateOrderVariable

//
// FUNCTION NAME.
//      GetOption - Get an Option Object from the database.
//
// FUNCTIONAL DESCRIPTION.
//      This function searches the database, per OptionType, to find an Option
//      object with the OptionNumber specified.
//
//      The Option parameter is optional. When it is not provided the Status
//      simply indicates if this Option Object exists in the Option database.
//
// ENTRY PARAMETERS.
//      OptionNumber    - a UINT16 value, the number of the option.
//      OptionType      - a UINTN value, the type of the option Boot or Driver.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      Option          - the address of a pointer that will be updated with
//                        the address of the Option Object whose OptionNumber
//                        field is the same as the OptionNumber parameter of
//                        this function.
//

SCT_STATUS
EFIAPI
GetOption (
  IN UINT16 OptionNumber,
  IN UINTN OptionType,
  OUT PLOAD_OPTION_OBJECT *Option OPTIONAL
  )
{
  PLOAD_OPTION_OBJECT p;

  DPRINTF_LO ("GetOption 0x%x, Type = 0x%x.\n", OptionNumber, OptionType);

  if (OptionType == SCT_BM_LO_BOOT) {
    p = mBootOptionListHead;
    DPRINTF_LO ("  Boot List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_DRIVER) {
    p = mDriverOptionListHead;
    DPRINTF_LO ("  Driver List @ 0x%x.\n", p);
  } else if (OptionType == SCT_BM_LO_SYS_PREP) {
    p = mSysPrepOptionListHead;
    DPRINTF_LO ("  SysPrep List @ 0x%x.\n", p);
  } else {
    DPRINTF_LO ("  Bad OptionType 0x%x.\n", OptionType);
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Search for the load option, if not found return SCT_STATUS_NOT_FOUND.
  //

  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (p, L"  ");
    });
    if (p == NULL) {
      DPRINTF_LO ("  Couldn't find Option:0x%x.\n", OptionNumber);
      return SCT_STATUS_NOT_FOUND;
    }
    if (p->OptionNumber == OptionNumber) {
      break;
    }
    p = p->Next;
  }

  //
  // Return with success.
  //

  DPRINTF_LO ("  Found it:\n");
  DISPLAY_OPTION_INFORMATION (p, L"    ");
  if (Option != NULL) {
    *Option = p;
  }
  return SCT_STATUS_SUCCESS;
} // GetOption

//
// FUNCTION NAME.
//      GetOptionString - Create an option string for a bootable device.
//
// FUNCTIONAL DESCRIPTION.
//      The Device Path protocol instance passed into this function is also
//      attached to the handle passed into this function. They are two
//      parameters strictly for convenience.
//
//      The board module is expected to provide translation for the device
//      path to string. Often the string needs to correspond to a silk screen
//      value on the board to the positioning of a port on the chassis. This
//      is board level mapping.
//
//      If no board mapping is provided this function will use the text of
//      the device path as the string.
//
// ENTRY PARAMETERS.
//      Handle          - EFI Handle referencing this device.
//      DevicePath      - ptr to the EFI_DEVICE_PATH_PROTOCOL instance for this
//                        device.
//
// EXIT PARAMETERS.
//      Function Return - unicode string, the description for this device.
//

PCHAR16
EFIAPI
GetOptionString (
  IN EFI_HANDLE Handle,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  PCHAR16 Str;

  //
  // NEWREL 09/07/07 cu, This function is used by EnumerateAllBootOptions. The
  // default operation of the Boot Manager does not use this function, although
  // it is commonly used during development to list out all the boot-able
  // devices. It would be nice to display a name that was more human readable
  // than just the device path.
  //

  Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
  return Str;
} // GetOptionString

//
// FUNCTION NAME.
//      AddOptionByHandle - Add an option for this handle, if it does not already exist.
//
// FUNCTIONAL DESCRIPTION.
//      This function adds an option to the database with the device path from
//      the input handle. Before adding the option the database is scanned for
//      any instances of the device path. If there is an option in the database
//      with this device path this function will return an error.
//
// ENTRY PARAMETERS.
//      Handle          - EFI Handle referencing the device to add an option for.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      OptionNumber    - the address of a UINT16, the option number that was added.
//

SCT_STATUS
AddOptionByHandle (
  IN EFI_HANDLE Handle,
  OUT PUINT16 OptionNumber
  )
{
  PCHAR16 Str;
  SCT_STATUS Status;
  PLOAD_OPTION_OBJECT p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  DPRINTF_LO ("AddOptionByHandle: 0x%x.\n", Handle);

  //
  // Get the device path of this handle.
  //

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **) &DevicePath,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR (Status) || DevicePath == NULL) {
    return Status;
  }

  //
  // Scan the database for an option with this device path.
  //

  p = mBootOptionListHead;
  while (TRUE) {
    if (p == NULL) {
      break;    // This is a new option. Add it.
    }
    if (CompareDevicePath(p->FilePathList, DevicePath)) {
      DPRINTF_LO ("  This handle's device path already has an option: 0x%x\n",
        p->OptionNumber);
      return SCT_STATUS_UNSUPPORTED;
    }
    p = p->Next;
  }

  Str = GetOptionString (Handle, DevicePath);

  //
  // Create an option. CreateNewOption will automatically save the option's
  // variable.
  //

  Status = CreateNewOption (
             OptionNumber,                      // OptionNumber.
             SCT_BM_LO_BOOT,                    // OptionType.
             LOAD_OPTION_ACTIVE|
             LOAD_OPTION_CATEGORY_BOOT,         // Attributes.
             Str,                               // Description.
             DevicePath,                        // DevicePath.
             0,                                 // OptionalDataLength.
             NULL,                              // OptionalData.
             NULL);                             // NewOptionAddress.
  DPRINTF_LO ("  CreateNewOption returned %r.\n", Status);

  return SCT_STATUS_SUCCESS;
} // AddOptionByHandle

//
// FUNCTION NAME.
//      PrepareToBoot - Do last minute preparation for boot.
//
// FUNCTIONAL DESCRIPTION.
//      This function does all the last minute setup for a boot event including
//      setting the BootCurrent variable, signaling ReadyToBoot and setting
//      the Watchdog timer.
//
//      This is second to last chance for drivers to do something. The next
//      opportunity will be when the loader calls gBS->ExitBootServices.
//
// ENTRY PARAMETERS.
//      OptionNumber    - the Boot Option Number that we are about to boot.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
PrepareToBoot (IN UINT16 OptionNumber)
{
  SCT_STATUS Status;
  EFI_HANDLE Handle;

  DPRINTF_LO ("PrepareToBoot:0x%x.\n", OptionNumber);

 #if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  //
  //          UpdateBdaKeyboardFlag - Update BDA Keyboard Flags for NumLock.
  //
  UpdateBdaKeyboardFlag ();
 #endif //OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  //
  // Set Boot Current variable.
  //

  SetEfiGlobalVariable (
    EFI_BOOT_CURRENT_VARIABLE_NAME,
    EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS,
    sizeof (UINT16),
    &OptionNumber);

  //
  // Also copy OptionNumber to LastBootCurrent in NV storage.
  // So we will know what device to boot directly if resuming from S4.
  //

  gRT->SetVariable (
         L"LastBootCurrent",
         &gSctBdsServicesProtocolGuid,
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS |
         EFI_VARIABLE_NON_VOLATILE,
         sizeof (UINT16),
         &OptionNumber);

  //
  // Show Error Log Message Screen
  //

  PERF_START (0, "ShowErrLogMsgScreen", "PrepareToBoot", 0);
  Status = EFI_SUCCESS;
  if (ErrorInfoScreen == NULL) {
    Status = gBS->LocateProtocol
              ((EFI_GUID *)&gSctErrorScreenTextProtocolGuid,
              NULL,
              (VOID **) &ErrorInfoScreen);
  } // if (ErrorInfoScreen == NULL) {
  if (!EFI_ERROR (Status)) {
    SctSignalProtocolEvent(&gSctErrLogEnterProtocolGuid, NULL);
    ErrorInfoScreen->ShowAllErrorMessage (ErrorInfoScreen);
    SctSignalProtocolEvent(&gSctErrLogExitProtocolGuid, NULL);
  }

  PERF_END (0, "ShowErrLogMsgScreen", "PrepareToBoot", 0);

  if (mDxeSmmReadyToLockProtocol == FALSE) {
    Handle = NULL;
    DEBUG ((DEBUG_ERROR, "Install  gEfiDxeSmmReadyToLockProtocol\n"));
    Status = gBS->InstallProtocolInterface (
                    &Handle,
                    &gEfiDxeSmmReadyToLockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    NULL);
    mDxeSmmReadyToLockProtocol = TRUE;
  }

  PERF_START (0, "PrepareToBoot", "SignalEventReadyToBoot", 0);
  //
  // Signal ready to boot.
  //
  EfiSignalEventReadyToBoot();

  //
  // Report Status Code to indicate ReadyToBoot was signalled
  //
  REPORT_STATUS_CODE (EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT));
  PRINT_REPORT_STATUS("(EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT))\n");
  PERF_END (0, "PrepareToBoot", "SignalEventReadyToBoot", 0);

  //
  // Save Memory Map.
  //
#if OPTION_SYSTEM_BOOT_MANAGER_EFI_LEGACY_OS_SUPPORT
  SaveMemoryMap ();
#endif
  //
  // Signal AFTER ready to boot.
  //

  PERF_START (0, "PrepareToBoot", "MsTaskAfterReadyToBoot", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_AFTER_READY_TO_BOOT, MsTaskAfterReadyToBoot, NULL, 0);
  PERF_END (0, "PrepareToBoot", "MsTaskAfterReadyToBoot", 0);

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // PrepareToBoot

//
// FUNCTION NAME.
//      MatchHttpBootDevicePath - Check if the device path match.
//
// FUNCTIONAL DESCRIPTION.
//      This function Check whether Left and Right are the same without matching the specific
//      device path data in IP device path and URI device path node.
//
// ENTRY PARAMETERS.
//      Left            - The boot device path.
//      Right           - The searched device path.
//
// EXIT PARAMETERS.
//      Function Return - Boolean value to indicate Left and Right are the same.
//

BOOLEAN
MatchHttpBootDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *Left,
  IN EFI_DEVICE_PATH_PROTOCOL *Right
  )
{
  BOOLEAN IsIPv4Match;
  BOOLEAN IsIPv6Match;

  IsIPv4Match = FALSE;
  IsIPv6Match = FALSE;

  for (;  !IsDevicePathEnd (Left) && !IsDevicePathEnd (Right)
    ;  Left = NextDevicePathNode (Left), Right = NextDevicePathNode (Right)
    ) {
    if (CompareMem (Left, Right, DevicePathNodeLength (Left)) != 0) {

      if ((DevicePathType (Left) != MESSAGING_DEVICE_PATH) || (DevicePathType (Right) != MESSAGING_DEVICE_PATH)) {
        return FALSE;
      }

      if (DevicePathSubType (Left) == MSG_DNS_DP) {
        Left = NextDevicePathNode (Left);
      }

      if (DevicePathSubType (Right) == MSG_DNS_DP) {
        Right = NextDevicePathNode (Right);
      }

      //
      // The MAC address should be the same.
      //

      if ((DevicePathSubType (Left) == MSG_MAC_ADDR_DP) || (DevicePathSubType (Right) == MSG_MAC_ADDR_DP)) {
        return FALSE;
      }

      if (((DevicePathSubType (Left) != MSG_IPv4_DP) || (DevicePathSubType (Right) != MSG_IPv4_DP)) &&
        ((DevicePathSubType (Left) != MSG_IPv6_DP) || (DevicePathSubType (Right) != MSG_IPv6_DP)) &&
        ((DevicePathSubType (Left) != MSG_URI_DP)  || (DevicePathSubType (Right) != MSG_URI_DP))
        ) {
        return FALSE;
      }
    }

    if ((DevicePathType (Left) == MESSAGING_DEVICE_PATH) && (DevicePathSubType (Left) == MSG_IPv4_DP) &&
      (DevicePathType (Right) == MESSAGING_DEVICE_PATH) && (DevicePathSubType (Right) == MSG_IPv4_DP)) {
      IsIPv4Match = TRUE;
    }

    if ((DevicePathType (Left) == MESSAGING_DEVICE_PATH) && (DevicePathSubType (Left) == MSG_IPv6_DP) &&
      (DevicePathType (Right) == MESSAGING_DEVICE_PATH) && (DevicePathSubType (Right) == MSG_IPv6_DP)) {
      IsIPv6Match = TRUE;
    }
  }

  //DPRINTF (">>>>> IsIPv4Match = [%d] !! (%d) \n", IsIPv4Match, __LINE__);
  //DPRINTF (">>>>> IsIPv6Match = [%d] !! (%d) \n", IsIPv6Match, __LINE__);

  return (BOOLEAN) (IsDevicePathEnd (Left) && (IsIPv4Match | IsIPv6Match));
} // MatchHttpBootDevicePath

//
// FUNCTION NAME.
//      GetRamDiskMemoryInfo - Get Ram Disk information.
//
// FUNCTIONAL DESCRIPTION.
//      This function return the buffer and buffer size occupied by the RAM Disk.
//
// ENTRY PARAMETERS.
//      RamDiskDevicePath - the Device Path of the RAM Disk.
//
// EXIT PARAMETERS.
//      Function Return - RAM Disk buffer.
//      RamDiskSize - RAM Disk size in pages
//

VOID *
GetRamDiskMemoryInfo (
  IN EFI_DEVICE_PATH_PROTOCOL *RamDiskDevicePath,
  OUT UINTN *RamDiskSize
  )
{
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  UINT64 StartingAddr;
  UINT64 EndingAddr;

  *RamDiskSize = 0;

  if (RamDiskDevicePath == NULL) {
    return NULL;
  }

  //
  // Get the buffer occupied by RAM Disk.
  //

  Status = gBS->LocateDevicePath (&gEfiLoadFileProtocolGuid, &RamDiskDevicePath, &Handle);
  if (EFI_ERROR (Status)) {
    return NULL;
  }
  if ((DevicePathType (RamDiskDevicePath) != MEDIA_DEVICE_PATH) &&
    (DevicePathSubType (RamDiskDevicePath) != MEDIA_RAM_DISK_DP)) {
    return NULL;
  }

  StartingAddr = ReadUnaligned64 ((UINT64 *) ((MEDIA_RAM_DISK_DEVICE_PATH *) RamDiskDevicePath)->StartingAddr);
  EndingAddr = ReadUnaligned64 ((UINT64 *) ((MEDIA_RAM_DISK_DEVICE_PATH *) RamDiskDevicePath)->EndingAddr);
  *RamDiskSize = (UINTN) (EndingAddr - StartingAddr + 1);
  return (VOID *) (UINTN) StartingAddr;
} // GetRamDiskMemoryInfo

//
// FUNCTION NAME.
//      DestroyRamDisk - Destroy the RAM Disk.
//
// FUNCTIONAL DESCRIPTION.
//      This function destroy operation includes to call RamDisk.  Unregister to
//      unregister the RAM DISK from RAM DISK driver, free the memory
//      allocated for the RAM Disk.
//
// ENTRY PARAMETERS.
//      RamDiskDevicePath - the Device Path of the RAM Disk.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

VOID
DestroyRamDisk (IN EFI_DEVICE_PATH_PROTOCOL *RamDiskDevicePath)
{
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  VOID *RamDiskBuffer;
  UINTN RamDiskSizeInPages;

  if (RamDiskDevicePath == NULL) {
    return;
  }

  RamDiskBuffer = GetRamDiskMemoryInfo (RamDiskDevicePath, &RamDiskSizeInPages);

  //
  // Destroy RAM Disk.
  //

  if (mRam_Disk == NULL) {
    Status = gBS->LocateProtocol (&gEfiRamDiskProtocolGuid, NULL, (VOID *) &mRam_Disk);
  }

  if (mRam_Disk != NULL) {
    Status = mRam_Disk->Unregister (RamDiskDevicePath);
  }

  SafeFreePool (RamDiskBuffer);
} // DestroyRamDisk

//
// FUNCTION NAME.
//      GetRamDiskHandle - Get the handle from the RamDisk device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to find the best match of the pass-in BootPath
//      to find the Ram Disk handle.
//
// ENTRY PARAMETERS.
//      BootPath        - the Device Path for the Device Type to boot.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      RamDiskHandle   - The found handle of the Ram Disk.
//

EFI_STATUS
GetRamDiskHandle (
  IN EFI_DEVICE_PATH_PROTOCOL *BootPath,
  OUT EFI_HANDLE *RamDiskHandle
  )
{
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  EFI_HANDLE *Handles;
  UINTN HandleCount;
  UINTN Index;
  EFI_DEVICE_PATH_PROTOCOL *Node;

  Status = EFI_NOT_FOUND;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles);

  if (EFI_ERROR (Status)) {
    Handles = NULL;
    HandleCount = 0;
  }

  Handle = NULL;
  for (Index = 0; Index < HandleCount; Index++) {
    Node = DevicePathFromHandle (Handles [Index]);
    Status = gBS->LocateDevicePath (&gEfiLoadFileProtocolGuid, &Node, &Handle);

    if (!EFI_ERROR (Status) &&
      (DevicePathType (Node) == MEDIA_DEVICE_PATH) && (DevicePathSubType (Node) == MEDIA_RAM_DISK_DP)) {

      //
      // Try to find the match for the device path.
      //

      if (MatchHttpBootDevicePath (BootPath, DevicePathFromHandle (Handle))) {

        //
        // Check if it does have the simplefilesystem protocol.
        //

        Status = gBS->OpenProtocol (
                        Handles [Index], // the handle we are testing.
                        &gEfiSimpleFileSystemProtocolGuid,
                        NULL,         // interface - Not needed.
                        mImageHandle, // the handle for who is testing.
                        NULL,         // no controller handle.
                        EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
        if (!EFI_ERROR (Status)) {
          Handle = Handles [Index];
          break;
        }
      }
    }
  }

  if (Handles != NULL) {
    FreePool (Handles);
  }

  if (Index == HandleCount) {
    Handle = NULL;
  }

  if (Handle != NULL) {
    *RamDiskHandle = Handle;
    Status = EFI_SUCCESS;
  } else {
    *RamDiskHandle = NULL;
    Status = EFI_NOT_FOUND;
  }

  return Status;
} // GetRamDiskHandle


//
// FUNCTION NAME.
//      GetNicHandler - Get NicHandler for current Boot Device Path.
//
// FUNCTIONAL DESCRIPTION.
//      This function return the NIC Handler for current Boot Device Path.
//
// ENTRY PARAMETERS.
//      DevicePath      - the Device Path for the Device Type to boot.
//
// EXIT PARAMETERS.
//      Function Return - NIC Handler.
//                        if NOT found return NULL.
//

EFI_HANDLE
GetNicHandler (
  IN EFI_DEVICE_PATH_PROTOCOL *BootDevicePath
  )
{
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  EFI_HANDLE  PreNicHandler = NULL;
  EFI_HANDLE  NicHandler = NULL;
  CHAR16      *BootDevicePathStr = NULL;

  EFI_DEVICE_PATH_PROTOCOL  *NicDevicePath = NULL;
  CHAR16                    *NicDevicePathStr = NULL;

  UINTN         SnpHandlerCount = 0;
  EFI_HANDLE    *SnpHandlersBuffer = NULL;
  UINTN         i;

  DPRINTF_LO ("GetNicHandler Entry.\n");

  BootDevicePathStr = BM_CONVERT_DEVICE_PATH_TO_TEXT (BootDevicePath, FALSE, TRUE);
  DPRINTF_LO (" Boot DevicePath - [%s].\n", BootDevicePathStr);

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleNetworkProtocolGuid,
                  NULL,
                  &SnpHandlerCount,
                  &SnpHandlersBuffer);
  DPRINTF_LO (">>> Found SnpHandlerCount = [%d]  for the SimpleNetworkProtocol.\n", SnpHandlerCount);
  for (i = 0; i < SnpHandlerCount; i++) {
    EFI_DEVICE_PATH_PROTOCOL *TempDevicePath = DevicePathFromHandle (SnpHandlersBuffer [i]);
    DPRINTF_LO (">>> Found SnpHandlersBuffer[%d] 0x%x for the NIC Handler.\n", i, SnpHandlersBuffer [i]);

    if (TempDevicePath != NULL) {

      if (StrStr(BM_CONVERT_DEVICE_PATH_TO_TEXT(TempDevicePath, FALSE, TRUE), L"IP") != NULL) {
        continue;   // for loop
      }

      PreNicHandler = SnpHandlersBuffer [i];
      DPRINTF_LO ("    PreNicHandler = [0x%x].(%d)\n", PreNicHandler, __LINE__);

      NicDevicePath = DevicePathFromHandle (PreNicHandler);
      NicDevicePathStr = BM_CONVERT_DEVICE_PATH_TO_TEXT (NicDevicePath, FALSE, TRUE);
      DPRINTF_LO (" PreNicHandler DevicePath - [%s].\n", NicDevicePathStr);
      if (StrnCmp(BootDevicePathStr, NicDevicePathStr, StrLen(NicDevicePathStr)) !=0 ) {
        SafeFreePool (NicDevicePathStr);
        continue;   // for loop
      }
      SafeFreePool (NicDevicePathStr);

      NicHandler = SnpHandlersBuffer [i];
      break;        // for loop

    }
  }

  SafeFreePool (BootDevicePathStr);

  DPRINTF_LO ("GetNicHandler return NicHandler = [0x%x].\n", NicHandler);
  return NicHandler;
} // GetNicHandler


//
// FUNCTION NAME.
//      UefiBoot - Boot the UEFI way.
//
// FUNCTIONAL DESCRIPTION.
//      This function preforms a UEFI boot on the device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - the Device Path for the Device Type to boot.
//      OptionNumber    - the Option Number for this Device Path.
//      OptionalData    - the Data to pass to the boot.
//      OptionalDataLength - the number of byte of data.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
UefiBoot (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINT16 OptionNumber,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  )
{
  UINTN i;
  UINTN j;
  EFI_TPL Tpl;
  PCHAR16 ExitData;
  SCT_STATUS Status;
  UINTN ExitDataSize;
  BOOLEAN IsImageLoaded;
  SCT_STATUS RetStatus;
  UINTN NumberOfChildren;
  UINTN NumberOfFilePath;
  BOOLEAN AppendFilePath;
  EFI_HANDLE ConnectedHandle;
  EFI_HANDLE FileImageHandle;
  EFI_HANDLE *ChildHandleBuffer;
  UINTN HandleCount;
  EFI_HANDLE *Handles;
  BOOLEAN FoundHttpDp = FALSE;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_DEVICE_PATH_PROTOCOL *BootDevicePath;
  EFI_DEVICE_PATH_PROTOCOL **FilePathList;
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_HANDLE NicHandler = NULL;

  EFI_HANDLE RamDiskHandle;
 #if OPTION_SYSTEM_BOOT_MANAGER_UEFI_BOOT_CLEAR_SCREEN
  BOOLEAN ClearScreenBeforeBoot;
 #endif
 #if OPTION_SUPPORT_OS_INDICATIONS_CAPSULE_DELIVERY
  SCT_BDS_MILESTONE_CAPSULE_UPDATE_DATA CapsuleUpdateData;
 #endif
  INT32 StoMode, GopMode;

  DPRINTF_LO ("UefiBoot:\n");
  DEBUG_LO (
    DPRINTF_DEVICE_PATH ("DevicePath = ", DevicePath);
  );

  IsImageLoaded = FALSE;
  AppendFilePath = FALSE;
  NumberOfFilePath = 0;
  FilePathList = (EFI_DEVICE_PATH_PROTOCOL **)AllocatePool (sizeof (EFI_DEVICE_PATH_PROTOCOL *));

  //
  // Connect the Device Path.
  //

  ConnectedHandle = NULL;
  PERF_START (0, "ConnectDevicePath", "UefiBoot", 0);
  Status = ConnectDevicePathWithRemaining (
             DevicePath,
             &ConnectedHandle,
             &RemainingDevicePath);
  DPRINTF_LO ("  ConnectDevicePathWithRemaining returned %r.\n", Status);
  PERF_END (0, "ConnectDevicePath", "UefiBoot", 0);

  if (ConnectedHandle == NULL) {
    DPRINTF_LO ("  ConnectedHandle is NULL\n");
    Status = UpdateWindowsBootManagerBootOption (OptionNumber, &DevicePath);
    if (EFI_ERROR (Status)) {
      return EFI_UNSUPPORTED;
    }
    Status = ConnectDevicePathWithRemaining (
               DevicePath,
               &ConnectedHandle,
               &RemainingDevicePath);
  }

#if OPTION_SYSTEM_BOOT_MANAGER_CONNECT_ALL_WITH_INTERNAL_SHELL_AT_FIRST_BOOT_ORDER
{
  //
  // Check First Boot Order is "Internal Shell"
  //
  UINT16 *BootOrderList = NULL;
  LOAD_OPTION_OBJECT *LoadOption = NULL;
  EFI_DEVICE_PATH_PROTOCOL *DeviceNode = NULL;
  EFI_DEVICE_PATH_PROTOCOL *CompareNode = NULL;

  GetEfiGlobalVariable2 (EFI_BOOT_ORDER_VARIABLE_NAME, (VOID **)&BootOrderList, NULL);
  if ( BootOrderList[0] == OptionNumber) {
    Status = GetBootOption (OptionNumber, &LoadOption);
    if (!EFI_ERROR (Status) && LoadOption != NULL) {
      DPRINTF_LO ("  LoadOption->Description = [%s]\n", LoadOption->Description);
      DEBUG_LO ( DPRINTF_DEVICE_PATH ("  LoadOption->FilePathList = ", LoadOption->FilePathList); );
      if ( StrCmp (LoadOption->Description, CONFIG_SYSTEM_INTERNAL_SHELL_DESCRIPTION) == 0 ) {
        DPRINTF ("  SHELL DESCRIPTION = [%s]\n", CONFIG_SYSTEM_INTERNAL_SHELL_DESCRIPTION);
        DPRINTF ("  SHELL DEVICE_PATH = [%s]\n", CONFIG_SYSTEM_INTERNAL_SHELL_DEVICE_PATH);

        DeviceNode = GetLastDeviceNode (DevicePath);
        DEBUG_LO ( DPRINTF_DEVICE_PATH ("DeviceNode = ", DeviceNode); );

        CompareNode = BM_CONVERT_TEXT_TO_DEVICE_PATH (CONFIG_SYSTEM_INTERNAL_SHELL_DEVICE_PATH);
        DEBUG_LO ( DPRINTF_DEVICE_PATH ("CompareNode = ", CompareNode); );

        if (CompareDevicePath (DeviceNode, CompareNode)) {
          Status = ConnectAllHandlesExceptPciVga();
          if (EFI_ERROR(Status)) {
            DPRINTF_ERROR (" ConnectAllHandlesExceptPciVga () ret [%r] for [%s]\n",
              Status, CONFIG_SYSTEM_INTERNAL_SHELL_DESCRIPTION);
          }
        }
      }
    }
  }
}
#endif

  //
  // Check if the LastNode is URI, then search the LoadFile protocols to find the handle since the HTTP boot
  // installed DevicePath protocol will be updated/reinstall each time if the HTTP boot driver connect to the
  // DHCP server successfully.  And it will result the IP information or URI string from the installed DevicePath
  // protocol will be different each time and cause the LocateDevicePath function will not be able to locate
  // the correct handle.
  //

  LastNode = GetLastDeviceNode (DevicePath);
  if ((DevicePathType (LastNode) == MESSAGING_DEVICE_PATH) &&
    (DevicePathSubType (LastNode) == MSG_URI_DP)) {

    DPRINTF_LO ("  The DevicePath last node is URI.\n");
    DEBUG_LO (
      DPRINTF_DEVICE_PATH ("   ", DevicePath);
    );
    Handles = NULL;
    Status = gBS->LocateHandleBuffer (
                    ByProtocol,
                    &gEfiLoadFileProtocolGuid,
                    NULL,
                    &HandleCount,
                    &Handles);
    if (EFI_ERROR (Status)) {
      Handles = NULL;
      HandleCount = 0;
    }
    FoundHttpDp = FALSE;
    for (i = 0; i < HandleCount; i++) {
      if (MatchHttpBootDevicePath (DevicePathFromHandle (Handles [i]), DevicePath)) {

        DPRINTF_LO ("  Found ConnectedHandle 0x%x for the HTTP boot DevicePath.\n", Handles [i]);
        ConnectedHandle = Handles [i];
        FoundHttpDp = TRUE;
        NicHandler = GetNicHandler(DevicePath);
        break;
      }
    }
    if (Handles != NULL) {
      FreePool (Handles);
    }
    if (FoundHttpDp == FALSE) {
      DPRINTF_LO ("  Could not find the LoadFile protocol for HTTP boot DevicePath.\n");
    }
  }

  //
  // Attempt to load the image. We are going to look for a device path that
  // actually succeed when we attempt to load it. This will involve looking
  // at the protocols on ConnectedHandle and the value of RemainingDevicePath.
  // Once FileDevicePath is non-NULL we are ready to call LoadImage.
  //
  // The priority of protocols on ConnectedHandle is FirmwareVolume then
  // SimpleFileSystem then LoadFile. If none of these is supported we look for
  // BlockIo.
  //
  // If BlockIo is supported we will connect it recursively and look at all
  // the children under this handle to see if any of them have the
  // SimpleFileSystem protocol. Then we will append the default file to each
  // of the first child that supports SimpleFileSystem and use that as the
  // device path to load.
  //

  PERF_START (0, "OpenProtocol:FWVolume", "UefiBoot", 0);
  Status = gBS->OpenProtocol (
                  ConnectedHandle,      // the handle we are testing.
                  &gEfiFirmwareVolume2ProtocolGuid,
                  NULL,                 // interface - Not needed.
                  mImageHandle,         // the handle for who is testing.
                  NULL,                 // no controller handle.
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
  DPRINTF_LO ("  Check ConnectedHandle 0x%x for the Firmware Volume Protocol: [%r].\n", ConnectedHandle, Status);
  PERF_END (0, "OpenProtocol:FWVolume", "UefiBoot", 0);

  if (!EFI_ERROR (Status)) {            // firmware volume is supported.

    //
    // If ConnectedHandle supports EFI_FIRMWARE_VOLUME_PROTOCOL
    // RemainingDevicePath must be a FvFile device path node that refers to the
    // GUID name of the file to load from the firmware volume.
    //

    FilePathList [0] = DuplicateDevicePath (DevicePath);
    NumberOfFilePath = 1;
  } else {                              // firmware volume is not supported.

    PERF_START (0, "EfiSimpleFileSystem", "UefiBoot", 0);
    Status = gBS->OpenProtocol (
                    ConnectedHandle,    // the handle we are testing.
                    &gEfiSimpleFileSystemProtocolGuid,
                    NULL,               // interface - Not needed.
                    mImageHandle,       // ihe handle for who is testing.
                    NULL,               // no controller handle.
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
    DPRINTF_LO ("  Check ConnectedHandle 0x%x for the Simple File System Protocol: [%r].\n", ConnectedHandle, Status);
    PERF_END (0, "EfiSimpleFileSystem", "UefiBoot", 0);

    if (!EFI_ERROR (Status)) {          // simple File System is supported.

      DPRINTF_LO (">>>>>>> It [IS] Simple File System \n");

      //
      // If ConnectedHandle supports EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
      // RemainingDevicePath should be a Media Device Path node(s)
      // specifying the path name part of the device path DevicePath.
      //

      PERF_START (0, "FinishDevicePath", "UefiBoot", 0);
      if (IsDevicePathEnd (RemainingDevicePath)) {

        //
        // No file was specified, so we must append the default file path to the
        // device path.
        //

        AppendFilePath = TRUE;
        FilePathList [0] = FileDevicePath (ConnectedHandle, EFI_REMOVABLE_MEDIA_FILE_NAME);
        NumberOfFilePath = 1;
      } else {

        //
        // Assume that RemainingDevicePath is a Media Device Path.
        //

        FilePathList [0] = DuplicateDevicePath (DevicePath);
        NumberOfFilePath = 1;
      } // if (IsDevicePathEnd (RemainingDevicePath)
      PERF_END (0, "FinishDevicePath", "UefiBoot", 0);
    } else { // Simple File System is not supported

      DPRINTF_LO (">>>>>>> It's [NOT] Simple File System \n");

      //
      // Look for the LoadFile protocol.
      //

      PERF_START (0, "OpenLoadFileProtocol", "UefiBoot", 0);
      Status = gBS->OpenProtocol (
                      ConnectedHandle,  // the handle we are testing.
                      &gEfiLoadFileProtocolGuid,
                      NULL,             // interface - Not needed.
                      mImageHandle,     // the handle for who is testing.
                      NULL,             // no controller handle.
                      EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
      DPRINTF_LO ("  Check ConnectedHandle 0x%x for the Load File Protocol: [%r].\n", ConnectedHandle, Status);
      PERF_END (0, "OpenLoadFileProtocol", "UefiBoot", 0);

      if (!EFI_ERROR (Status)) {        // LoadFile is supported.

        //
        // If ConnectedHandle supports EFI_LOAD_FILE_PROTOCOL, the remaining device
        // path nodes of DevicePath and the BootPolicy flag are passed to the
        // EFI_LOAD_FILE_PROTOCOL.LoadFile() function. The default image responsible
        // for booting is loaded when DevicePath specifies only the device (and
        // there are no further device nodes). For more information see the
        // discussion of the EFI_LOAD_FILE_PROTOCOL in Section 12.1.
        //

        PERF_START (0, "DuplicateDevicePath", "UefiBoot", 0);
        FilePathList [0] = DuplicateDevicePath (DevicePath);
        NumberOfFilePath = 1;
        PERF_END (0, "DuplicateDevicePath", "UefiBoot", 0);
      } else {
        EFI_DEVICE_PATH_PROTOCOL        *UpdatedDevicePath = DevicePath;
        EFI_HANDLE                      Handle;
        EFI_BLOCK_IO_PROTOCOL           *BlockIo;

        //
        // We have no DevicePath that will load.
        // If the handle supports BlockIo we must connect it recursively, then
        // look at each child handle for a handle with the Simple File System.
        // If we find such a handle we will set the device path to the device
        // path of that handle with the default file node appended.
        //

        PERF_START (0, "LoadFileCheck", "UefiBoot", 0);
        Status = gBS->OpenProtocol (
                        ConnectedHandle,// the handle we are testing.
                        &gEfiBlockIoProtocolGuid,
                        NULL,           // interface - Not needed.
                        mImageHandle,   // the handle for who is testing.
                        NULL,           // no controller handle.
                        EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
        DPRINTF_LO ("  Check ConnectedHandle 0x%x for the BlockIo Protocol: [%r].\n", ConnectedHandle, Status);
        if (EFI_ERROR (Status)) {
          return Status;
        }

        Status = gBS->LocateDevicePath (&gEfiBlockIoProtocolGuid, &UpdatedDevicePath, &Handle);
        if (EFI_ERROR (Status)) {
          //
          // Skip the case that the boot option point to a simple file protocol which does not consume block Io protocol,
          //
          Status = gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &UpdatedDevicePath, &Handle);
          if (EFI_ERROR (Status)) {
            //
            // Fail to find the proper BlockIo and simple file protocol, maybe because device not present,  we need to connect it firstly
            //
            UpdatedDevicePath = DevicePath;
            Status            = gBS->LocateDevicePath (&gEfiDevicePathProtocolGuid, &UpdatedDevicePath, &Handle);
            gBS->ConnectController (Handle, NULL, NULL, TRUE);
          }
        } else {
          //
          // Get BlockIo protocol and check removable attribute
          //
          Status = gBS->HandleProtocol (Handle, &gEfiBlockIoProtocolGuid, (VOID **)&BlockIo);
          ASSERT_EFI_ERROR (Status);

          //
          // It must do DisconnectController then ConnectController for some Non-RemovableMedia storage (Ex:Sata or Nvme) when Hdd PWD set
          //
          if (!BlockIo->Media->RemovableMedia) {
            Status = gBS->DisconnectController (
                            Handle,
                            NULL,
                            NULL);
          }

          gBS->ConnectController (Handle, NULL, NULL, TRUE);
        }

        DPRINTF_LO ("    Find the children.\n");
        Status = FindDeviceChildren (
                   ConnectedHandle,
                   &NumberOfChildren,
                   &ChildHandleBuffer);
        DPRINTF_LO ("    FindDeviceChildren returned %r\n", Status);
        if (EFI_ERROR (Status)) {
          return Status;
        }
        DPRINTF_LO ("    ChildHandleBuffer @ 0x%x, NumberOfChildren = 0x%x\n", ChildHandleBuffer, NumberOfChildren);

        //
        // Check each child for the Simple File System. If it exists setup
        // the device path and break out. We only use the first one we find.
        //

        SafeFreePool (FilePathList);
        FilePathList = (EFI_DEVICE_PATH_PROTOCOL **)AllocateZeroPool (sizeof (EFI_DEVICE_PATH_PROTOCOL *) * NumberOfChildren);
        for (i = 0; i < NumberOfChildren; i++) {
          Status = gBS->OpenProtocol (
                          ChildHandleBuffer [i], // the handle we are testing.
                          &gEfiSimpleFileSystemProtocolGuid,
                          NULL,         // interface - Not needed.
                          mImageHandle, // the handle for who is testing.
                          NULL,         // no controller handle.
                          EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
          DPRINTF_LO ("  Check Child Handle 0x%x for the Simple File System Protocol: [%r].\n", ChildHandleBuffer [i], Status);
          if (!EFI_ERROR (Status)) {
            FilePathList [NumberOfFilePath++] = FileDevicePath (ChildHandleBuffer [i], EFI_REMOVABLE_MEDIA_FILE_NAME);
            AppendFilePath = TRUE;
          }
        } // for (i = 0; i < NumberOfChildren; i++)

        SafeFreePool (ChildHandleBuffer);

        PERF_END (0, "LoadFileCheck", "UefiBoot", 0);
      } // Check for Load File.
    } // Check for Simple File System.
  } // Check for Firmware Volume.

  DPRINTF_LO ("NumberOfFilePath = %d\n", NumberOfFilePath);

  if (NumberOfFilePath == 0) {
    DPRINTF_LO ("  Device Path is not loadable.\n");
    return SCT_STATUS_NOT_FOUND;
  }

 #if OPTION_SUPPORT_OS_INDICATIONS_CAPSULE_DELIVERY

  //
  // Check if it need to proceed with capsule from ESP.
  //

  if ((mCapsuleEspDelivery == TRUE) && (mBootMode == BOOT_ON_FLASH_UPDATE)) {
    CapsuleUpdateData.BootMode = mBootMode;
    PERF_START (0, "CapsuleFlashUpdate", "BootManager", 0);
    SCT_MILESTONE_TASK (
      BDS_MILESTONE_TASK_CAPSULE_FLASH_UPDATE,
      MsTaskCapsuleFlashUpdate,
      &CapsuleUpdateData,
      sizeof (CapsuleUpdateData));
    PERF_END (0, "CapsuleFlashUpdate", "BootManager", 0);
  }
 #endif

  PERF_START (0, "PrepareToBoot", "UefiBoot", 0);
  Status = PrepareToBoot (OptionNumber);
  PERF_END (0, "PrepareToBoot", "UefiBoot", 0);

  PERF_START (0, "LoadImage", "UefiBoot", 0);

  //
  // Find the best boot target.
  //

  BootDevicePath = NULL;
  FileImageHandle = NULL;
  RamDiskHandle = NULL;
  for (j = 0; j < NumberOfFilePath; j++) {

    if (FilePathList [j] == NULL) {
      continue;
    }

    if (AppendFilePath) {
      RemainingDevicePath = FilePathList [j];
      ConnectedHandle = NULL;
      Status = gBS->LocateDevicePath (
                      &gEfiSimpleFileSystemProtocolGuid,
                      &RemainingDevicePath,
                      &ConnectedHandle);
    }

    IsImageLoaded = FALSE;

    REPORT_STATUS_CODE (EFI_PROGRESS_CODE, PcdGet32 (PcdProgressCodeOsLoaderLoad));

    for(i = 0; !IsImageLoaded; i++) {

      if (AppendFilePath) {
        SafeFreePool (FilePathList [j]);
        if (mBootableFilePath [i] != NULL) {
          //
          // Try alternative file path in the file system.
          //
          FilePathList [j] = FileDevicePath (ConnectedHandle, mBootableFilePath [i]);
        } else {
          //
          // Try default file path in the file system.
          //
          FilePathList [j] = FileDevicePath (ConnectedHandle, EFI_REMOVABLE_MEDIA_FILE_NAME);
        }
      }

      FileImageHandle = NULL;
      Status = gBS->LoadImage (
                     TRUE,
                     mImageHandle,
                     FilePathList [j],
                     NULL,
                     0,
                     &FileImageHandle);
      DEBUG_LO ({
        DPRINTF_DEVICE_PATH (" LoadImage: ", FilePathList [j]);
        DPRINTF_LO ("    returned %r.\n", Status);
      });

 #if OPTION_SUPPORT_SECURE_BOOT
      if (Status == EFI_SUCCESS || Status == EFI_SECURITY_VIOLATION)
 #else  //OPTION_SUPPORT_SECURE_BOOT
      if (Status == EFI_SUCCESS)
 #endif //OPTION_SUPPORT_SECURE_BOOT
      {
        IsImageLoaded = TRUE;
        //
        // Duplicate the device path of found boot target.
        //
        BootDevicePath = DuplicateDevicePath (FilePathList [j]);
        break;
      }

      //
      // Check if the Ram Disk has been installed by the LoadImage, if it is,
      // then it is the HttpBoot and need to check if it does produced SimpleFileSystem
      // protocol, then append the boot file device path.
      //

      if (RamDiskHandle == NULL) {
        if (!EFI_ERROR (GetRamDiskHandle (FilePathList [j], &RamDiskHandle))) {

          EFI_DEVICE_PATH_PROTOCOL **TempFilePathList;

          //DumpAllDevicePaths ();

          //
          // Assume the Ram Disk should only provide one SimpleFileSystem.
          //

          Status = gBS->OpenProtocol (
                          RamDiskHandle, // the handle we are testing.
                          &gEfiSimpleFileSystemProtocolGuid,
                          NULL,         // interface - Not needed.
                          mImageHandle, // the handle for who is testing.
                          NULL,         // no controller handle.
                          EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

          DPRINTF_LO ("    Check gEfiSimpleFileSystemProtocolGuid return %r\n", Status);
          if (!EFI_ERROR (Status)) {
            TempFilePathList = FilePathList;
            FilePathList = AllocateZeroPool (sizeof (EFI_DEVICE_PATH_PROTOCOL *) * (NumberOfFilePath + 1));
            CopyMem (FilePathList, TempFilePathList, sizeof (EFI_DEVICE_PATH_PROTOCOL *));
            SafeFreePool (TempFilePathList);

            FilePathList [NumberOfFilePath] = FileDevicePath (RamDiskHandle, EFI_REMOVABLE_MEDIA_FILE_NAME);
            AppendFilePath = TRUE;

            DEBUG_LO (
              DPRINTF_DEVICE_PATH (" RamDisk DevicePath = ", FilePathList [NumberOfFilePath]);
            );

            RemainingDevicePath = FilePathList [NumberOfFilePath];
            ConnectedHandle = NULL;
            Status = gBS->LocateDevicePath (
                            &gEfiSimpleFileSystemProtocolGuid,
                            &RemainingDevicePath,
                            &ConnectedHandle);

            NumberOfFilePath ++;

            //
            // Advanced to the next Boot file device path from the FilePathList.
            //

            break;
          }
        }
      }

      if (AppendFilePath == FALSE || mBootableFilePath [i] == NULL) {
        break;
      }

    } // for(i = 0; !IsImageLoaded; i++)

    if (IsImageLoaded) {
      break;
    }
  } // for (j = 0; ...)

  DPRINTF_LO ("\n LoadImage returned %r.\n", Status);

  //
  // Clean up allocated resources.
  //

  if ((RamDiskHandle != NULL) && (IsImageLoaded == FALSE)) {
    DestroyRamDisk (DevicePathFromHandle (RamDiskHandle));
    RamDiskHandle = NULL;
  }

  for (j = 0; j < NumberOfFilePath; j++) {
    SafeFreePool (FilePathList [j]);
  }
  SafeFreePool (FilePathList);

  if (EFI_ERROR (Status)) {
    SafeFreePool (BootDevicePath);
    return Status;
  }

  PERF_END (0, "LoadImage", "UefiBoot", 0);

  DEBUG_LO (
    DPRINTF_DEVICE_PATH (" Boot Target - ", BootDevicePath);
  );

  //
  // Report Status Code.
  //

  REPORT_STATUS_CODE (EFI_PROGRESS_CODE, EFI_SOFTWARE_EFI_OS_LOADER);
  PRINT_REPORT_STATUS("(EFI_PROGRESS_CODE, EFI_SOFTWARE_EFI_OS_LOADER)\n");

  //
  // Fix up the Image Information protocol to pass in any option data.
  //

  Status = gBS->HandleProtocol (
                  FileImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **) &ImageInfo);

  if (OptionalDataLength != 0 && !EFI_ERROR (Status)) {
    ImageInfo->LoadOptionsSize = OptionalDataLength;
    ImageInfo->LoadOptions = OptionalData;
  }

 #if (OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)
  if (!EFI_ERROR (Status) && IsPureUefiOs (ImageInfo->ImageBase)) {

    Status = SetVariable (
               L"LoadCsmNextBoot",
               &gSctBdsServicesProtocolGuid,
               EFI_VARIABLE_NON_VOLATILE |
               EFI_VARIABLE_BOOTSERVICE_ACCESS |
               EFI_VARIABLE_RUNTIME_ACCESS,
               0,
               NULL);
  }
 #endif //(OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)

  //
  // Optionally clear screen before executing the UEFI boot option. It appears
  // that some loaders, like UEFI Shell and Win7 DVD loader, do not clear the
  // screen and output on top of the existing content, e.g. splash image.
  // If the preference is to optimize boot time over appearance then the
  // option to clear screen at this point can be disabled.
  //

  if (SeamLessBootFlag() == 0) {
 #if OPTION_SYSTEM_BOOT_MANAGER_UEFI_BOOT_CLEAR_SCREEN
    ClearScreenBeforeBoot = FALSE;
    Status = ConfigureConOutBeforeBoot (BootDevicePath, &ClearScreenBeforeBoot);

    ClearScreenBeforeBoot = EFI_ERROR (Status) ? !QuickBootEnabled () : ClearScreenBeforeBoot;

    if (ClearScreenBeforeBoot) {
      gST->ConOut->ClearScreen (gST->ConOut);
 #if OPTION_SYSTEM_SCT_ACPI_BGRT
      SetBootLogoInvalid ();
 #endif // OPTION_SYSTEM_SCT_ACPI_BGRT
    }
 #endif // OPTION_SYSTEM_BOOT_MANAGER_UEFI_BOOT_CLEAR_SCREEN
  }

  //
  // Take the final timestamp for UEFI boot right before jumping to the UEFI
  // image.
  //

  //PERF_START (0, "UefiBoot:StartImage", "BootManager", 0);
  //PERF_END (0, "UefiBoot:StartImage", "BootManager", 0);

 #if (OPTION_SYSTEM_ACPI_TIMER_TO_POSTCODE && OPTION_DEBUG_POSTCODE)

  //
  // Send timestamp in milliseconds to bottom 2-bytes of postcode display.
  //

  Status = SendAcpiTimerToPostcode (0);
  if (EFI_ERROR (Status)) {
    DPRINTF_LO ("  Failed to send ACPI timer to POSTCODE port. Status = %r.\n", Status);
  }
 #endif //(OPTION_SYSTEM_ACPI_TIMER_TO_POSTCODE && OPTION_DEBUG_POSTCODE)

  Tpl = SetTpl (TPL_APPLICATION);
  {
    SCT_BDS_MILESTONE_TIMEOUT_DATA MilestoneTimeout;
    //
    // Process the time out milestone.  And set the timeout
    // value default to 5 minutes based on the spec.
    //
    MilestoneTimeout.Timeout = CONFIG_SYSTEM_BOOT_MANAGER_WATCHDOG_TIMEOUT;
    SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_TIMEOUT, MsTaskTimeout, &MilestoneTimeout, sizeof (MilestoneTimeout));
  }

  //
  // Start the image.
  //
  SetVideoToProperRes (&StoMode, &GopMode, 0, 0);

  //
  // Report Status Code.
  //
  REPORT_STATUS_CODE (EFI_PROGRESS_CODE, PcdGet32 (PcdProgressCodeOsLoaderStart));
  PRINT_REPORT_STATUS("(EFI_PROGRESS_CODE, PcdProgressCodeOsLoaderStart)\n");

  DPRINTF ("\n StartImage for UEFI Boot ...\n\n\n");
  RetStatus = gBS->StartImage (
                     FileImageHandle,
                     &ExitDataSize,
                     &ExitData);
  DPRINTF ("\n StartImage returned [%r].\n", RetStatus);
  //REPORT_STATUS_CODE (EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_BS_PC_EXIT));
  REPORT_STATUS_CODE_EX (
    EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_BS_PC_EXIT),
    OptionNumber,
    NULL,
    &gEfiDevicePathProtocolGuid,
    DevicePath,
    GetDevicePathSize (DevicePath));
  PRINT_REPORT_STATUS("(EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_BS_PC_EXIT))\n");
  RestoreVideoMode (StoMode, GopMode);

  gBS->SetWatchdogTimer (0, 0, 0, NULL);

  SetTpl (Tpl);

  //
  // The image returned, cleanup.
  //

  DPRINTF_LO ("  StartImage returned %r\n", RetStatus);

  if (EFI_ERROR (RetStatus)) {
    SignalBootFail (SCT_BDS_EFI_BOOT_FAIL);
  }

  if ( (FoundHttpDp) && (NicHandler != NULL) ) {
    //
    // For http boot, disconnect the HttpBoot binding driver in case client launch the http boot
    // second time.  So the contents within the HttpBoot binding driver could be reset and start over.
    //
    Status = BmReconnectImagesBinding (NicHandler);
    DPRINTF_LO (">>>>> BmReconnectImagesBinding return = [%r] !! (%d) \n", Status, __LINE__);
  }

  //
  // If boot failed, clear the screen.
  //

  gST->ConOut->OutputString (gST->ConOut, L"  ");
  gST->ConOut->ClearScreen (gST->ConOut);
  SetEfiGlobalVariable (
    EFI_BOOT_CURRENT_VARIABLE_NAME,
    EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS,
    0,
    NULL);

 #if OPTION_SYSTEM_SCT_ACPI_BGRT
  SetBootLogoInvalid ();
 #endif //OPTION_SYSTEM_SCT_ACPI_BGRT

  SafeFreePool (BootDevicePath);
  return RetStatus;
} // UefiBoot

//
// FUNCTION NAME.
//      LaunchDevicePath - Launch an expanded device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function does all the work related to launching a device path once
//      it has been expanded.
//
//      The attempt to LegacyBoot may occur before or after the attempt to UEFI
//      boot, per a configuration option.
//
//      Note that returning SCT_STATUS_SUCCESS from this function will cause
//      the Boot Manager to launch the Boot Menu application. This will abort
//      the processing of the BootOrder variable, if this function was called
//      in that context.
//
// ENTRY PARAMETERS.
//      DevicePath      - the Device Path for the Device Type to boot.
//      OptionNumber    - the Option Number for this Device Path.
//      OptionalData    - the Data to pass to the boot.
//      OptionalDataLength - the number of byte of data.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
LaunchDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINT16 OptionNumber,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  )
{
  EFI_STATUS Status;
  SCT_BDS_LAUNCH_DEVICE_PATH_DATA MilestoneData;
  UINT32 MilestoneDataSize = sizeof (MilestoneData);

  MilestoneData.DevicePath = DevicePath;
  MilestoneData.OptionNumber = OptionNumber;
  MilestoneData.OptionalData = OptionalData;
  MilestoneData.OptionalDataLength = OptionalDataLength;
  MilestoneData.ReturnStatus = EFI_SUCCESS;

  Status = SCT_MILESTONE_TASK (
            BDS_MILESTONE_TASK_LAUNCH_DEVICE_PATH,
            MsTaskLaunchDevicePath,
            &MilestoneData,
            MilestoneDataSize);
  DPRINTF_LO ("BDS_MILESTONE_TASK_LAUNCH_DEVICE_PATH Ret_Status = [%r]\n", MilestoneData.ReturnStatus);
  Status = MilestoneData.ReturnStatus;

  return Status;
} // LaunchDevicePath

//
// FUNCTION NAME.
//      LaunchDevicePaths - Launch each device path in an array of device paths.
//
// FUNCTIONAL DESCRIPTION.
//      This function walks through the input array of device paths. For each
//      device path this function will attempt to expand the device path. If
//      device path expands then this function will call itself with the new
//      array of device paths, otherwise this function will call the
//      LaunchDevicePath function, which does the work for launching an
//      expanded device path.
//
// ENTRY PARAMETERS.
//      FilePathList
//      NumberOfFilePaths
//      OptionNumber
//      OptionalData
//      OptionalDataList
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
LaunchDevicePaths (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePathList,
  IN UINTN NumberOfFilePaths,
  IN UINT16 OptionNumber,
  IN PUINT8 OptionalData,
  IN UINT32 OptionalDataLength
  )
{
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *p;
  EFI_DEVICE_PATH_PROTOCOL *ExpandedDevicePaths;
  UINTN NumberOfDevicePaths;
  UINTN i;

  DPRINTF_LO ("Entry:\n");

  Status = SCT_STATUS_NOT_FOUND;

  if ((FilePathList == NULL) || (NumberOfFilePaths == 0)) {
    DPRINTF_LO (" No paths to launch!\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }
  DPRINTF_LO (" %d paths @ 0x%x.\n", NumberOfFilePaths, FilePathList);

  p = FilePathList;
  for (i = 0; i < NumberOfFilePaths; i++, p = NextDevicePath (p)) {
    DEBUG_LO ({
      CHAR8 strPtr[80];
      AsciiSPrint (strPtr, sizeof(strPtr), "LaunchDevicePaths [%d] = ", i);
      DPRINTF_DEVICE_PATH (strPtr, p);
    });

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
    if (IsIgnoreBootDevicePath (p)) {
      continue;
    }
#endif

    Status = ExpandDevicePath (
               p,
               &ExpandedDevicePaths,
               &NumberOfDevicePaths);
    if (EFI_ERROR (Status)) {
      PERF_START (0, UEFI_BOOT_TOK, "LaunchDevicePath", 0);
      Status = LaunchDevicePath (
                 p,
                 OptionNumber,
                 OptionalData,
                 OptionalDataLength);
      PERF_END (0, UEFI_BOOT_TOK, "LaunchDevicePath", 0);
      DPRINTF_LO ("LaunchDevicePath ret HOOK_STATUS = [%d].\n", Status);

      //
      // If any launch returns success we need to stop processing options.
      // The UEFI spec says we need to launch the Boot Menu in this case.
      //

      if (!EFI_ERROR (Status)) {
        return Status;
      }
      continue;
    }

    //
    // The current device path p in the list FilePathList expanded. Walk into
    // the expanded paths and launch them.
    //

    Status = LaunchDevicePaths (
               ExpandedDevicePaths,
               NumberOfDevicePaths,
               OptionNumber,
               OptionalData,
               OptionalDataLength);
    DPRINTF_LO ("LaunchDevicePaths.LaunchDevicePaths returned %r.\n", Status);

    //
    // If any of these device paths returned success we must pass that up
    // immediately so that we can rewind to the Boot Menu.
    //

    SafeFreePool (ExpandedDevicePaths);
    if (!EFI_ERROR (Status)) {
      return Status;
    }
  }

  return Status;
} // LaunchDevicePaths


//
// FUNCTION NAME.
//      SignalBootFail - Signal a boot failed event.
//
// FUNCTIONAL DESCRIPTION.
//      describe Credential Providers which will be discovered and managed
//      by the User Manager.
//      This function signals a Boot Failed event by installing a protocol.
//      This event helps platform/silicon drivers to handle cleanup or
//      configuration reset needed for next boot.
//
// ENTRY PARAMETERS.
//      Type            - The boot failed type.
//                        SCT_BDS_LEGACY_BOOT_FAIL
//                        SCT_BDS_EFI_BOOT_FAIL
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
SignalBootFail (IN UINT8 Type)
{
  EFI_STATUS Status;
  EFI_HANDLE BootFailedHandle;
  EFI_EVENT ReadyToBootEvent;

  mBootFailedProtocol.BootType = Type;

  DPRINTF_LO ("SignalBootFail\n");

  Status = EfiCreateEventReadyToBootEx (
             TPL_CALLBACK,
             InternalBmEmptyCallbackFunction,
             NULL,
             &ReadyToBootEvent);

  if (!EFI_ERROR (Status)) {
    DPRINTF_LO ("  SignalEvent: ReadyToBootEvent\n");
    gBS->SignalEvent (ReadyToBootEvent);
    gBS->CloseEvent (ReadyToBootEvent);
  }

  BootFailedHandle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &BootFailedHandle,
                  &gSctBdsBootFailedProtocolGuid,
                  &mBootFailedProtocol,
                  NULL);

  return Status;
} // SignalBootFail

//
// FUNCTION NAME.
//      SendAcpiTimerToPostcode - Send ACPI Timer to POSTCODE Port.
//
// FUNCTIONAL DESCRIPTION.
//      Send the ACPI timer the lower two bytes of the POSTCODE port. Convert
//      the ACPI timer first to ms, and then to BCD.
//
// ENTRY PARAMETERS.
//      ShiftValue      - number of bits to left-shift the result.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

#if (OPTION_SYSTEM_ACPI_TIMER_TO_POSTCODE && OPTION_DEBUG_POSTCODE)
SCT_STATUS
SendAcpiTimerToPostcode (IN UINT8 ShiftValue)
{
  UINT64 PmTimer;
  UINT32 TimerInMs;
  UINTN i;
  UINT32 TimerInBcd = 0;

  //
  // Only support shifting result to upper 2 bytes or no shift at all.
  //

  if ((ShiftValue != 0) && (ShiftValue != 16)) {
    DPRINTF_LO ("  Incorrect output shift value.\n");
    return SCT_STATUS_PARAMETER_OUT_OF_RANGE;
  }

  //
  // Display Boot Menu handoff timestamp in the upper 2 bytes of the
  // POSTCODE port. Start by getting the ACPI timer value.
  //

  PmTimer = _inpd (CONFIG_ACPI_IO_BASE + 8); // I/O address, ACPI timer.
  if (!PmTimer) {
    DPRINTF_LO ("  Failed to get ACPI timer.\n");
    return SCT_STATUS_INVALID_DATA;
  }

  //
  // Convert the current timestamp to ms.
  //

  TimerInMs = (UINT32)((PmTimer * 0x4784) / 0x10000) / 1000;

  //
  // Convert timestamp to BCD.
  //

  for (i = 0; i < (sizeof (UINTN) * 2); i++) {
    if (TimerInMs) {
      TimerInBcd |= TimerInMs % 10;
      TimerInMs /= 10;
    }

    TimerInBcd = (((TimerInBcd) >> (4)) | (((TimerInBcd) << (32 - (4))) & 0xf0000000));
  }

  //
  // Send BCD timestamp to designated position of the POSTCODE port. Only
  // support either 16-bit shift into upper two bytes, or no shift at all.
  //

  if (ShiftValue) {
    _outpd (CONFIG_DEBUG_POSTCODE_IO_PORT, (TimerInBcd << ShiftValue));
  } else {
    _outpw (CONFIG_DEBUG_POSTCODE_IO_PORT, (UINT16)TimerInBcd);
  }

  return SCT_STATUS_SUCCESS;
} // SendAcpiTimerToPostcode
#endif


#if OPTION_SUPPORT_SECURE_BOOT

//
// FUNCTION NAME.
//      IsSecureBootEnabled - Check if Secure Boot is enabled.
//
// FUNCTIONAL DESCRIPTION.
//      This function will query the "SecureBoot" variable and check if the system
//      enables the secure boot.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - TRUE, if enabled. Otherwise, disabled.
//

BOOLEAN
IsSecureBootEnabled (VOID)
{
  UINT8 *SecureBoot;

  DPRINTF_LO ("\n");

  SecureBoot = NULL;
  SecureBoot = SctLibGetVariableAndSize (
                 EFI_SECURE_BOOT_MODE_NAME,
                 &gEfiGlobalVariableGuid,
                 NULL);
  if (SecureBoot != NULL && *SecureBoot == (UINT8)TRUE) {
    FreePool (SecureBoot);
    DPRINTF_LO (" Secure Boot is enabled\n");
    return TRUE;
  }

  DPRINTF_LO (" Secure Boot is disabled\n");
  return FALSE;

} // IsSecureBootEnabled
#endif

//
// FUNCTION NAME.
//      CreateLoadOptionNumberVariable - Create variables to store option number.
//
// FUNCTIONAL DESCRIPTION.
//      This function will create a variable to store the number of specific LoadOption.
//
// ENTRY PARAMETERS.
//      BmConfig        - a pointer points to BOOT_MANAGER_CONFIGURATION.
//      OptionNumber    - Boot Option number.
//      Guid            - namespace of the created variable.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
CreateLoadOptionNumberVariable (
  IN PBOOT_MANAGER_CONFIGURATION BmConfig,
  IN UINT16 OptionNumber,
  IN EFI_GUID *Guid)
{
  UINT8 Factor;
  UINT32 BootId;
  EFI_STATUS Status;
  UINT32 Attribute;
  CHAR16 VariableName [256];
  UINTN VariableSize;
  PUINT16 VariableValue;

  DPRINTF_LO ("Entry\n");
  if (BmConfig == NULL || Guid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = EFI_UNSUPPORTED;
  SetMem (VariableName, sizeof (VariableName), 0);

  if ((BmConfig->Flags & SCT_BM_BOOT_MENU) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_BOOT_MENU);

  } else if ((BmConfig->Flags & SCT_BM_RECOVERY) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_RECOVERY);

  } else if ((BmConfig->Flags & SCT_BM_ALL_HDD) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_BOOT_ALL_HDD);

  } else if ((BmConfig->Flags & SCT_BM_ALL_CDROM) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_BOOT_ALL_CDROM);

  } else if ((BmConfig->Flags & SCT_BM_BIOS_SETUP) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_BIOS_SETUP);

  } else if ((BmConfig->Flags & SCT_BM_ALL_PCI_LAN) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_BOOT_ALL_PCI_LAN);

  } else if ((BmConfig->Flags & SCT_BM_BOOT_NEXT) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_DUMMY_BOOT_NEXT);

  } else if ((BmConfig->Flags & SCT_BM_ALL_HTTP) != 0) {

    StrCpyS (VariableName, 256, SCT_BOOT_OPTION_BOOT_ALL_HTTP);

  } else if ((BmConfig->Flags & SCT_BM_IDENTIFICATION_MASK) != 0) {

    //
    // Check to see if the BootOption number identification flag is set.
    // If the flag is setted, create a variable to store the BootOption
    // number.
    //

    Factor = 0;
    DPRINTF_LO ("   BootOption number identification flag is set.\n");
    BootId = (BmConfig->Flags & SCT_BM_IDENTIFICATION_MASK);
    BootId = BootId >> SCT_BM_IDENTIFICATION_START_BIT;
    while (TRUE) {
      BootId = BootId / 2;
      if (BootId == 0) {
        break;
      }
      Factor++;
    }

    UnicodeSPrint (
      VariableName,
      sizeof (VariableName),
      CONFIG_SYSTEM_BOOT_MANAGER_IDENTIFICATION_VARIABLE_NAME_FORMAT,
      Factor);

    DPRINTF_LO ("   Create %s variable for BootOption 0x%x.\n",
      VariableName, OptionNumber);
  } else {

    return EFI_SUCCESS;
  }

  //
  // Check if the variable is already existent.
  //

  DPRINTF_LO ("  Create LoadOption %s Number variable.\n", VariableName);
  VariableValue = NULL;
  VariableSize = 0;
  Status = SctLibGetVariable (
             VariableName,
             Guid,
             &Attribute,
             &VariableSize,
             (VOID **) &VariableValue);
  if (!EFI_ERROR (Status) && OptionNumber == *VariableValue) {
    DPRINTF_LO ("  Variable %s is already existent\n", VariableName);
    SafeFreePool (VariableValue);
    return EFI_SUCCESS;
  }

  if (Status == EFI_NOT_FOUND) {
    Attribute = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;
  }

  Status = gRT->SetVariable (
                  VariableName,
                  Guid,
                  Attribute,
                  sizeof (UINT16),
                  &OptionNumber);

  SafeFreePool (VariableValue);
  return Status;

} // CreateLoadOptionNumberVariable

//
// FUNCTION NAME.
//      CheckAppOptionAttribute - Check the essential attributes of an APP loadoption.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the built-in APP loadOption's attributes are valid.
//      An APP loadOption should have LOAD_OPTION_CATEGORY_APP flag.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
CheckAppOptionAttribute (VOID)
{
  UINT8 Index;
  EFI_STATUS Status;
  UINT16 OptionNumber;
  PLOAD_OPTION_OBJECT Option;
  PBOOT_MANAGER_CONFIGURATION p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  Index = 0;
  while (TRUE) {
    p = &mBootManagerConfigurationTable [Index];
    if (p->Flags & SCT_BM_FLAGS_END) {
      break;
    }
    if ((p->OptionAttributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_APP) {

      //
      // Validate the attribute of current APP LoadOption.
      //

      DevicePath = NULL;
      DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
      if (DevicePath != NULL) {

        //
        // Get corresponding Option number.
        //

        Status = GetLoadOptionNumber (
                   p->Description,
                   DevicePath,
                   p->OptionType,
                   &OptionNumber);
        SafeFreePool (DevicePath);
        if (!EFI_ERROR (Status)) {

          //
          // Get target Option object.
          //

          Option = NULL;
          Status = GetOption (OptionNumber, p->OptionType, &Option);
          if (!EFI_ERROR (Status)) {
            DPRINTF_LO ("  p->OptionAttributes = 0x%x\n", p->OptionAttributes);
            DPRINTF_LO ("  Option->OptionAttributes = 0x%x\n", Option->Attributes);
            if ((Option->Attributes & LOAD_OPTION_CATEGORY_APP) == 0) {

              DPRINTF_LO ("  Update attribute for app loadoption\n");

              //
              // Update LoadOption's attributes.
              //

              CreateOption (
                OptionNumber,
                p->OptionType,
                p->OptionAttributes,
                Option->Description,
                Option->FilePathList,
                Option->OptionalDataLength,
                Option->OptionalData,
                NULL);
            }
          }
        }
      }
    }
    Index++;
  }

  return EFI_SUCCESS;
} // CheckAppOptionAttribute

//
// FUNCTION NAME.
//      CheckBootManagerVariable - Check those variables that are essential for BootManager.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if all of the essential variables are existed in the
//      current system.
//
//      1. If any of the essential variable is not found, return EFI_LOAD_ERROR.
//      2. If any of the essential variable is found but not in BootOrder, add it back to BootOrder.
//      3. If there is an associated HOTKEY, try to update the option number.
//      4. If there is any associated variable, try to update the option number.
//
// ENTRY PARAMETERS.
//      Force           - Force to check in any case.
//      Guid            - Namespace GUID for BootManager essential variables.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
CheckBootManagerVariable (
  IN BOOLEAN Force,
  IN EFI_GUID *Guid
  )
{
  UINTN j;
  UINTN k;
  UINTN m;
  UINT8 Index;
  SCT_STATUS Status;
  UINT32 Attributes;
  PUINT16 BootOrder;
  UINTN BootOrderSize;
  UINT16 OptionNumber;
  BOOLEAN IsAbsentInBootOrder;       SUPPRESS_WARNING_IF_UNUSED (IsAbsentInBootOrder);
  PLOAD_OPTION_OBJECT Option;
  PBOOT_MANAGER_CONFIGURATION p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  UINT16 TempBootOrder [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];
  UINT16 ProtectedBootOptions [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  UINTN i;
  UINT32 *CrcTable;
  UINT32 *OrgCrcTable;
  UINTN CrcTableSize;
  UINT16 PreDefinedLoadOptions [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];
#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  DPRINTF_LO ("Entry\n");

  BootOrder = NULL;
  BootOrderSize = 0;
  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             &Attributes,
             &BootOrderSize,
             (VOID **) &BootOrder);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR (" Error[%r] to Get [%s]\n", Status, EFI_BOOT_ORDER_VARIABLE_NAME);
    return EFI_LOAD_ERROR;
  }

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  i = 0;
  CrcTableSize = 0;
  CrcTable = NULL;
  OrgCrcTable = NULL;
  Status = SctLibGetVariable (
             L"LoadOptionCrcTable",
             &gSctBdsServicesProtocolGuid,
             NULL,
             &CrcTableSize,
             (VOID **)&CrcTable);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR (" Error[%r] to Get [LoadOptionCrcTable]\n", Status);
    return EFI_LOAD_ERROR;
  }
  Status = SctLibGetVariable (
             L"OrgLoadOptionCrcTable",
             &gSctBdsServicesProtocolGuid,
             NULL,
             &CrcTableSize,
             (VOID **)&OrgCrcTable);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR (" Error[%r] to Get [OrgLoadOptionCrcTable]\n", Status);
    return EFI_LOAD_ERROR;
  }
#endif //OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  if (Force == FALSE &&
    BootOrder != NULL &&
    mIsBootOrderChanged == FALSE) {
    CheckAppOptionAttribute ();
    DPRINTF_LO (" Skip check.\n");
    return EFI_SUCCESS;
  }

  j = 0;
  k = 0;
  Index = 0;
  IsAbsentInBootOrder = FALSE;
  while (TRUE) {
    p = &mBootManagerConfigurationTable [Index];

    if (p->Flags & SCT_BM_FLAGS_END) {
      break;
    }

    DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (DevicePath == NULL) {
      Index++;
      continue;
    }

    DPRINTF_LO (" p->Description = %s\n", p->Description);

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

    //
    // If this is pre-defined LoadOption, try to retrieve it from LoadOptionCrc table.
    //

    if ((p->Flags & SCT_BM_PRE_DEFINED_SLOT) != 0) {

      DPRINTF_LO (" CrcTable    [%d] = 0x%x\n", i, CrcTable [i]);
      DPRINTF_LO (" OrgCrcTable [%d] = 0x%x\n", i, OrgCrcTable [i]);
      Status = GetBootOptionNumberByCrc (CrcTable [i], &OptionNumber);
      if (EFI_ERROR (Status)) {
        DPRINTF_LO ("  Find from OrgLoadOptionCrc table\n");
        Status = GetBootOptionNumberByCrc (OrgCrcTable [i], &OptionNumber);
        if (!EFI_ERROR (Status)) {
          UpdateLoadOptionCrcTable (CrcTable [i], OrgCrcTable [i]);
        }
      }
      if (!EFI_ERROR (Status)) {
        PreDefinedLoadOptions [i] = OptionNumber;
      }
      i++;
    } else {
      Status = GetLoadOptionNumber (
                p->Description,
                DevicePath,
                p->OptionType,
                &OptionNumber);
      SafeFreePool (DevicePath);
    }

#else  // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

    Status = GetLoadOptionNumber (
               p->Description,
               DevicePath,
               p->OptionType,
               &OptionNumber);
    SafeFreePool (DevicePath);
#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

    if (EFI_ERROR (Status)) {

      //
      // This is a fatal error.
      //

      return EFI_LOAD_ERROR;
    }

    DPRINTF_LO ("  Option Number = 0x%x\n\n", OptionNumber);

    Status = GetOption (OptionNumber, p->OptionType, &Option);
    if (!EFI_ERROR (Status)) {
      Attributes = Option->Attributes;
      if ((p->OptionAttributes & LOAD_OPTION_CATEGORY_APP) != 0 &&
        (Option->Attributes & LOAD_OPTION_CATEGORY_APP) == 0) {

        DPRINTF_LO ("  Update LoadOption to be LOAD_OPTION_CATEGORY_APP\n");
        Attributes |= LOAD_OPTION_CATEGORY_APP;
      }

      if ((p->OptionAttributes & LOAD_OPTION_HIDDEN) != 0 &&
        (Option->Attributes & LOAD_OPTION_HIDDEN) == 0) {

        DPRINTF_LO ("  Update LoadOption to be LOAD_OPTION_HIDDEN\n");
        Attributes |= LOAD_OPTION_HIDDEN;
      }

      //
      // Update LoadOption's attributes.
      //

      if (Option->Attributes != Attributes) {
        DPRINTF_LO ("  Original CRC = 0x%x\n", Option->RawCrc);
        CreateOption (
          OptionNumber,
          p->OptionType,
          Attributes,
          Option->Description,
          Option->FilePathList,
          Option->OptionalDataLength,
          Option->OptionalData,
          &Option);
        DPRINTF_LO ("  Updated CRC = 0x%x\n", Option->RawCrc);
      }
    }

    CreateLoadOptionNumberVariable (p, OptionNumber, Guid);
    UpdateKeyOptionDataByCrc (Option->RawCrc, OptionNumber);

    if ((p->Flags & SCT_BM_PROTECTED) != 0) {
      ProtectedBootOptions [k++] = OptionNumber;
    }

    if ((p->OptionType == SCT_BM_LO_BOOT) &&
        ((p->OptionAttributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_BOOT) &&
        (j < CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER) &&
        ((p->OptionAttributes & LOAD_OPTION_HIDDEN) == 0)) {

      TempBootOrder [j++] = OptionNumber;

      //
      // Check if this BootOption is in BootOrder.
      //

      for (m = 0; m < BootOrderSize / sizeof (UINT16); m++) {
        if (OptionNumber == BootOrder [m]) {
          break;
        }
      }
      if (m == BootOrderSize / sizeof (UINT16)) {

        //
        // Not found in BootOrder, add it to BootOrder in any case.
        //

        IsAbsentInBootOrder = TRUE;
        AddBootOptionToBootOrder (OptionNumber);
        Option->InBootOrder = TRUE;
      }
    }

    Index++;
  }

  SafeFreePool (BootOrder);

  //
  // Update BootOrderDefault variable.
  //

  gRT->SetVariable (
         L"BootOrderDefault",
         Guid,
         EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS,
         j * sizeof (UINT16),
         TempBootOrder);

  //
  // Update ProtectedBootOptions variable.
  //

  gRT->SetVariable (
         L"ProtectedBootOptions",
         Guid,
         EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS,
         k * sizeof (UINT16),
         ProtectedBootOptions);

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  //
  // Update PreDefinedBootOptions variable.
  //

  gRT->SetVariable (
         L"PreDefinedBootOptions",
         Guid,
         EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS,
         i * sizeof (UINT16),
         PreDefinedLoadOptions);

  SafeFreePool (CrcTable);
  SafeFreePool (OrgCrcTable);
#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  return EFI_SUCCESS;
} // CheckBootManagerVariable

//
// FUNCTION NAME.
//      IsLoadOptionDuplicated - Check if the Load Option is duplicated.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the LoadOption is a duplicated one in DB.
//
// ENTRY PARAMETERS.
//      Option          - a pointer points to LOAD_OPTION_OBJECT.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN value.
//

BOOLEAN
EFIAPI
IsLoadOptionDuplicated (
  IN LOAD_OPTION_OBJECT *Option,
  OUT UINT16 *OptionNumber OPTIONAL
  )
{
  PLOAD_OPTION_OBJECT p;
  DPRINTF_LO ("Entry:\n");

  if (Option == NULL) {
    return FALSE;
  }

  p = mBootOptionListHead;
  while (TRUE) {
    if (p == NULL) {
      return FALSE;
    }
    if (p->RawCrc == Option->RawCrc ||
     (StrCmp (p->Description, Option->Description) == 0 &&
     CompareDevicePath (p->FilePathList, Option->FilePathList) &&
     p->Attributes == Option->Attributes)) {

      DPRINTF_LO ("  Find duplicated one in DB\n");
      if (OptionNumber != NULL) {
        *OptionNumber = p->OptionNumber;
      }
      return TRUE;
    }
    p = p->Next;
  }

  return FALSE;
} // IsLoadOptionDuplicated

//
// FUNCTION NAME.
//      MsTaskLaunchBootOption - Default task for the LaunchBootOption
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the LaunchBootOption
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskLaunchBootOption (
  IN VOID *MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  SCT_STATUS Status;
  PLOAD_OPTION_OBJECT LoadOption;
  UINT16 MillisecondsToStall;
  PUINT16 BootMenuOptionNumber;
  SCT_BDS_LAUNCH_BOOT_OPTION_DATA *MilestoneBootOptionData;
  UINT16 OptionNumber;
  UINT32 OptionCrc;
  EFI_DEVICE_PATH_PROTOCOL *FilePathList;
  UINTN NumberOfFilePaths;
  PUINT8 OptionalData;
  UINT32 OptionalDataLength;
  BOOLEAN IsBootMenu;

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  PBOOT_MANAGER_CONFIGURATION p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  UINTN DevicePathSize;
#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  IsBootMenu = FALSE;
  MilestoneBootOptionData = (SCT_BDS_LAUNCH_BOOT_OPTION_DATA *)MilestoneData;
  OptionNumber = MilestoneBootOptionData->OptionNumber;
  OptionCrc = MilestoneBootOptionData->OptionCrc;

  DPRINTF_LO ("LaunchBootOption: Number = 0x%x, Crc = 0x%x\n", OptionNumber, OptionCrc);

  //
  // Search for the load option, if not found return SCT_STATUS_NOT_FOUND.
  //

  LoadOption = mBootOptionListHead;
  while (TRUE) {
    DEBUG_LO_L (2, {
      DISPLAY_OPTION_INFORMATION (LoadOption, L"  ");
    });
    if (LoadOption == NULL) {
      DPRINTF_LO ("  Couldn't find Option:0x%x.\n", OptionNumber);
      MilestoneBootOptionData->ReturnStatus = SCT_STATUS_NOT_FOUND;
      return SCT_STATUS_NOT_FOUND;
    }
    if (LoadOption->OptionNumber == OptionNumber) {
      break;
    }
    LoadOption = LoadOption->Next;
  }

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  if (ValidateLoadOption (LoadOption, FALSE, FALSE)) {

    DPRINTF_LO ("  BootOption is valid\n");

    //
    // Re-retrieve the BootOption for updated one.
    //

    Status = GetBootOption (OptionNumber, &LoadOption);

    if (EFI_ERROR (Status)) {
      MilestoneBootOptionData->ReturnStatus = Status;
      return Status;
    }

    //
    // Since the BootOption has been updated by our code, ignore CRC check.
    //

    OptionCrc = LoadOption->RawCrc;

  } else {

    DPRINTF_LO ("  BootOption is invalid.\n");
    Status = RecoverBootOption (OptionNumber);
    DPRINTF_LO ("  RecoverBootOption returned %r.\n", Status);

    if (!EFI_ERROR (Status)) {
      Status = GetBootOption (OptionNumber, &LoadOption);
      OptionCrc = LoadOption->RawCrc;
    }
  }

#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  FilePathList = LoadOption->FilePathList;
  NumberOfFilePaths = LoadOption->NumberOfFilePaths;
  OptionalDataLength = LoadOption->OptionalDataLength;
  OptionalData = LoadOption->OptionalData;

  //
  // Check to see if the CRC was as expected.
  //

  if (LoadOption->RawCrc != OptionCrc) {
    DPRINTF_LO ("  CRC Mismatch 0x%x is not 0x%x.\n", LoadOption->RawCrc, OptionCrc);

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

    //
    // Pre-defined LoadOption might be changed so we need a chance to restore
    // the original data.
    //

    p = GetPreDefinedLoadOptionByCrcTable (LoadOption->RawCrc);
    if (p == NULL) {
      MilestoneBootOptionData->ReturnStatus = SCT_STATUS_CRC_ERROR;
      return SCT_STATUS_CRC_ERROR;
    }
    FilePathList = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (FilePathList == NULL) {
      MilestoneBootOptionData->ReturnStatus = EFI_NOT_FOUND;
      return EFI_NOT_FOUND;
    }

    DevicePath = FilePathList;
    NumberOfFilePaths = 1;
    if (IsDevicePathMultiInstance (DevicePath)) {
      while (TRUE) {
        GetNextDevicePathInstance (&DevicePath, &DevicePathSize);
        if (DevicePath == NULL) {
          break;
        }
        NumberOfFilePaths++;
      }
    }

    OptionalDataLength = 0;
    OptionalData = NULL;
    if (p->OptionData != NULL) {
      OptionalDataLength = (UINT32)StrSize (p->OptionData);
      OptionalData = (PUINT8)(p->OptionData);
    }

#else  // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
    MilestoneBootOptionData->ReturnStatus = SCT_STATUS_CRC_ERROR;
    return SCT_STATUS_CRC_ERROR;
#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  }

  //
  // The logic for processing an application is much simpler. Determine if this
  // option is an application, and if it is use the LaunchApplication function.
  //

  //
  // If the device path is MEDIA_FV_FILEPATH_DP type, we also consider it is an
  // application.
  //

  if (((LoadOption->Attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_APP)) {


    //
    // Unlock all HDDs before entering BootMenu.
    //

    BootMenuOptionNumber = NULL;
    BootMenuOptionNumber = SctLibGetVariableAndSize (
                             SCT_BOOT_OPTION_BOOT_MENU,
                             &gSctBdsServicesProtocolGuid,
                             NULL);

    if (BootMenuOptionNumber != NULL &&
      (*BootMenuOptionNumber == OptionNumber)) {
      IsBootMenu = TRUE;
    }
    SafeFreePool (BootMenuOptionNumber);

    //
    // Always stall specific time to let USB devices be ready.
    //

    GetUsbHcProperStallTime (&MillisecondsToStall);
    gBS->Stall (1000 * MillisecondsToStall);

    if (IsBootMenu) {
#if OPTION_SYSTEM_BOOT_MANAGER_UNLOCK_HDD_BEFORE_BOOTMENU
      DPRINTF_LO ("  Unlock HDDs before launching BootMenu. \n");
      UnlockAllHdd ();
#endif
#if OPTION_SYSTEM_SCT_ACPI_BGRT
      SetBootLogoInvalid ();
#endif
      Status = LaunchBootMenuApplication ();
    } else {
      Status = LaunchApplicationOption (
                 FilePathList,
                 OptionalData,
                 OptionalDataLength);
    }

  } else {
    Status = LaunchDevicePaths (
               FilePathList,
               NumberOfFilePaths,
               LoadOption->OptionNumber,
               OptionalData,
               OptionalDataLength);
  }

  MilestoneBootOptionData->ReturnStatus = Status;
  return Status;

} // MsTaskLaunchBootOption

//
// FUNCTION NAME.
//      MsTaskLaunchApplicationOption - Default task for the LaunchApplicationOption
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the LaunchApplicationOption
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskLaunchApplicationOption (
  IN VOID *MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_TPL Tpl;
  SCT_STATUS Status;

  EFI_HANDLE ConnectedHandle;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *ExpandedDevicePath;

  EFI_HANDLE FileImageHandle;
  UINTN ExitDataSize;
  PCHAR16 ExitData;
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  SCT_BDS_LAUNCH_APPLICATION_OPTION_DATA *MilestoneLaunchApData;
  EFI_DEVICE_PATH_PROTOCOL *FilePathList;
  PUINT8 OptionalData;
  UINT32 OptionalDataLength;

  MilestoneLaunchApData = (SCT_BDS_LAUNCH_APPLICATION_OPTION_DATA *)MilestoneData;
  FilePathList = MilestoneLaunchApData->FilePathList;
  OptionalData = MilestoneLaunchApData->OptionalData;
  OptionalDataLength = MilestoneLaunchApData->OptionalDataLength;

  //
  // First do device path translation or expansion.
  // Hdd Expansion. Usb Expansion. Phoenix Expansion.
  //

  ExpandedDevicePath = ExpandOneDevicePath (FilePathList);

  //
  // Connect the Device Path.
  //

  Status = ConnectDevicePathWithRemaining (
             ExpandedDevicePath,
             &ConnectedHandle,
             &RemainingDevicePath);
  DPRINTF_LO ("  ConnectDevicePathWithRemaining returned %r.\n", Status);

  //
  // Load the image.
  //

  DEBUG_LO (
    DPRINTF_DEVICE_PATH ("  LoadImage: ", ExpandedDevicePath);
  );
  Status = gBS->LoadImage (
                  TRUE,
                  mImageHandle,
                  ExpandedDevicePath,
                  NULL,
                  0,
                  &FileImageHandle);
  DPRINTF_LO ("  LoadImage returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    MilestoneLaunchApData->ReturnStatus = Status;
    return Status;
  }

  //
  // Fix up the Image Information protocol to pass in any option data.
  //

  if (OptionalDataLength != 0) {
    Status = gBS->HandleProtocol (
                    FileImageHandle,
                    &gEfiLoadedImageProtocolGuid,
                    (VOID **) &ImageInfo);
    if (!EFI_ERROR(Status)) {
      ImageInfo->LoadOptionsSize = OptionalDataLength;
      ImageInfo->LoadOptions = OptionalData;
    }
  }

#if OPTION_SYSTEM_SCT_ACPI_BGRT
  SetBootLogoInvalid ();
#endif

  //
  // Show Error Log Message Screen.
  //

  PERF_START (0, "ShowErrLogMsgScreen", "PrepareToBoot", 0);
  Status = EFI_SUCCESS;
  if (ErrorInfoScreen == NULL) {
    Status = gBS->LocateProtocol
               ((EFI_GUID *)&gSctErrorScreenTextProtocolGuid,
               NULL,
               (VOID **) &ErrorInfoScreen);
  } // if (ErrorInfoScreen == NULL) {
  if (!EFI_ERROR(Status)) {
      SctSignalProtocolEvent(&gSctErrLogEnterProtocolGuid, NULL);
      ErrorInfoScreen->ShowAllErrorMessage (ErrorInfoScreen);
      SctSignalProtocolEvent(&gSctErrLogExitProtocolGuid, NULL);
  }
  PERF_END (0, "ShowErrLogMsgScreen", "PrepareToBoot", 0);

#if OPTION_SUPPORT_SURE_BOOT
  Status = DisableSureBootTimerReset ();
#endif

  REPORT_STATUS_CODE_EX (
    EFI_PROGRESS_CODE,
    (EFI_SOFTWARE_EFI_APPLICATION | EFI_SW_BS_PC_START_IMAGE),
    0,
    NULL,
    &gEfiDevicePathProtocolGuid,
    ExpandedDevicePath,
    GetDevicePathSize(ExpandedDevicePath));
  PRINT_REPORT_STATUS("(EFI_SOFTWARE_EFI_APPLICATION | EFI_SW_BS_PC_START_IMAGE)\n");

  //
  // Force the TPL to TPL_APPLICATION.
  //

  Tpl = SetTpl (TPL_APPLICATION);

  //
  // Start the image.
  //

  Status = gBS->StartImage (
                  FileImageHandle,
                  &ExitDataSize,
                  &ExitData);

  //
  // The image returned, cleanup.
  //

  SetTpl (Tpl);
  MilestoneLaunchApData->ReturnStatus = Status;
  return Status;

} // MsTaskLaunchApplicationOption

//
// FUNCTION NAME.
//      MsTaskLaunchDevicePath - Default task for the LaunchDevicePath
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the LaunchDevicePath
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskLaunchDevicePath (
  IN VOID *MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  SCT_STATUS Status;
  BOOLEAN LegacyBootEnable;   SUPPRESS_WARNING_IF_UNUSED (LegacyBootEnable);
  BOOLEAN LegacyBeforeUefi;   SUPPRESS_WARNING_IF_UNUSED (LegacyBeforeUefi);
  BOOLEAN UefiBootOnly;       SUPPRESS_WARNING_IF_UNUSED (UefiBootOnly);
  EFI_HANDLE FwVolHandle;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *p;
  EFI_DEVICE_PATH_PROTOCOL *ConnectDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  EFI_HANDLE ConnectDeviceHandle;
#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  UINT32 ExtraDevicePathSize;
#endif
#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  SCT_BDS_LAUNCH_DEVICE_PATH_DATA *MilestoneLaunchDpData;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  UINT16 OptionNumber;
  PUINT8 OptionalData;
  UINT32 OptionalDataLength;

  MilestoneLaunchDpData = (SCT_BDS_LAUNCH_DEVICE_PATH_DATA *)MilestoneData;
  DevicePath = MilestoneLaunchDpData->DevicePath;
  OptionNumber = MilestoneLaunchDpData->OptionNumber;
  OptionalData = MilestoneLaunchDpData->OptionalData;
  OptionalDataLength = MilestoneLaunchDpData->OptionalDataLength;

  if (DevicePath == NULL) {
    MilestoneLaunchDpData->ReturnStatus = SCT_STATUS_INVALID_PARAMETER;
    return SCT_STATUS_INVALID_PARAMETER;
  }

  DPRINTF_LO ("Entry:\n");
  DEBUG_LO (
    DPRINTF_DEVICE_PATH ("DevicePath = ", DevicePath);
  );

  p = NULL;
  UefiBootOnly = FALSE;

  //
  // If this image is from firmware volume, never do legacy boot.
  //

  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiFirmwareVolume2ProtocolGuid,
                  &RemainingDevicePath,
                  &FwVolHandle);

  UefiBootOnly = !EFI_ERROR (Status);
  RemainingDevicePath = NULL;

  //
  // Because the Bop device path has been expanded in LaunchDevicePaths routine
  // so it should be ignored if the expanded device is identical to the original
  // but not for the one with SCT_EXEC_OPROM_BOOT_OPTION_PROTOCOL_GUID.
  //

  if (IsDeviceNodeBootOptionProtocol (DevicePath)) {
    p = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *)DevicePath;

    if (!CompareGuid (&(p->ProtocolGuid), &gExecOpromBootOptionProtocolGuid)) {

      DPRINTF_LO ("LaunchDevicePath - BOP Device Path is not allowable.\n");
      MilestoneLaunchDpData->ReturnStatus = SCT_STATUS_UNSUPPORTED;
      return SCT_STATUS_UNSUPPORTED;

    }
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT_INT18
    else {

      DPRINTF_LO ("LaunchDevicePath.LegacyInt18Boot.");
      Status = LegacyInt18Boot (
                DevicePath,
                OptionNumber,
                OptionalData,
                OptionalDataLength);
      MilestoneLaunchDpData->ReturnStatus = Status;
      return Status;
    }
#endif
  }

  gST->ConOut->SetAttribute (
                 gST->ConOut,
                 CONFIG_SYSTEM_BOOT_MANAGER_CONOUT_LAUNCH_ATTRIBUTE);

  //
  // Get Legacy Boot Configuration.
  //

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  LegacyBootEnable = LegacyBootEnabled (&LegacyBeforeUefi);
#else
  LegacyBootEnable = FALSE;
  LegacyBeforeUefi = FALSE;
#endif

  ConnectDevicePath = DevicePath;

  DPRINTF_LO ("LegacyBootEnable = [%a]\n", LegacyBootEnable ? "TRUE" : "FALSE");
  DPRINTF_LO ("LegacyBeforeUefi = [%a]\n", LegacyBeforeUefi ? "TRUE" : "FALSE");
  DPRINTF_LO (    "UefiBootOnly = [%a]\n", UefiBootOnly ? "TRUE" : "FALSE");

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)

  //
  // Connect the device path first.
  //

  if (IsDeviceNodeBbs (DevicePath) && LegacyBootEnable) {
    if (OptionalData != NULL &&
        (OptionalDataLength > (sizeof (BBS_TABLE) + sizeof (UINT16)))) {

      //
      // Retrieve the extra device path from optional data.
      //

      ExtraDevicePathSize = OptionalDataLength - sizeof (BBS_TABLE);
      ExtraDevicePathSize -= sizeof (UINT16);
      ConnectDevicePath = (EFI_DEVICE_PATH_PROTOCOL*)AllocateZeroPool (ExtraDevicePathSize);
      CopyMem (
        ConnectDevicePath,
        OptionalData + sizeof (BBS_TABLE) + sizeof (UINT16),
        ExtraDevicePathSize);
    }
  }
#endif // (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)

  DEBUG_LO (
    DPRINTF_DEVICE_PATH ("  ConnectDevicePath = ", ConnectDevicePath);
  );

  RemainingDevicePath = NULL;
  Status = ConnectDevicePathWithRemaining (
             ConnectDevicePath,
             &ConnectDeviceHandle,
             &RemainingDevicePath);
#endif // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

#if (OPTION_SYSTEM_ACPI_TIMER_TO_POSTCODE && OPTION_DEBUG_POSTCODE)

  //
  // At this point we can fork between a legacy and UEFI boot. Capture the
  // timestamp and force it to the upper 2-bytes of a 4-byte post code
  // display, so we can determine the time duration of the two types of boots.
  //

  Status = SendAcpiTimerToPostcode (16);
  if (EFI_ERROR (Status)) {
    DPRINTF_LO ("  Failed to send ACPI timer to upper 2-bytes of POSTCODE port. Status = %r.\n", Status);
  }
#endif

#if OPTION_SUPPORT_SURE_BOOT
  DPRINTF_LO ("  Reset the SureBootStatus.\n");
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_RESET_SURE_BOOT_STATUS, ResetSureBootStatus, NULL, 0);
#endif

  //
  // If we get into the UEFI Boot section Status will be updated and the UEFI
  // Boot Status is what should be returned. All failed LegacyBoot attempts
  // should return SCT_STATUS_NOT_FOUND and if we don't even try either (which
  // could happen give the configuration options we support) we should also
  // return SCT_STATUS_NOT_FOUND.
  //

  Status = SCT_STATUS_NOT_FOUND;

  //
  //  Declare the end of the BDS for performance.
  //
  PERF_END (0, BDS_TOK, NULL, 0); // End of our BDS phase.

  DPRINTF_DEVICE_PATH("\n====== 1 DevicePathText = ", DevicePath);
  REPORT_STATUS_CODE_WITH_DEVICE_PATH (
    EFI_PROGRESS_CODE,
    (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_BS_PC_LOAD_IMAGE),
    DevicePath);
  PRINT_REPORT_STATUS("EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_BS_PC_LOAD_IMAGE) - (%d)\n", __LINE__);

  DPRINTF_DEVICE_PATH("\n====== 2 DevicePathText = ", DevicePath);
  REPORT_STATUS_CODE_EX (
    EFI_PROGRESS_CODE,
    (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_BS_PC_LOAD_IMAGE),
    OptionNumber,
    NULL,
    &gEfiDevicePathProtocolGuid,
    DevicePath,
    GetDevicePathSize (DevicePath));
  PRINT_REPORT_STATUS("EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_BS_PC_LOAD_IMAGE), 0x%04x (%d)\n", OptionNumber, __LINE__);

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  //
  // Do Legacy Boot before Uefi Boot, if enabled.
  //

  if (LegacyBootEnable && LegacyBeforeUefi && !UefiBootOnly) {

#if OPTION_SUPPORT_SECURE_BOOT
    if (IsSecureBootEnabled ()) {
      MilestoneLaunchDpData->ReturnStatus = EFI_SECURITY_VIOLATION;
      return EFI_SECURITY_VIOLATION;
    }
#endif
    PERF_START (0, BDS_TOK, LEGACY_BOOT_TOK, 0);
    DPRINTF_LO ("LaunchDevicePath attempt Legacy before Uefi.\n");
    Status = LegacyBoot (
               ConnectDevicePath,
               OptionNumber,
               OptionalData,
               OptionalDataLength);
    DPRINTF_LO ("LaunchDevicePath.LegacyBoot returned %r.\n", Status);
    PERF_END (0, BDS_TOK, LEGACY_BOOT_TOK, 0);
  }
#endif

  //
  // Attempt to boot the UEFI way. Skip this section if the device path is for
  // legacy boot, i.e. it is a BBS Device Path.
  //

  if (UefiBootEnabled () && !IsDeviceNodeBbs (DevicePath)) {
    ToggleHddUnlockPromptState (TRUE);
    PERF_START (0, BDS_TOK, UEFI_BOOT_TOK, 0);
    DPRINTF_LO ("LaunchDevicePath Attempt UefiBoot.\n");
    Status = UefiBoot (
               ConnectDevicePath,
               OptionNumber,
               OptionalData,
               OptionalDataLength);
    DPRINTF_LO ("UefiBoot returned %r.\n", Status);
    PERF_END (0, BDS_TOK, UEFI_BOOT_TOK, 0);
    ToggleHddUnlockPromptState (FALSE);

  }

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  //
  // Do Legacy Boot after UEFI Boot, if enabled. Don't overwrite the status
  // from the Uefi Boot attempt. The UEFI Boot status is the correct one to
  // return if LegacyBoot returns.
  //

  if (LegacyBootEnable && !LegacyBeforeUefi && !UefiBootOnly) {

#if OPTION_SUPPORT_SECURE_BOOT
    if (IsSecureBootEnabled ()) {
      MilestoneLaunchDpData->ReturnStatus = EFI_SECURITY_VIOLATION;
      return EFI_SECURITY_VIOLATION;
    }
#endif
    PERF_START (0, BDS_TOK, LEGACY_BOOT_TOK, 0);
    DPRINTF_LO ("LaunchDevicePath attempt UEFI before Legacy.\n");
    Status = LegacyBoot (
               ConnectDevicePath,
               OptionNumber,
               OptionalData,
               OptionalDataLength);
    DPRINTF_LO ("LaunchDevicePath.LegacyBoot returned %r.\n", Status);
    PERF_END (0, BDS_TOK, LEGACY_BOOT_TOK, 0);
  }
#endif
  MilestoneLaunchDpData->ReturnStatus = Status;
  return Status;
} // MsTaskLaunchDevicePath

//
// FUNCTION NAME.
//      IsBootOrderChanged - To indicate whether BootOrder has been changed or not.
//
// FUNCTIONAL DESCRIPTION.
//      This function will return TRUE if current BootOrder (this P.O.S.T) is not
//      identical to previous one (last P.O.S.T).
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - Boolean value.
//

BOOLEAN
EFIAPI
IsBootOrderChanged (VOID)
{
  return mIsBootOrderChanged;
} // IsBootOrderChanged

#if 0
//
// FUNCTION NAME.
//      CheckWindowsBootManager - Check Windows Boot Manager load option.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to remove the invalid Windows Boot Manager load option
//      Windows Boot Manager option will be considered as invalid if it is not listed in
//      BootOrder or duplicated in BootOrder.
//      If it has been found in BootOrder, BootManager will also check and update the
//      attributes if necessary.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
STATIC
CheckWindowsBootManager (
  VOID
  )
{
  BOOLEAN Found;
  UINT32 Attributes;
  PLOAD_OPTION_OBJECT p;
  PLOAD_OPTION_OBJECT q;
  PLOAD_OPTION_OBJECT WinBootMgrOption;

  DPRINTF_LO ("CheckWindowsBootManager\n");
  Found = FALSE;
  WinBootMgrOption = NULL;
  p = mBootOptionListHead;
  while (TRUE) {
    if (p == NULL) {
      break;
    }

    if (StrCmp (p->Description, WINDOWS_BOOTMGR_DESCRIPTION) == 0) {
      DPRINTF_LO ("  Find Windows Boot Manager in DB\n");
      if (p->InBootOrder && Found == FALSE) {
        Found = TRUE;
        WinBootMgrOption = p;
        DPRINTF_LO ("    In BoorOrder\n");
      } else {

        DPRINTF_LO ("    Not in BootOrder or duplicated one, remove it from the system\n");

        //
        // Remove it.
        //

        q = p;
        p = p->Next;
        DeleteBootOption (q->OptionNumber);
        RemoveOption (q);
        continue;
      }
    }
    p = p->Next;
  }

  //
  // If found in BootOrder, try to update the attribute to valid value.
  //

  if (Found && WinBootMgrOption != NULL) {

    //
    // Must with LOAD_OPTION_CATEGORY_BOOT flag in attributes.
    //

    if ((WinBootMgrOption->Attributes & LOAD_OPTION_CATEGORY) != LOAD_OPTION_CATEGORY_BOOT) {

      //
      // Update the attributes.
      //

      Attributes = WinBootMgrOption->Attributes;
      Attributes &= ~LOAD_OPTION_CATEGORY;

      CreateOption (
        WinBootMgrOption->OptionNumber,
        WinBootMgrOption->OptionType,
        Attributes,
        WinBootMgrOption->Description,
        WinBootMgrOption->FilePathList,
        WinBootMgrOption->OptionalDataLength,
        WinBootMgrOption->OptionalData,
        NULL);
    }
  }
} // CheckWindowsBootManager
#endif // 0

//
// FUNCTION NAME.
//      UpdateWindowsBootManagerBootOption - Update Windows Boot Manager Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to update the FilePathList of Windows Boot Manager Boot Option.
//
//      The caller has the responsibility to free the allocated resource for FullBootPath.
//
// ENTRY PARAMETERS.
//      p               - pointer points to LOAD_OPTION_OBJECT.
//      FullBootPath    - New found full bootable device path.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
EFIAPI
UpdateWindowsBootManagerBootOption (
  IN UINT16 OptionNumber,
  OUT EFI_DEVICE_PATH_PROTOCOL **FullBootPath OPTIONAL
  )
{
  EFI_STATUS Status;
  UINTN HandleCount;
  PLOAD_OPTION_OBJECT p;
  EFI_HANDLE *HandleBuffer;
  HARDDRIVE_DEVICE_PATH *HddNode;
  EFI_DEVICE_PATH_PROTOCOL *NewDevicePath;

  DPRINTF_LO ("Entry OptionNumber = %d\n", OptionNumber);

  p = NULL;
  Status = GetBootOption (OptionNumber, &p);
  if (EFI_ERROR (Status) || p == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (StrCmp (p->Description, WINDOWS_BOOTMGR_DESCRIPTION) != 0 ||
    !IsDeviceNodeHdd (p->FilePathList)) {
    return EFI_UNSUPPORTED;
  }

  HddNode = (HARDDRIVE_DEVICE_PATH *)p->FilePathList;

  //
  // *MUST* be a GPT partition.
  //

  if (HddNode->MBRType != MBR_TYPE_EFI_PARTITION_TABLE_HEADER ||
    HddNode->SignatureType != SIGNATURE_TYPE_GUID) {
    return EFI_UNSUPPORTED;
  }

  //
  // Find all ESP.
  //

  HandleBuffer = NULL;
  HandleCount = 0;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPartTypeSystemPartGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  DPRINTF_LO ("  Locate all ESP %r\n", Status);
  if (EFI_ERROR (Status) || HandleCount == 0) {
    return Status;
  }

  //
  // Always select the first one.
  //

  NewDevicePath = DevicePathFromHandle (HandleBuffer [0]);
  NewDevicePath = AppendDevicePath (
                    GetLastDeviceNode (NewDevicePath),
                    NextDevicePathNode (p->FilePathList));

  DEBUG_LO (
    DPRINTF_DEVICE_PATH ("  NewDevicePath = ", NewDevicePath);
  );

  //
  // Update the FilePathList of Windows Boot Manager BootOption.
  //

  SafeFreePool (p->FilePathList);
  p->FilePathList = NewDevicePath;
  p->FilePathListLength = (UINT16)GetDevicePathSize (NewDevicePath);
  PackOption (p);
  SaveOption (p);

  if (FullBootPath != NULL) {
    *FullBootPath = AppendDevicePath (
                      DevicePathFromHandle (HandleBuffer [0]),
                      NextDevicePathNode (p->FilePathList));
    DEBUG_LO (
      DPRINTF_DEVICE_PATH ("  New Full path = ", *FullBootPath);
    );
  }

  //
  // Freed the allocated resources.
  //

  SafeFreePool (HandleBuffer);

  return EFI_SUCCESS;
} // UpdateWindowsBootManagerBootOption

