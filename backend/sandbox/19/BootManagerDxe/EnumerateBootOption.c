//
// FILENAME.
//      EnumerateBootOption.c - SecureCore Technology(TM).
//
// FUNCTIONAL DESCRIPTION.
//      Functions related to OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS = 1
//
// NOTICE.
//      Copyright (C) 2021-2024 Phoenix Technologies.  Inc. All Rights Reserved.
//

#include "Meta.h"

//
// Prototypes for functions in other modules that are a part of this component.
//

extern
SCT_STATUS
EFIAPI
ValidateOrderVariable (
  IN PCHAR16 VariableName,
  IN UINTN OptionType
  );

extern
BOOLEAN
EFIAPI
IsLoadOptionDuplicated (
  IN LOAD_OPTION_OBJECT *Option,
  OUT UINT16 *OptionNumber OPTIONAL
  );

extern
SCT_STATUS
EFIAPI
DestroyOption (
  IN LOAD_OPTION_OBJECT *Option
  );

//
// Data defined in other modules and used by this module.
//
extern
LOAD_OPTION_OBJECT *mBootOptionListHead;

extern
BOOT_MANAGER_CONFIGURATION mBootManagerConfigurationTable [];

///////////////////////////////////////////////////////////////////////////////

//
// Prototypes for functions are defined here and share with other modules within
// this component.
//


//
// Data are defined here and share with other modules *within* this component.
//


///////////////////////////////////////////////////////////////////////////////

//
// Private functions implemented by this component. Note these functions do not
// take the API prefix implemented by the module, or they might be confused with
//  the API itself.
//


//
// Private data types used by this module are defined here and any static items
// are declared here.
//

static UINT16   *mPreDefinedBootOptions = NULL;
static UINTN    mPreDefinedBootOptionsSize = 0;
static UINT16   *mProtectedBootOptions = NULL;
static UINTN    mProtectedBootOptionsSize = 0;
static BOOLEAN  mEnumerateAllHappened = FALSE;

static
CHAR16   *mIgnoreDevicePath [] = {
  CONFIG_SYSTEM_BOOT_MANAGER_IGNORE_BOOT_DEVICE_PATH
};

//
// Customized Search Device Paths.
//

static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList0 [] = {
  CONFIG_BmCustomizedDevicePathSearchList0
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList1 [] = {
  CONFIG_BmCustomizedDevicePathSearchList1
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList2 [] = {
  CONFIG_BmCustomizedDevicePathSearchList2
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList3 [] = {
  CONFIG_BmCustomizedDevicePathSearchList3
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList4 [] = {
  CONFIG_BmCustomizedDevicePathSearchList4
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList5 [] = {
  CONFIG_BmCustomizedDevicePathSearchList5
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList6 [] = {
  CONFIG_BmCustomizedDevicePathSearchList6
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList7 [] = {
  CONFIG_BmCustomizedDevicePathSearchList7
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList8 [] = {
  CONFIG_BmCustomizedDevicePathSearchList8
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList9 [] = {
  CONFIG_BmCustomizedDevicePathSearchList9
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList10 [] = {
  CONFIG_BmCustomizedDevicePathSearchList10
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList11 [] = {
  CONFIG_BmCustomizedDevicePathSearchList11
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList12 [] = {
  CONFIG_BmCustomizedDevicePathSearchList12
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList13 [] = {
  CONFIG_BmCustomizedDevicePathSearchList13
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList14 [] = {
  CONFIG_BmCustomizedDevicePathSearchList14
};
static BOOT_MANAGER_DEVICE_PATH_SEARCH mDevicePathSearchList15 [] = {
  CONFIG_BmCustomizedDevicePathSearchList15
};

static BOOT_MANAGER_DEVICE_PATH_SEARCH *mDevicePathSearchListArray [] = {
  mDevicePathSearchList0,
  mDevicePathSearchList1,
  mDevicePathSearchList2,
  mDevicePathSearchList3,
  mDevicePathSearchList4,
  mDevicePathSearchList5,
  mDevicePathSearchList6,
  mDevicePathSearchList7,
  mDevicePathSearchList8,
  mDevicePathSearchList9,
  mDevicePathSearchList10,
  mDevicePathSearchList11,
  mDevicePathSearchList12,
  mDevicePathSearchList13,
  mDevicePathSearchList14,
  mDevicePathSearchList15
};

static CHAR16 *mSataIdePortMappingTable [] = {
  CONFIG_DiagIDESataPortMappingSearchList
};

//
// Search those devices which are under PCI Root Bridge.
//
GLOBAL_REMOVE_IF_UNREFERENCED
BOOT_MANAGER_DEVICE_PATH_SEARCH mAllDeviceSearchPath [] = {
  CONFIG_All_Device_SearchList,      //{L"PciRoot(0x0)", NULL},
  BOOT_MANAGER_DEVICE_PATH_SEARCH_LIST_END
};

BOOLEAN IsInSetupOrBootMenu = FALSE;

///////////////////////////////////////////////////////////////////////////////

//
// Private functions implemented by this component.
//

//
// FUNCTION NAME.
//      GetPreDefinedLoadOptionByCrcTable - Get specific pre-defined LoadOption.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help to find specific original LoadOption defined in
//      configuration table via LoadOptionCrcTable.
//
// ENTRY PARAMETERS.
//      CrcValue        - CRC value.
//
// EXIT PARAMETERS.
//      Function Return - pointer points to BOOT_MANAGER_CONFIGURATION.
//

BOOT_MANAGER_CONFIGURATION *
EFIAPI
GetPreDefinedLoadOptionByCrcTable (
  IN UINT32 CrcValue
  )
{
  UINTN i;
  UINT8 Index;
  UINT32 *CrcTable;
  EFI_STATUS Status;
  UINTN CrcTableSize;
  PBOOT_MANAGER_CONFIGURATION p;

  DPRINTF_LO_ENUM ("GetPreDefinedLoadOptionByCrcTable 0x%x\n", CrcValue);

  CrcTableSize = 0;
  CrcTable = NULL;
  Status = SctLibGetVariable (
             L"LoadOptionCrcTable",
             &gSctBdsServicesProtocolGuid,
             NULL,
             &CrcTableSize,
             (VOID **)&CrcTable);
  DPRINTF_LO_ENUM ("  Get LoadOptionCrcTable returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return NULL;
  }

  DPRINTF_LO_ENUM ("  CrcTableSize = 0x%x\n", CrcTableSize);

  for (i = 0; i < CrcTableSize / sizeof (UINT32); i++) {
    DPRINTF_LO_ENUM ("  CrcTable [%d] = 0x%x\n", i, CrcTable [i]);
    if (CrcTable [i] == CrcValue) {
      break;
    }
  }

  SafeFreePool (CrcTable);

  if (i == CrcTableSize / sizeof (UINT32)) {

    //
    // Not Found.
    //

    return NULL;
  }

  DPRINTF_LO_ENUM ("  Find %dst pre-defined LoadOption in config table\n", i);

  Index = 0;
  while (TRUE) {
    p = &mBootManagerConfigurationTable [Index++];
    if (p->Flags & SCT_BM_FLAGS_END) {
      break;
    }

    if ((p->Flags & SCT_BM_PRE_DEFINED_SLOT) != 0) {
      if (i == 0) {
        DPRINTF_LO_ENUM ("  Description %s\n", p->Description);
        return p;
      }
      i--;
    }
  }

  return NULL;
} // GetPreDefinedLoadOptionByCrcTable

//
// FUNCTION NAME.
//      IsLoadOptionChanged - Is a pre-defined LoadOption be changed.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if LoadOption has been changed.
//
// ENTRY PARAMETERS.
//      Option          - A pointer points to LOAD_OPTION_OBJECT.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, been changed.
//

BOOLEAN
IsLoadOptionChanged (IN PLOAD_OPTION_OBJECT Option)
{
  BOOLEAN IsChanged;
  PBOOT_MANAGER_CONFIGURATION p;
  EFI_DEVICE_PATH_PROTOCOL *FilePathList;

  IsChanged = FALSE;
  p = GetPreDefinedLoadOptionByCrcTable (Option->RawCrc);
  if (p == NULL) {
    return FALSE;
  }

  FilePathList = NULL;
  FilePathList = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
  if (FilePathList == NULL) {
    return FALSE;
  }

  if (StrCmp (Option->Description, p->Description) != 0) {
    IsChanged = TRUE;
  }

  if (!IsChanged && !CompareDevicePath (FilePathList, Option->FilePathList)) {
    IsChanged = TRUE;
  }

  SafeFreePool (FilePathList);

  DEBUG_LO ({
    if (IsChanged) {
      CHAR16 *Str = NULL;
      DPRINTF_LO (" IsLoadOptionChanged returned %d\n", IsChanged);

      DPRINTF_LO ("  Description:\n");
      DPRINTF_LO ("          Option->Description: [%s]\n", Option->Description);
      DPRINTF_LO ("    ConfingTable->Description: [%s]\n", p->Description);

      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (Option->FilePathList, FALSE, TRUE);
      DPRINTF_LO ("  FilePathList:\n");
      DPRINTF_LO ("          Option->FilePathList: [%s]\n", Str);
      DPRINTF_LO ("    ConfingTable->FilePathList: [%s]\n", p->TextDevicePath);
      SafeFreePool (Str);
    }
  });

  return IsChanged;
} // IsLoadOptionChanged

//
// FUNCTION NAME.
//      GetSataPortMappingDevicePath - Get SATA port mapped device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function will use SATA port mapping table provided by platform and
//      get the corresponding device path.
//
//      If the input device path is MSG_SATA_DP, return MSG_ATAPI_DP.
//      If the input device path is MSG_ATAPI_DP, return MSG_SATA_DP.
//
// ENTRY PARAMETERS.
//      DevicePath      - a pointer points to device path.
//      IsSataNode      - MSG_SATA_DP or MSG_ATAPI_DP.
//
// EXIT PARAMETERS.
//      MappedDevicePath- a pointer points mapped device path
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
GetSataPortMappingDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **MappedDevicePath,
  IN BOOLEAN IsSataNode
  )
{
  UINT16 i;
  UINT16 PortNumber;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  SATA_DEVICE_PATH *SataDp;
  EFI_DEVICE_PATH_PROTOCOL *AtapiDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *SataControllerDp;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;

  i = 0;
  PortNumber = 0;
  LastNode = NULL;
  SataControllerDp = NULL;
  AtapiDevicePath = NULL;

  DPRINTF_LO_ENUM ("GetSataPortMappingDevicePath\n");
  if (DevicePath == NULL || MappedDevicePath == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  *MappedDevicePath = NULL;

  LastNode = GetLastDeviceNode (DevicePath);
  if (LastNode == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  if (IsSataNode) {
    DPRINTF_LO_ENUM (" SATA->ATAPI \n");
    if (LastNode->Type != MESSAGING_DEVICE_PATH ||
        LastNode->SubType != MSG_SATA_DP) {
      return SCT_STATUS_INVALID_PARAMETER;
    }

    //
    // Retrieve the port number of SATA device node.
    //

    SataDp = (SATA_DEVICE_PATH*)LastNode;
    PortNumber = SataDp->HBAPortNumber;

    while (TRUE) {
      if (mSataIdePortMappingTable [i] == NULL) {
        break;
      }
      if (i == PortNumber) {
        *MappedDevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (mSataIdePortMappingTable [i]);
        break;
      }
      i++;
    }

  } else {
    DPRINTF_LO_ENUM (" ATAPI->SATA \n");
    if (LastNode->Type != MESSAGING_DEVICE_PATH ||
        LastNode->SubType != MSG_ATAPI_DP) {
      return SCT_STATUS_INVALID_PARAMETER;
    }

    while (TRUE) {
      if (mSataIdePortMappingTable [i] == NULL) {
        break;
      }
      AtapiDevicePath = NULL;
      AtapiDevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (mSataIdePortMappingTable [i]);
      if (AtapiDevicePath != NULL &&
          CompareDevicePath (AtapiDevicePath, DevicePath)) {

        SafeFreePool (AtapiDevicePath);
        AtapiDevicePath = NULL;

        //
        // Construct a SATA device node.
        //

        SataDp = AllocateZeroPool (sizeof (SATA_DEVICE_PATH));
        if (SataDp == NULL) {
          return SCT_STATUS_OUT_OF_RESOURCES;
        }

        SataDp->Header.Type = MESSAGING_DEVICE_PATH;
        SataDp->Header.SubType = MSG_SATA_DP;
        SetDevicePathNodeLength (&SataDp->Header, sizeof (SATA_DEVICE_PATH));
        SataDp->HBAPortNumber = i;
        SataDp->PortMultiplierPortNumber = 0;
        SataDp->Lun = 0;

        //
        // Get the device path of parent controller (SATA controller).
        //

        RemainingDevicePath = DevicePath;

        Status = gBS->LocateDevicePath (
                        &gEfiPciIoProtocolGuid,
                        &RemainingDevicePath,
                        &Handle);

        if (EFI_ERROR (Status) || IsDevicePathEnd (RemainingDevicePath)) {
          return SCT_STATUS_INVALID_PARAMETER;
        }

        Status = gBS->OpenProtocol (
                        Handle,
                        &gEfiDevicePathProtocolGuid,
                        (VOID **) &SataControllerDp,
                        mImageHandle,
                        NULL,
                        EFI_OPEN_PROTOCOL_GET_PROTOCOL);

        if (!EFI_ERROR (Status)) {
          *MappedDevicePath = AppendDevicePathNode (
                                SataControllerDp,
                                &SataDp->Header);
        }

        SafeFreePool (SataDp);
        break;
      }
      SafeFreePool (AtapiDevicePath);
      i++;
    }
  }

  if (*MappedDevicePath == NULL) {
    return SCT_STATUS_NOT_FOUND;
  }

  return SCT_STATUS_SUCCESS;

} // GetSataPortMappingDevicePath

//
// FUNCTION NAME.
//      IsDeviceExistInBootOption - Check if the device has been exist in BootOption.
//
// FUNCTIONAL DESCRIPTION.
//      This function check if the device has been exist in Boot Option Variable.
//
// ENTRY PARAMETERS.
//      DevicePath      - pointer to the EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, been exist Boot Option Variable.
//

BOOLEAN
IsDeviceExistInBootOption (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{

  UINTN i;
  SCT_STATUS Status;
  PUINT16 OptionOrder;
  UINTN OptionOrderSize;
  PLOAD_OPTION_OBJECT Option;
  BOOLEAN DevicePathMatched;
  DEBUG_LO_ENUM (CHAR16* Str;)

  DevicePathMatched = FALSE;

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,
             &OptionOrderSize,
             (VOID **) &OptionOrder);

  DPRINTF_LO_ENUM ("    SctLibGetEfiGlobalVariable returned %r.\n", Status);
  if (EFI_ERROR(Status)) {
    return FALSE;
  }

  for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {

    Option = NULL;
    Status = GetOption (
               OptionOrder [i],
               SCT_BM_LO_BOOT,
               &Option);
    if (EFI_ERROR (Status) || Option == NULL) {
      continue;
    }
    DEBUG_LO_ENUM (
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (Option->FilePathList, FALSE, TRUE);
      DPRINTF_LO_ENUM ("    DevicePath: %s.\n", Str);
    )

    if (CompareDevicePath(Option->FilePathList, DevicePath)) {
      DevicePathMatched = TRUE;
      DPRINTF_LO_ENUM ("    DevicePath is matched (%x) \n", DevicePathMatched);
      break;
    }
  }

  return DevicePathMatched;

}

//
// FUNCTION NAME.
//      IsMatchDevicePrefix_Group - Check if match, update BootOption.
//
// FUNCTIONAL DESCRIPTION.
//      This function check if match Group and
//      settings provided in the project.
//
// ENTRY PARAMETERS.
//      Option          - pointer to the LOAD_OPTION_OBJECT to pack.
//      OriginalGroup   - The Group of Device.
//      DevicePath      - pointer to the EFI_DEVICE_PATH_PROTOCOL.
//      Description     - Pointer points to description string.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, been update Boot Option Variable.
//

BOOLEAN
EFIAPI
IsMatchDevicePrefix_Group (
  IN PLOAD_OPTION_OBJECT Option,
  IN UINT8 OriginalGroup,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN CHAR16 * Description
  )
{
  UINTN BufferSize;
  UINT8 GroupIndex;
  BOOLEAN SameGroup;
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  CHAR16 * TempDescription;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *BopDp;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;
  PBOOT_MANAGER_CONFIGURATION pConfigTable;

  SameGroup = FALSE;
  TempDescription = NULL;
  DPRINTF_LO_ENUM (" Option->RawCrc = 0x%x \n", Option->RawCrc);
  pConfigTable = GetPreDefinedLoadOptionByCrcTable (Option->RawCrc);
  if (pConfigTable == NULL)
    return SameGroup;

  DPRINTF_LO_ENUM (" pConfigTable->Device = %s \n", pConfigTable->TextDevicePath);
  TempDevicePath= BM_CONVERT_TEXT_TO_DEVICE_PATH (pConfigTable->TextDevicePath);

  if (IsDeviceNodeBootOptionProtocol (TempDevicePath)) {
    BopDp = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *) TempDevicePath;
    Status = GetDeviceGroupIndex (&BopDp->ProtocolGuid, &GroupIndex);
    if (OriginalGroup == GroupIndex &&
        IsDeviceExistInBootOption(DevicePath) == FALSE) {
      SameGroup = TRUE;
      BufferSize = StrLen (GetDeviceGroupPrefix (GroupIndex)) << 1;
      BufferSize += StrLen (Description) << 1;

      //
      // Add additional size for terminator character.
      //

      BufferSize += sizeof (CHAR16);
      TempDescription = AllocateZeroPool (BufferSize);

      UnicodeSPrint (
        TempDescription,
        BufferSize,
        L"%s%s",
        GetDeviceGroupPrefix (GroupIndex),
        Description);

      if (StrCmp (TempDescription, Option->Description) != 0) {

        //
        // if the Description is not same as Option->Description, it needs to create Option
        //

        Status = CreateOption (
                   Option->OptionNumber,
                   Option->OptionType,
                   Option->Attributes,
                   TempDescription,
                   DevicePath,
                   Option->OptionalDataLength,
                   Option->OptionalData,
                   NULL);

        SafeFreePool (TempDescription);
      } // if (StrCmp (TempDescription, Option->Description) != 0)
    }
  }
  return SameGroup;
} //IsMatchDevicePrefix_Group

//
// FUNCTION NAME.
//      ValidateLoadOption - Validate the LoadOption.
//
// FUNCTIONAL DESCRIPTION.
//      This function will test if one LoadOption is still valid.
//
// ENTRY PARAMETERS.
//      Option          - Pointer points to LOAD_OPTION_OBJECT *.
//      ForceConnect    - Force to connect device or not.
//      IgnoreBbsDevicePath - Ignore the check for BBS BootOption.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, if valid.
//

BOOLEAN
EFIAPI
ValidateLoadOption (
  IN LOAD_OPTION_OBJECT *Option,
  IN BOOLEAN ForceConnect,
  IN BOOLEAN IgnoreBbsDevicePath)
{
  UINT16 OptionNumber;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  BOOLEAN GroupMatched;
  EFI_GUID OriginalGroupGuid;
  UINT8 OriginalGroupIndex;
  CHAR16* DescriptionString;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *AlternativeDevicePath;
  URI_DEVICE_PATH *UriDevicePath;
  UINTN UriStrLength;       SUPPRESS_WARNING_IF_UNUSED (UriStrLength);
#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath;
  BBS_TABLE *LocalBbsEntry;
  BBS_TABLE *BbsEntry;
  UINT16 LocalBbsIndex;
  UINT16 BbsIndex;
  UINT8 *NewOptionalData;
#endif
  DEBUG_LO_ENUM (CHAR16* Str;)

  if (Option == NULL) {
    return FALSE;
  }

  Handle = NULL;
  GroupMatched = FALSE;
  DescriptionString = NULL;
  AlternativeDevicePath = NULL;
  OptionNumber = 0;

  RemainingDevicePath = Option->FilePathList;
  DEBUG_LO_ENUM (
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (RemainingDevicePath, FALSE, TRUE);
    DPRINTF_LO_ENUM ("\nDevicePath: %s.\n", Str);
    SafeFreePool (Str);
  )

  DPRINTF_LO_ENUM ("ValidateLoadOption Description is %s\n", Option->Description);
  LastNode = GetLastDeviceNode (RemainingDevicePath);

  DPRINTF_LO_ENUM ("  LastNode Type = 0x%x, SubType = 0x%x\n",
    LastNode->Type,
    LastNode->SubType);

  if (LastNode->Type == MESSAGING_DEVICE_PATH ||
      (LastNode->Type == HARDWARE_DEVICE_PATH && LastNode->SubType == HW_CONTROLLER_DP)) {

    //
    // Following UEFI Specification 3.1.2
    // USB WWID and USB Class short-form device path are always valid.
    //

    if (LastNode->SubType == MSG_USB_WWID_DP ||
      LastNode->SubType == MSG_USB_CLASS_DP) {
      DPRINTF_LO_ENUM ("  USB WWID or USB Class are always valid\n");
      return TRUE;
    }

    if (LastNode->SubType == MSG_URI_DP) {

      UriDevicePath = (URI_DEVICE_PATH*) LastNode;
      UriStrLength = DevicePathNodeLength (UriDevicePath) - sizeof (EFI_DEVICE_PATH_PROTOCOL);

      if ((AsciiStrnCmp (UriDevicePath->Uri, "http://", 7) == 0) ||
        (AsciiStrnCmp (UriDevicePath->Uri, "https://", 8) == 0)) {
        DPRINTF_LO_ENUM ("  URI subtype always valid if it contain valid http address.\n");
        return TRUE;
      }
    }

    if (ForceConnect) {
      Status = ConnectDevicePathWithRemaining (
                 Option->FilePathList,
                 &Handle,
                 &RemainingDevicePath);
    } else {
      Status = gBS->LocateDevicePath (
                      &gEfiDevicePathProtocolGuid,
                      &RemainingDevicePath,
                      &Handle);

      //
      // If the user changed the mode of SATA controller from AHCI to IDE or IDE
      // to AHCI, we use the port mapping table to update the BootOption.
      //

      if ((EFI_ERROR (Status) || !IsDevicePathEnd (RemainingDevicePath)) &&
          (LastNode->SubType == MSG_ATAPI_DP || LastNode->SubType == MSG_SATA_DP)) {
        Status = GetSataPortMappingDevicePath (
                   Option->FilePathList,
                   &AlternativeDevicePath,
                   LastNode->SubType == MSG_SATA_DP);

        if (!EFI_ERROR (Status)) {

          DEBUG_LO_ENUM (
            Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (AlternativeDevicePath, FALSE, TRUE);
            DPRINTF_LO_ENUM ("  AlternativeDevicePath: %s.\n", Str);
            SafeFreePool (Str);
          )
          RemainingDevicePath = AlternativeDevicePath;
          Status = gBS->LocateDevicePath (
                          &gEfiDevicePathProtocolGuid,
                          &RemainingDevicePath,
                          &Handle);
        }
      }
    }

    if (!EFI_ERROR (Status) && IsDevicePathEnd (RemainingDevicePath)) {

      DPRINTF_LO_ENUM (" Device Path is presnet in system\n");

      //
      // If AlternativeDevicePath is not NULL, update the BootOption.
      //

      if (AlternativeDevicePath != NULL) {
        DPRINTF_LO_ENUM ("  Update BootOption");
        OptionNumber = Option->OptionNumber;
        Status = CreateOption (
                   Option->OptionNumber,
                   Option->OptionType,
                   Option->Attributes,
                   Option->Description,
                   AlternativeDevicePath,
                   Option->OptionalDataLength,
                   Option->OptionalData,
                   NULL);
        SafeFreePool (AlternativeDevicePath);

        if (EFI_ERROR (Status)) {
          DPRINTF_LO_ENUM (" Failed\n");
          return FALSE;
        }

        //
        // Get the updated BootOption.
        //

        Option = NULL;
        Status = GetOption (
                   OptionNumber,
                   SCT_BM_LO_BOOT,
                   &Option);

        DPRINTF_LO_ENUM (" Successfully\n");
        DEBUG_LO_ENUM (
          Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (Option->FilePathList, FALSE, TRUE);
          DPRINTF_LO_ENUM ("  Option->FilePathList: %s.\n", Str);
          SafeFreePool (Str);
        )
      }

      //
      // Double-check for device type.
      //

      DPRINTF_LO_ENUM ("  Double-check for device type - ");
      if (Option->OptionalData != NULL &&
          Option->OptionalDataLength == sizeof (EFI_GUID)) {
        DPRINTF_LO_ENUM ("  Device Type Recorded.\n");
        CopyMem (
          &OriginalGroupGuid,
          Option->OptionalData,
          Option->OptionalDataLength);

        DPRINTF_LO_ENUM ("  Original Device group GUID = %g\n",
          &OriginalGroupGuid);
        Status = GetDeviceGroupIndex (&OriginalGroupGuid, &OriginalGroupIndex);
        if (EFI_ERROR (Status)) {

          //
          // If the group index cannot be found, considerate unsupported.
          //

          return FALSE;
        }
        DescriptionString = NULL;
        GroupMatched = IsDeviceMatchGroup (
                         Option->FilePathList,
                         OriginalGroupIndex,
                         &DescriptionString);

        if (GroupMatched) {
          DPRINTF_LO_ENUM ("  Device Type unchanged, ");
          DPRINTF_LO_ENUM ("  Device Description is %s\n", DescriptionString);
          if (StrStr (Option->Description, DescriptionString) == NULL) {
            DPRINTF_LO_ENUM ("  Description is changed\n");
            GroupMatched = FALSE;
          }
          SafeFreePool (DescriptionString);
          return GroupMatched;
        }
        DPRINTF_LO_ENUM ("  Device Type changed!, Invalid BootOption.\n");
      } else {
#if OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME
       if (LastNode->SubType == MSG_USB_DP || LastNode->SubType == MSG_SATA_DP) {
         DescriptionString = NULL;
         if (IsSupportedBootDevice (Option->FilePathList, &DescriptionString, &OriginalGroupIndex)) {
           IsMatchDevicePrefix_Group (Option, OriginalGroupIndex, Option->FilePathList, DescriptionString);
         }
       } // if (LastNode->SubType == MSG_USB_DP)
#endif // OPTION_SYSTEM_410_BOOTMANAGER_POSTTIME

        DPRINTF_LO_ENUM ("  Device Type not Recorded, ignore check.\n");
        return TRUE;
      }
    }
  }
#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  else if (RemainingDevicePath->Type == BBS_DEVICE_PATH &&
           RemainingDevicePath->SubType == BBS_BBS_DP) {

    DPRINTF_LO_ENUM ("   Validate BBS device \n");
    if (IgnoreBbsDevicePath) {
      return TRUE;
    }

    DPRINTF_LO_ENUM (
      "   OptionalDataLength  = 0x%x \n",
      Option->OptionalDataLength);

    BbsEntry = (BBS_TABLE *)Option->OptionalData;
    BbsIndex = *(UINT16 *)(Option->OptionalData + sizeof (BBS_TABLE));
    PhysicalDevicePath = (EFI_DEVICE_PATH_PROTOCOL *)(Option->OptionalData +
                                                      sizeof (BBS_TABLE) +
                                                      sizeof (UINT16));

    DPRINTF_LO_ENUM ("   BbsIndex = 0x%x \n", BbsIndex);

    Status = GetBbsEntryByDevicePath (
              PhysicalDevicePath,
              &LocalBbsIndex,
              &LocalBbsEntry);

    DEBUG_LO_ENUM (
      if (EFI_ERROR (Status)) {
        DPRINTF_LO_ENUM ("  GetBbsEntryByDevicePath failed, %r.\n", Status);
      } else {
        DPRINTF_LO_ENUM (
          "  LocalBbsEntry->DeviceType = 0x%x\n"
          "               ->Bus        = 0x%x\n"
          "               ->Device     = 0x%x\n"
          "               ->Function   = 0x%x\n",
          LocalBbsEntry->DeviceType,
          LocalBbsEntry->Bus,
          LocalBbsEntry->Device,
          LocalBbsEntry->Function);

        DPRINTF_LO_ENUM (
          "  BbsEntry->DeviceType      = 0x%x\n"
          "          ->Bus             = 0x%x\n"
          "          ->Device          = 0x%x\n"
          "          ->Function        = 0x%x\n",
          BbsEntry->DeviceType,
          BbsEntry->Bus,
          BbsEntry->Device,
          BbsEntry->Function);
      }
    ) // DEBUG_LO_ENUM

    if (!EFI_ERROR (Status) &&
        (LocalBbsEntry->DeviceType == BbsEntry->DeviceType) &&
        (LocalBbsEntry->Bus == BbsEntry->Bus) &&
        (LocalBbsEntry->Device == BbsEntry->Device) &
        (LocalBbsEntry->Function == BbsEntry->Function)) {
      DPRINTF_LO_ENUM ("  BBS Device is existed in system, ");
      DPRINTF_LO_ENUM ("Double check for the description. \n");

      //
      // Also check the description string.
      //

      BuildDescriptionFromBbsEntry (LocalBbsEntry ,&DescriptionString);
      DPRINTF_LO_ENUM ("  LocalBbsEntry Description:%s\n", DescriptionString);
      if (StrStr (Option->Description, DescriptionString) != NULL) {
        DPRINTF_LO_ENUM ("  Description is unchanged\n");
        GroupMatched = TRUE;
      }
      SafeFreePool (DescriptionString);

      //
      // If the option otherwise matches, compare the index in its optional data
      // to the one retrieved from the BBS table.  If they don't match, update
      // (re-create) the option.
      //

      if (GroupMatched && LocalBbsIndex != BbsIndex) {
        DPRINTF_LO_ENUM (
          "  BBS index changed from %d to %d - updating the option.\n",
          BbsIndex,
          LocalBbsIndex);

        NewOptionalData = AllocateCopyPool (
                            Option->OptionalDataLength,
                            Option->OptionalData);

        if (NewOptionalData != NULL) {
          CopyMem (NewOptionalData, LocalBbsEntry, sizeof (BBS_TABLE));
          *(UINT16 *) (NewOptionalData + sizeof (BBS_TABLE)) = LocalBbsIndex;

          //
          // Re-create the option.  This frees the old option and its data.
          //

          Status = CreateOption (
                     Option->OptionNumber,
                     Option->OptionType,
                     Option->Attributes,
                     Option->Description,
                     Option->FilePathList,
                     Option->OptionalDataLength,
                     NewOptionalData,
                     NULL);

          Option = NULL;                // don't access freed pointer.

          if (EFI_ERROR (Status)) {
            DPRINTF_LO_ENUM ("Failed to update option, %r.\n", Status);
            SafeFreePool (NewOptionalData);
          }
        }
      }

      return GroupMatched;
    }
  }
#endif
  else {

    //
    // For others, we always consider the BootOption is valid.
    //

    return TRUE;
  }

  return FALSE;
} // ValidateLoadOption

//
// FUNCTION NAME.
//      IsProtectedLoadOption - Check if a LoadOption is protected.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the LoadOption is protected.
//
// ENTRY PARAMETERS.
//      OptionNumber    - LoadOption number.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, Protected.
//

BOOLEAN
EFIAPI
IsProtectedLoadOption (
  IN UINT16 OptionNumber
  )
{
  UINT16 j;

  if (mProtectedBootOptions == NULL) {
    mProtectedBootOptions = SctLibGetVariableAndSize (
                              L"ProtectedBootOptions",
                              &gSctBdsServicesProtocolGuid,
                              &mProtectedBootOptionsSize);
    if (mProtectedBootOptions == NULL) {
      mProtectedBootOptionsSize = 0;
      return FALSE;
    }
  }

  if (mProtectedBootOptionsSize != 0) {
    for (j = 0; j < (mProtectedBootOptionsSize / sizeof (UINT16)); j++) {
      if (OptionNumber == mProtectedBootOptions [j]) {
        return TRUE;
      }
    }
  }

  return FALSE;

} // IsProtectedLoadOption

//
// FUNCTION NAME.
//      IsPreDefinedLoadOption - Check if a LoadOption is pre-defined.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the LoadOption is pre-defined for matched
//      device path to be filled.
//
// ENTRY PARAMETERS.
//      OptionNumber    - LoadOption number.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, Protected.
//

BOOLEAN
IsPreDefinedLoadOption (IN UINT16 OptionNumber)
{
  UINT16 j;

  if (mPreDefinedBootOptions == NULL) {
    mPreDefinedBootOptions = SctLibGetVariableAndSize (
                               L"PreDefinedBootOptions",
                               &gSctBdsServicesProtocolGuid,
                               &mPreDefinedBootOptionsSize);
    if (mPreDefinedBootOptions == NULL) {
      mPreDefinedBootOptionsSize = 0;
      return FALSE;
    }
  }

  if (mPreDefinedBootOptionsSize != 0) {
    for (j = 0; j < (mPreDefinedBootOptionsSize / sizeof (UINT16)); j++) {
      if (OptionNumber == mPreDefinedBootOptions [j]) {
        return TRUE;
      }
    }
  }

  return FALSE;

} // IsPreDefinedLoadOption

//
// FUNCTION NAME.
//      ValidateAllLoadOptions - Validate all LoadOptions.
//
// FUNCTIONAL DESCRIPTION.
//      This function will validate all LoadOptions and delete the invalid ones.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ValidateAllLoadOptions (VOID)
{
  UINTN i;
  SCT_STATUS Status;
  UINT16 *OptionOrder;
  UINTN OptionOrderSize;
  LOAD_OPTION_OBJECT *Option;
  BOOT_MANAGER_CONFIGURATION *p;
  UINT8 *OptionalData;
  UINT32 OptionalDataLength;
  BOOLEAN IsPreDefinedBootOption;
  BOOLEAN IsProtectedBootOption;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  DPRINTF_LO_ENUM ("ValidateAllLoadOptions\n");

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,
             &OptionOrderSize,
             (VOID **) &OptionOrder);

  DPRINTF_LO_ENUM ("  SctLibGetEfiGlobalVariable returned %r.\n", Status);
  if (EFI_ERROR(Status)) {
    return SCT_STATUS_SUCCESS;
  }

  for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {

    Option = NULL;
    p = NULL;
    Status = GetOption (
               OptionOrder [i],
               SCT_BM_LO_BOOT,
               &Option);
    if (EFI_ERROR (Status) || Option == NULL) {
      continue;
    }

    //
    // Skip application.
    //

    if ((Option->Attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_APP) {
      continue;
    }

    if (ValidateLoadOption (Option, FALSE, FALSE)) {
      continue;
    }

    //
    // Get option again because the original one may be updated by ValidateLoadOption.
    //

    Option = NULL;
    Status = GetOption (
               OptionOrder [i],
               SCT_BM_LO_BOOT,
               &Option);
    if (EFI_ERROR (Status) || Option == NULL) {
      continue;
    }

    //
    // Never delete the built-in(pre-defined or protected) LoadOption.
    //

    IsProtectedBootOption = IsProtectedLoadOption (OptionOrder [i]);
    IsPreDefinedBootOption = IsPreDefinedLoadOption (OptionOrder [i]);

    if ((IsPreDefinedBootOption && !IsLoadOptionChanged (Option)) ||
     (IsProtectedBootOption && !IsPreDefinedBootOption)) {

      //
      // If this built-in BootOption is unchanged, keep it.
      //

      continue;

    }

    if (IsPreDefinedBootOption) {
      DPRINTF_LO_ENUM ("   LoadOption 0x%x is invalid but is a pre-defined option, DO NOT DELETE!.\n",
        OptionOrder [i]);

      //
      // Restore the pre-defined LoadOption.
      //

      DPRINTF_LO_ENUM ("  Restore the pre-defined LoadOption\n");
      p = GetPreDefinedLoadOptionByCrcTable (Option->RawCrc);
      if (p == NULL) {
        return EFI_NOT_FOUND;
      }

      DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
      if (DevicePath == NULL) {
        return Status;
      }

      OptionalDataLength = 0;
      OptionalData = NULL;
      if (p->OptionData != NULL) {
        OptionalDataLength = (UINT32)StrSize (p->OptionData);
        OptionalData = (UINT8 *)(p->OptionData);
      }

      //
      // Restore the pre-defined LoadOption.
      //

      Status = CreateOption (
                 Option->OptionNumber,
                 Option->OptionType,
                 Option->Attributes,    // Keep the attributes.
                 p->Description,
                 DevicePath,
                 OptionalDataLength,
                 OptionalData,
                 NULL);

      //
      // Freed the resource.
      //

      SafeFreePool (DevicePath);

    } else {

      //
      // If failed to verify, remove the Option from DB and also delete the
      // Boot#### variable.
      //

      DPRINTF_LO_ENUM ("   LoadOption 0x%x is invalid, DELETE!.\n",
        OptionOrder [i]);

      if (Option != NULL) {
        Status = DeleteBootOption (Option->OptionNumber); // Remove from variable Boot####.
      } else {
        DPRINTF_LO ("  Error:NULL Option.\n");
      }

      if (Status == SCT_STATUS_SUCCESS){
        RemoveOption (Option);            // Removed from database.
      }

    }
  }

  return SCT_STATUS_SUCCESS;
} // ValidateAllLoadOptions

//
// FUNCTION NAME.
//      IsIgnoreBootDevicePath - Check if this device path is in ignored list.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the input device path is in ignored list.
//
// ENTRY PARAMETERS.
//      DevicePath      - DevicePath to be checked.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, if in ignored list.
//

BOOLEAN
IsIgnoreBootDevicePath (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  UINT8 SizeOfIgnoreList;
  EFI_DEVICE_PATH_PROTOCOL *IgnoreDevicePath;

  if (DevicePath == NULL) {
    return FALSE;
  }

  SizeOfIgnoreList = sizeof (mIgnoreDevicePath) / sizeof (CHAR16*) - 1;

  while (TRUE) {
    if (SizeOfIgnoreList == 0) {
      break;
    }
    IgnoreDevicePath = NULL;
    if (mIgnoreDevicePath [--SizeOfIgnoreList] != NULL) {

      IgnoreDevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (mIgnoreDevicePath [SizeOfIgnoreList]);

      if (IgnoreDevicePath != NULL &&
          CompareDevicePath (DevicePath, IgnoreDevicePath)) {
        SafeFreePool (IgnoreDevicePath);
        return TRUE;
      }

      SafeFreePool (IgnoreDevicePath);
    }
  }
  return FALSE;
} // IsIgnoreBootDevicePath

//
// FUNCTION NAME.
//      BuildAllSctBootOption - Construct the SctBootOption list.
//
// FUNCTIONAL DESCRIPTION.
//      This function will retrieve all supported bootable devices and create
//      the SctBootOption for each device.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      ListHead        - the head points SctBootOption list.
//      Function Return - EFI status code.
//

SCT_STATUS
BuildAllSctBootOption (OUT PSCT_BOOT_OPTION_NODE *ListHead)
{
  UINTN i, n;
  UINT8 GroupIndex;
  SCT_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  EFI_DEVICE_PATH_PROTOCOL *p, *dp;
  PSCT_BOOT_OPTION_NODE *q;
  PCHAR16 Description;

  DEBUG_LO_ENUM (CHAR16* Str;)
  DPRINTF_LO_ENUM ("\n\n");

  if (ListHead == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  Status = SearchForDevicePaths (
             mAllDeviceSearchPath,
             &dp,
             &n);

  DPRINTF_LO_ENUM ("  0x%x devices found \n", n);
  q = ListHead;
  p = dp;

  for (i = 0; i < n; i++, p = NextDevicePath (p)) {

    DEBUG_LO_ENUM (
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (p, FALSE, TRUE);
      DPRINTF_LO_ENUM ("\n  DevicePath: %s.\n", Str);
      SafeFreePool (Str);
    )

    if (IsIgnoreBootDevicePath (p)) {
      DPRINTF_LO_ENUM ("  Device path is in ingored list.\n");
      continue;
    }

    if (!IsSupportedBootDevice (p, &Description, &GroupIndex)) {
      DPRINTF_LO_ENUM ("  Not support.\n");
      continue;
    }
    DPRINTF_LO_ENUM ("  Supported Device :\n");
    DPRINTF_LO_ENUM ("    Group Index = %d\n",GroupIndex);
    DPRINTF_LO_ENUM ("    Device description: %s.\n", Description);
    DPRINTF_LO_ENUM ("    Create one SctBootOption for this device.\n\n");

    *q = AllocateZeroPool (sizeof (SCT_BOOT_OPTION_NODE));
    if (*q == NULL) {
      return SCT_STATUS_OUT_OF_RESOURCES;
    }

    (*q)->NumberOfFilePaths = 1;
    (*q)->FilePathListLength = (UINT16)GetDevicePathSize (p);

    //
    // FilePathList and Description member variables need to be freed by caller.
    //

    (*q)->FilePathList = AllocateCopyPool ((*q)->FilePathListLength, p);
    (*q)->Description = Description;

    (*q)->ChildIndex = GroupIndex;
    (*q)->Attributes = (LOAD_OPTION_ACTIVE | LOAD_OPTION_CATEGORY_BOOT);
    q = &((*q)->Next);
  }

  SafeFreePool (dp);
  return SCT_STATUS_SUCCESS;

} // BuildAllSctBootOption


//
// FUNCTION NAME.
//      GetBopMatchedDevicePath - Expand a Boot Option Protocol Device Path.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes Vendor Guid nodes. These nodes provide the GUID
//      for the specified device type. This function will then use the
//      pre-defined criteria to search the matched device paths and put into an
//      array.
//      Before calling this functions, caller should do "ConnectAll" or shadow
//      all necessary OPROMs so that the candidate device paths can be found.
//
// ENTRY PARAMETERS.
//      DevicePath      - the Device Path to expand.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      DevicePaths     - the array of found device paths.
//      NumberDevicePaths - the number of found device paths.
//

SCT_STATUS
GetBopMatchedDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT EFI_DEVICE_PATH_PROTOCOL **DevicePaths,
  OUT UINTN *NumberDevicePaths
  )
{
  UINTN i, Size, n;
  SCT_STATUS Status;
  PVOID Context;
  UINT8 Index;
  UINTN ContextSize;
  UINT8 GroupIndex;
  UINT8 TargetGroupIndex;
  UINT8 MaxDevicePathSearchList;
  EFI_DEVICE_PATH_PROTOCOL *p, *dp, *q;
  BOOLEAN AnySupportedDevice;
  BOOT_OPTION_PROTOCOL_DEVICE_PATH *BopDp;

  DPRINTF_LO_ENUM ("GetBopMatchedDevicePath\n");
  if (DevicePath == NULL ||
      DevicePaths == NULL ||
      NumberDevicePaths == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Check if the device path is a BOP device path.
  //

  if (!IsDeviceNodeBootOptionProtocol (DevicePath)) {
    return SCT_STATUS_UNSUPPORTED;
  }

  BopDp = (BOOT_OPTION_PROTOCOL_DEVICE_PATH *)DevicePath;
  if (DevicePathNodeLength (DevicePath) >
      sizeof (BOOT_OPTION_PROTOCOL_DEVICE_PATH)) {

    ContextSize = DevicePathNodeLength (DevicePath);
    ContextSize -= sizeof (BOOT_OPTION_PROTOCOL_DEVICE_PATH);
    Context = BopDp + 1;
    Index = *(UINT8*)Context;
    DPRINTF_LO_ENUM ("  BOP Context = %d\n", Index);
  } else {

    ContextSize = 0;
    Context = NULL;
    Index = 0xff;
    DPRINTF_LO_ENUM ("  BOP Context not specified\n");
  }

  MaxDevicePathSearchList = sizeof (mDevicePathSearchListArray);
  MaxDevicePathSearchList /= sizeof (PBOOT_MANAGER_CONNECTION_DEVICE);
  GroupIndex = 0xff;
  TargetGroupIndex = 0xff;

  if (CompareGuid (
        &(BopDp->ProtocolGuid),
        &gAnyDeviceBootOptionProtocolGuid)) {

    AnySupportedDevice = TRUE;

    //
    // Must have specified DevicePath search list.
    //

    if (Index >= MaxDevicePathSearchList) {
      return SCT_STATUS_UNSUPPORTED;
    }

  } else {

    AnySupportedDevice = FALSE;
    Status = GetDeviceGroupIndex (&(BopDp->ProtocolGuid), &TargetGroupIndex);
    if (EFI_ERROR (Status)) {
      return SCT_STATUS_UNSUPPORTED;
    }
  }

  if (Index >= MaxDevicePathSearchList) {
    Status = SearchForDevicePaths (
               mAllDeviceSearchPath,
               &dp,
               &n);

  } else {

    Status = SearchForDevicePaths (
               mDevicePathSearchListArray [Index],
               &dp,
               &n);
  }

  DPRINTF_LO_ENUM ("  SearchForDevicePaths returned %r, %d.\n", Status, n);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Size = 0;
  p = dp;
  for (i = 0; i < n; i++, p = NextDevicePath (p)) {

    //
    // Check if the device is bootable.
    //

    if (!IsSupportedBootDevice (p, NULL, &GroupIndex)) {
      continue;
    }

    //
    // If the type of group is not AnyDeviceBootOptionProtocolGuid, make sure the type is matched.
    //

    if ((AnySupportedDevice == FALSE) && (GroupIndex != TargetGroupIndex)) {
      continue;
    }

    Size += GetDevicePathSize (p);
  }

  if (Size == 0) {
    return SCT_STATUS_NOT_FOUND;
  }

  //
  // Allocate the output buffer.
  //

  Status = (gBS->AllocatePool) (EfiBootServicesData, Size, (VOID **) DevicePaths);
  if (EFI_ERROR (Status)) {
    DPRINTF_LO_ENUM ("  Failed to allocate memory for DevicePaths.\n");
    SafeFreePool (dp);
    return Status;
  }

  *NumberDevicePaths = 0;
  p = dp;
  q = *DevicePaths;
  for (i = 0; i < n; i++, p = NextDevicePath (p)) {

    //
    // Check if the device is bootable.
    //

    if (!IsSupportedBootDevice (p, NULL, &GroupIndex)) {
      continue;
    }

    if ((AnySupportedDevice == FALSE) && (GroupIndex != TargetGroupIndex)) {
      continue;
    }

    Size = GetDevicePathSize (p);
    CopyMem (q, p, Size);
    q = (EFI_DEVICE_PATH_PROTOCOL *)(((UINT8 *)q) + Size);
    *NumberDevicePaths = *NumberDevicePaths + 1;
  }

  SafeFreePool (dp);
  return SCT_STATUS_SUCCESS;

} // GetBopMatchedDevicePath

//
// FUNCTION NAME.
//      IsHttpBootUriValid - Is Http Boot option URI node valid address.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if LoadOption has valid URI address.
//
// ENTRY PARAMETERS.
//      Option          - A pointer points to LOAD_OPTION_OBJECT.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE, uri is valid.
//

BOOLEAN
IsHttpBootUriValid (IN PLOAD_OPTION_OBJECT Option)
{
  UINTN UriStrLength;
  BOOLEAN IsUriValid;
  URI_DEVICE_PATH *UriDevicePath;
  PBOOT_MANAGER_CONFIGURATION p;
  EFI_DEVICE_PATH_PROTOCOL *FilePathList;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;

  IsUriValid = FALSE;
  LastNode = NULL;

  p = GetPreDefinedLoadOptionByCrcTable (Option->RawCrc);
  if (p == NULL) {
    return FALSE;
  }

  FilePathList = NULL;
  FilePathList = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
  if (FilePathList == NULL) {
    return FALSE;
  }

  DEBUG_LO ({
    CHAR16 *Str;

    DPRINTF ("  Description:\n");
    DPRINTF ("          Option->Description: [%s]\n", Option->Description);
    DPRINTF ("    ConfingTable->Description: [%s]\n", p->Description);

    Str = NULL;
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (Option->FilePathList, FALSE, TRUE);
    DPRINTF ("  FilePathList:\n");
    DPRINTF ("          Option->FilePathList: [%s]\n", Str);
    DPRINTF ("    ConfingTable->FilePathList: [%s]\n", p->TextDevicePath);
    SafeFreePool (Str);
  });

  LastNode = GetLastDeviceNode (Option->FilePathList);

  //
  // Check if the URI does have any data within.
  //

  if ((LastNode->Type == MESSAGING_DEVICE_PATH) && (LastNode->SubType == MSG_URI_DP)) {

    UriDevicePath = (URI_DEVICE_PATH*) LastNode;
    UriStrLength = DevicePathNodeLength (UriDevicePath) - sizeof(EFI_DEVICE_PATH_PROTOCOL);

    if (UriStrLength == 0) {
      IsUriValid = FALSE;
    } else {
      if ((AsciiStrnCmp (UriDevicePath->Uri, "http://", 7) == 0) ||
        (AsciiStrnCmp (UriDevicePath->Uri, "https://", 8) == 0)) {
        IsUriValid = TRUE;
      }
    }
  }

  SafeFreePool (FilePathList);

  DPRINTF_LO (" IsUriValid returned %d\n", IsUriValid);
  return IsUriValid;
} // IsHttpBootUriValid

//
// FUNCTION NAME.
//      FindSctBootOptionEntry - Find one node from list.
//
// FUNCTIONAL DESCRIPTION.
//      This function find the specified node from a SCT_BOOT_OPTION_NODE
//      list.
//      If the caller needs to release the resource of RemovedNode.
//
// ENTRY PARAMETERS.
//      Head            - Head of the single list.
//      DevicePath      - DevicePath to be compared.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
FindSctBootOptionEntry (
  IN PSCT_BOOT_OPTION_NODE *Head,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  SCT_STATUS Status;
  DEBUG_LO_ENUM (CHAR16* Str;)

  DPRINTF_LO_ENUM ("FindSctBootOptionEntry\n");
  DEBUG_LO_ENUM (
    Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_LO_ENUM ("  DevicePath %s.\n", Str);
    SafeFreePool (Str);
  )

  if (Head == NULL || DevicePath == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  Status = EFI_NOT_FOUND;
  while (TRUE) {
    if (*Head == NULL) {
      DPRINTF_LO_ENUM ("  Not Found\n");
      return EFI_NOT_FOUND;
    }
    DEBUG_LO_ENUM (
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT ((*Head)->FilePathList, FALSE, TRUE);

      DPRINTF_LO_ENUM ("FilePathList %s.\n", Str);
      SafeFreePool (Str);
    )

    if (CompareDevicePath (DevicePath, (*Head)->FilePathList)) {
      Status = EFI_SUCCESS;
      DPRINTF_LO_ENUM ("Found\n");
      break;
    }
    Head = &((*Head)->Next);
  } // while (TRUE) {

  return Status;

} // FindSctBootOptionEntry

//
// FUNCTION NAME.
//      FreeSctBootOptionList - Free a single SCT Boot Option.
//
// FUNCTIONAL DESCRIPTION.
//      This function frees a single SCT Boot Option.
//
// ENTRY PARAMETERS.
//      Head            - Points to a head of the single SCT Boot Option.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
FreeSctBootOptionList (IN PSCT_BOOT_OPTION_NODE Head)
{
  PSCT_BOOT_OPTION_NODE Temp;
  if (Head == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  while (TRUE) {
    if (Head == NULL) {
      break;
    }
    DPRINTF_LO_ENUM (" Free SctBootOption %s\n", Head->Description);
    SafeFreePool (Head->FilePathList);
    SafeFreePool (Head->Description);
    Temp = Head;
    Head = Head->Next;
    SafeFreePool (Temp);
  }

  return EFI_SUCCESS;
} // FreeSctBootOptionList

//
// FUNCTION NAME.
//      RemoveSctBootOptionEntry - Remove one node from list.
//
// FUNCTIONAL DESCRIPTION.
//      This function removes the specified node from a SCT_BOOT_OPTION_NODE
//      list.
//      If the caller needs to release the resource of RemovedNode.
//
// ENTRY PARAMETERS.
//      Head            - Head of the single list.
//      DevicePath      - DevicePath to be compared.
//
// EXIT PARAMETERS.
//      RemovedNode     - Pointer points to the pointer points to deleted node.
//      Function Return - EFI status code.
//

SCT_STATUS
RemoveSctBootOptionEntry (
  IN PSCT_BOOT_OPTION_NODE *Head,
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT PSCT_BOOT_OPTION_NODE *RemovedNode
  )
{
  SCT_STATUS Status;
  PSCT_BOOT_OPTION_NODE q;
  DPRINTF_LO_ENUM ("RemoveSctBootOptionEntry\n");

  if (Head == NULL || DevicePath == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  Status = SCT_STATUS_SUCCESS;
  while (TRUE) {
    if (*Head == NULL) {
      DPRINTF_LO_ENUM ("  Not Found\n");
      return EFI_NOT_FOUND;
    }
    if (CompareDevicePath (DevicePath, (*Head)->FilePathList)) {
      break;
    }
    Head = &((*Head)->Next);
  }

  DPRINTF_LO_ENUM ("  Remove one entry\n");
  q = *Head;
  *Head = (*Head)->Next;

  q->Next = NULL;
  if (RemovedNode != NULL) {
    *RemovedNode = q;
  } else {
    Status = FreeSctBootOptionList (q);
  }

  return Status;

} // RemoveSctBootOptionEntry

//
// FUNCTION NAME.
//      IsLegacyBootOnlyDevice - Check if DevicePath is for legacy boot only.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the input device path is for legacy boot
//      only.
//      Below protocols will be tested:
//      1. EFI_BLOCK_IO_PROTOCOL
//      2. LOAD_FILE_PROTOCOL
//      3. EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
//
// ENTRY PARAMETERS.
//      DevicePath      - Device path to be checked.
//
// EXIT PARAMETERS.
//      Boolean         - If TRUE, Legacy Boot Only.
//

BOOLEAN
IsLegacyBootOnlyDevice (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  if (DevicePath == NULL) {
    return FALSE;
  }

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
  // Test if EFI_BLOCK_IO_PROTOCOL attached ?
  //

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Test if LOAD_FILE_PROTOCOL attached ?
  //

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiLoadFileProtocolGuid,
                  NULL,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // Test if EFI_SIMPLE_FILE_SYSTEM_PROTOCOL attached ?
  //

  Status = gBS->OpenProtocol (
                  Handle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  mImageHandle,
                  NULL,
                  EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

  if (!EFI_ERROR (Status)) {
    return FALSE;
  }

  return TRUE;

} // IsLegacyBootOnlyDevice



//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      EnumerateAllLoadOptions - Enumerate all LoadOptions.
//
// FUNCTIONAL DESCRIPTION.
//      This function will retrieve all bootable devices and create the
//      LoadOption for them.
//      The invalid LoadOptions will also be deleted if check failed.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
EnumerateAllLoadOptions (VOID)
{
  UINTN i, j;
#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UINT8 *BufferPtr;
#endif //OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
  UINTN BufferSize;
  UINT16 NewOption;
  BOOLEAN FillSlot;
  SCT_STATUS Status;
  VOID *OptionalData;
  EFI_GUID *GroupGuid;
  CHAR16 *Description;
  UINTN NumberOfOptions;
  UINT32 TempAttributes;
  LOAD_OPTION_OBJECT *p;
  UINTN NumberDevicePaths;
  SCT_BOOT_OPTION_NODE **q;
  UINT32 OptionalDataLength;
  LOAD_OPTION_OBJECT *Option;
  UINT16 *PreDefinedBootOptions;
  UINTN PreDefinedBootOptionsSize;
  SCT_BOOT_OPTION_NODE *ChildListHead;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *DevicePaths;
  SCT_BOOT_OPTION_NODE *AllSctBootOptions;
  UINT16 LocalBootOrder [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER];

  DEBUG_LO_ENUM (CHAR16* Str;)

  Option = NULL;
  NumberDevicePaths = 0;
  DPRINTF_LO_ENUM ("EnumerateAllLoadOptions:\n");

  if (!IsInSetupOrBootMenu && mEnumerateAllHappened) {
    DPRINTF_LO_ENUM (" Already Happened.\n");
    return SCT_STATUS_SUCCESS;
  }

  //
  // Connect all handles first.
  //

  ConnectAllHandlesExceptPciVga ();

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_LEGACY_INIT, MsTaskLegacyInit, NULL, 0);

  //
  // Shadow all PCI OPROMs if legacy boot supported.
  //

  ShadowAllOproms ();
#endif

#if CONFIG_SYSTEM_BOOT_MANAGER_GENERIC_DEVICE_READY_WAIT_TIME != 0
  //
  // If this EnumerateAllLoadOptions() function is triggered due to USB mass
  // storage insertion/removal under boot menu or setup boot page, we assume the
  // USB device is properly initialized at this point. Hence we don't need this
  // delay.
  //
  if (!IsInSetupOrBootMenu) {
    EFI_TPL Tpl;
    //
    // Lower the TPL to application so that the pending event (timer) has the
    // opportunity to execute.
    //

    Tpl = SetTpl (TPL_APPLICATION);
    gBS->Stall (1000 * CONFIG_SYSTEM_BOOT_MANAGER_GENERIC_DEVICE_READY_WAIT_TIME);
    SetTpl (Tpl);
  }
#endif

  //
  // Validate all existing LoadOption in database.
  //

  DPRINTF_LO_ENUM ("\n1 - Validate all invalid existing LoadOptions.\n");
  ValidateAllLoadOptions ();

  //
  // Retrieve all bootable devices.
  // This step will also filter out those devices that the customer wants to
  // ingore during P.O.S.T according to SYSTEM_BOOT_MANAGER_IGNORE_BOOT_DEVICE_PATH.
  //

  DPRINTF_LO_ENUM ("\n2 - Retrieve all bootable devices in the system.\n");
  AllSctBootOptions = NULL;
  Status = BuildAllSctBootOption (&AllSctBootOptions);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Fill the pre-defined BootOption.
  // BootOption with Bop device path or explicit device path assigned will be
  // filled.
  //

  DPRINTF_LO_ENUM ("\n3 - Start to fill the pre-defined BootOption.\n");

  PreDefinedBootOptions = NULL;
  PreDefinedBootOptions = SctLibGetVariableAndSize (
                            L"PreDefinedBootOptions",
                            &gSctBdsServicesProtocolGuid,
                            &PreDefinedBootOptionsSize);
  if (PreDefinedBootOptions == NULL) {
    PreDefinedBootOptionsSize = 0;
  }

  NumberOfOptions = PreDefinedBootOptionsSize / sizeof (UINT16);

  for (i = 0; i < NumberOfOptions; i++) {

    DevicePath = NULL;
    DevicePaths = NULL;
    Description = NULL;

    DPRINTF_LO_ENUM (" Pre-defined BootOption Boot%04x\n",
      PreDefinedBootOptions [i]);

    Status = GetOption (PreDefinedBootOptions [i], SCT_BM_LO_BOOT, &Option);
    if (EFI_ERROR (Status) || Option->FilePathList == NULL) {
      continue;
    }

    if (IsLoadOptionChanged (Option)) {
      DPRINTF_LO_ENUM (" BootOption has been changed, skip it.\n");
      continue;
    }

    DevicePath = Option->FilePathList;
    DEBUG_LO_ENUM (
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
      DPRINTF_LO_ENUM ("Option->FilePathList %s.\n", Str);
      SafeFreePool (Str);
    )

    if (IsDeviceNodeBootOptionProtocol (DevicePath)) {

      Status = GetBopMatchedDevicePath (
                 DevicePath,
                 &DevicePaths,
                 &NumberDevicePaths);
      if (EFI_ERROR (Status) || NumberDevicePaths == 0) {

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_HIDE_INVALID_HTTP_BOOT
        //
        // If it is the Http BOP and there is no boot devicepath, then set it to hidden.
        //

        if (IsHttpBootUriValid (Option)) {
          Option->Attributes |= LOAD_OPTION_HIDDEN;
        }
#endif
        DPRINTF_LO_ENUM ( "  no any children existed\n");
        continue;
      }

      //
      // if it is the HTTP boot, check if the URI does specify.  If yes, then this pre-defined
      // boot option does not need to update the DevicePath.
      //

      if (IsHttpBootUriValid (Option)) {
        DPRINTF_LO_ENUM (" Boot URI is valid, skip it.\n");
        continue;
      }

      DPRINTF_LO_ENUM ( "  0x%x children found\n", NumberDevicePaths);
      FillSlot = FALSE;
      DevicePath = DevicePaths;
      for (j = 0; j < NumberDevicePaths; j++, DevicePath = NextDevicePath (DevicePath)) {
        DEBUG_LO_ENUM (
          Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
          DPRINTF_LO_ENUM ("  DevicePath %s.\n", Str);
          SafeFreePool (Str);
        )

        if (IsIgnoreBootDevicePath (DevicePath)) {
          DPRINTF_LO_ENUM ("  Device path is in ingored list.\n");
          continue;
        }

        p = mBootOptionListHead;
        while (TRUE) {
          if (p == NULL) {
            break;
          }

          if (CompareDevicePath (p->FilePathList, DevicePath)) {

            if (!IsPreDefinedLoadOption (p->OptionNumber) &&
              (j + 1) == NumberDevicePaths) {

              DPRINTF_LO_ENUM ("  Pre-defined BootOption is prioritized\n");
              if (!IsProtectedLoadOption (p->OptionNumber)) {

                //
                // Do not delete protected BootOption.
                //

                if (p != NULL){
                  Status = DeleteBootOption (p->OptionNumber);
                } else {
                  DPRINTF_LO_ENUM ("  Error: A NULL pointer pass to DeleteBootOption()!\n");
                }

                if (Status == SCT_STATUS_SUCCESS) {
                  RemoveOption (p);
                }

              }
              FillSlot = TRUE;

            } //  if (!IsPreDefinedLoadOption (p->OptionNumber) &&
            break;
          } // if (CompareDevicePath (p->FilePathList, DevicePath)) {
          p = p->Next;
        } // while (TRUE) {

        Status = FindSctBootOptionEntry (
                   &AllSctBootOptions,
                   DevicePath);
        DPRINTF_LO_ENUM ("FindSctBootOptionEntry, Status=%r \n", Status);

        if (EFI_ERROR (Status)) {
          DPRINTF_LO_ENUM ("Can't find entry, get Next\n");
          continue;
        }

        if (FillSlot || p == NULL) {
          break;
        }
      } // for (j = 0; j < NumberDevicePaths; j++, DevicePath = NextDevicePath (DevicePath)

      if (j == NumberDevicePaths) {
        DPRINTF_LO_ENUM ("j == NumberDevicePaths\n");
        continue;
      }
      DPRINTF_LO_ENUM ("Go\n");
    } // if (IsDeviceNodeBootOptionProtocol (DevicePath)) {

    //
    // If DevicePath is not identical to NULL, fill the pre-defined BootOption.
    //

    ChildListHead = NULL;
    if (DevicePath != NULL) {

      DPRINTF_LO_ENUM ("Fill pre-defined BootOption\n");
      Status = RemoveSctBootOptionEntry (
                 &AllSctBootOptions,
                 DevicePath,
                 &ChildListHead);

      if (EFI_ERROR (Status)) {
        SafeFreePool (DevicePaths);
        continue;
      }

      if (ChildListHead != NULL) {
        DPRINTF_LO_ENUM ("  Children->Description =  %s.\n",
        ChildListHead->Description);

        OptionalData = NULL;
        OptionalDataLength = 0;

        //
        // Default Optional data will record the GUID of supported groups.
        //

        GroupGuid = NULL;
        Status = GetDeviceGroupGuid (ChildListHead->ChildIndex, &GroupGuid);
        if (!EFI_ERROR (Status)) {
          OptionalDataLength = sizeof (EFI_GUID);
          OptionalData = AllocateCopyPool (
                           OptionalDataLength,
                           GroupGuid);
        }

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)

        if (IsLegacyBootOnlyDevice (DevicePath)) {
          DPRINTF_LO_ENUM ("  Legacy Boot Only device.\n");
          DevicePath = ChildListHead->FilePathList;
          Status = PrepareBbsBootOption (
                     &(ChildListHead->FilePathList),
                     ChildListHead->Description,
                     &OptionalDataLength,
                     (UINT8**)&OptionalData);
          if (EFI_ERROR (Status)) {
            return SCT_STATUS_OUT_OF_RESOURCES;
          }
          SafeFreePool (DevicePath);
          DevicePath = ChildListHead->FilePathList;
        }
#endif

        BufferSize = StrSize (Option->Description);
        BufferSize += StrSize (ChildListHead->Description);
        Description = AllocateZeroPool (BufferSize);

        StrCpyS (Description, BufferSize / sizeof (CHAR16), Option->Description);
        StrCatS (Description, BufferSize / sizeof (CHAR16), L" ");
        StrCatS (Description, BufferSize / sizeof (CHAR16), ChildListHead->Description);

        //
        // Update the content of pre-defined BootOption.
        //

        Status = CreateOption (
                   Option->OptionNumber,
                   Option->OptionType,
                   Option->Attributes,
                   Description,
                   DevicePath,
                   OptionalDataLength,
                   OptionalData,
                   NULL);

        SafeFreePool (OptionalData);
        SafeFreePool (DevicePaths);
        FreeSctBootOptionList (ChildListHead);
      } // if (ChildListHead != NULL) {
    } // if (DevicePath != NULL) {
  } // for (i = 0; i < NumberOfOptions; i++) {

  SafeFreePool (PreDefinedBootOptions);

  //
  // Validate the BootOrder variable.
  //

  DPRINTF_LO_ENUM ("\n4 - Validate the BootOrder variable.\n");
  Status = ValidateOrderVariable (EFI_BOOT_ORDER_VARIABLE_NAME, SCT_BM_LO_BOOT);

  //
  // Get the current BootOrder.
  //

  NumberOfOptions = sizeof (UINT16) * CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER;
  Status = gRT->GetVariable (
                  EFI_BOOT_ORDER_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  &TempAttributes,
                  &NumberOfOptions,
                  LocalBootOrder);

  if (EFI_ERROR (Status)) {
    DPRINTF_LO_ENUM ("  Couldn't get BootOrder variable, %r.\n", Status);
    NumberOfOptions = 0;
  } else {
    TempAttributes = EFI_VARIABLE_NON_VOLATILE |
                     EFI_VARIABLE_BOOTSERVICE_ACCESS |
                     EFI_VARIABLE_RUNTIME_ACCESS;
    NumberOfOptions = NumberOfOptions / sizeof (UINT16);
    DPRINTF_LO_ENUM (" Current BootOrder size 0x%x\n", NumberOfOptions);
  }

  //
  // Remove the occupied or duplicated SctBootOption.
  //

  DPRINTF_LO_ENUM ("\n5 - Remove the duplicated DevicePath from list.\n");
  for (i = 0; i < NumberOfOptions; i++) {
    Status = GetOption (LocalBootOrder [i], SCT_BM_LO_BOOT, &Option);
    if (EFI_ERROR (Status)) {
      continue;
    }
    DevicePath = Option->FilePathList;

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
    if (Option->FilePathList->Type == BBS_DEVICE_PATH &&
        Option->FilePathList->SubType == BBS_BBS_DP) {
      if (Option->OptionalDataLength > (sizeof (BBS_TABLE) + sizeof (UINT16))) {
        BufferPtr = Option->OptionalData;
        BufferPtr += sizeof (BBS_TABLE) + sizeof (UINT16);
        DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)BufferPtr;
      }
    }
#endif

    while (TRUE) {
      Status = RemoveSctBootOptionEntry (
                 &AllSctBootOptions,
                 DevicePath,
                 NULL);
      if (EFI_ERROR (Status)) {
        break;
      }
    }
  }

  //
  // Remove the duplicated DevicePath from the list.
  //

  q = &AllSctBootOptions;
  while (TRUE) {
    if ((*q) == NULL) {
      break;
    }
    RemoveSctBootOptionEntry (&((*q)->Next), (*q)->FilePathList, NULL);
    q = &((*q)->Next);
  }

  DPRINTF_LO_ENUM ("\n6 - Add the new BootOption into BootOrder.\n");
  q = &AllSctBootOptions;
  while (TRUE) {
    if ((*q) == NULL) {
      break;
    }

    DEBUG_LO_ENUM (
      Str = BM_CONVERT_DEVICE_PATH_TO_TEXT ((*q)->FilePathList, FALSE, TRUE);
      DPRINTF_LO_ENUM ("   FilePathList %s.\n", Str);
      SafeFreePool (Str);
    )

    //
    // Create one BootOption (Boot####) for this device.
    //

    OptionalData = NULL;
    OptionalDataLength = 0;
    DevicePath = (*q)->FilePathList;

    //
    // Default optional data will record the GUID of the supported group.
    //

    GroupGuid = NULL;
    Status = GetDeviceGroupGuid ((*q)->ChildIndex, &GroupGuid);
    if (!EFI_ERROR (Status)) {
      DPRINTF_LO_ENUM (" Prepare optional data (Group GUID) for BootOption\n");
      OptionalDataLength = sizeof (EFI_GUID);
      OptionalData = AllocateCopyPool (
                       OptionalDataLength,
                       GroupGuid);
    }

    DPRINTF_LO_ENUM ( "   Description = %s \n", (*q)->Description);

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
    if (IsLegacyBootOnlyDevice (DevicePath)) {

      DPRINTF_LO_ENUM ("  Legacy Boot Only device.\n");
      Status = PrepareBbsBootOption (
                 &((*q)->FilePathList),
                 (*q)->Description,
                 &OptionalDataLength,
                 (UINT8**)&OptionalData);
      if (EFI_ERROR (Status)) {
        return SCT_STATUS_OUT_OF_RESOURCES;
      }
      SafeFreePool (DevicePath);
      DevicePath = (*q)->FilePathList;
    }
#endif

    //
    // Append the prefix to device description string.
    //

    NewOption = 0;
    BufferSize = StrLen (GetDeviceGroupPrefix ((*q)->ChildIndex)) << 1;
    BufferSize += StrLen ((*q)->Description) << 1;

    //
    // Add additional size for terminator character.
    //

    BufferSize += sizeof (CHAR16);
    Description = AllocateZeroPool (BufferSize);

    UnicodeSPrint (
      Description,
      BufferSize,
      L"%s%s",
      GetDeviceGroupPrefix ((*q)->ChildIndex),
      (*q)->Description);

    Status = CreateNewOption (
               &NewOption,
               SCT_BM_LO_BOOT,
               LOAD_OPTION_ACTIVE | LOAD_OPTION_CATEGORY_BOOT | LOAD_OPTION_BIOS_CREATE,
               Description,
               DevicePath,
               OptionalDataLength,
               (UINT8 *)OptionalData,
               &Option);
    DPRINTF_LO_ENUM ("  CreateNewOption returned %r.\n", Status);

    if (Status == EFI_UNSUPPORTED && (Option != NULL) && IsLoadOptionDuplicated (Option, &NewOption)) {
      DPRINTF_LO_ENUM ("  Created new option is duplicated as option 0x%x.\n", NewOption);
      DestroyOption (Option);
    }

    SafeFreePool (OptionalData);
    SafeFreePool (Description);

    if ((NumberOfOptions + 1) < CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER) {

      DPRINTF_LO_ENUM ("  BootOrder [%d] = %s\n", NumberOfOptions, (*q)->Description);

      LocalBootOrder [NumberOfOptions++] = NewOption;

    } else {

      DPRINTF_LO_ENUM ("  Max BootOrder limitation.\n");
      Status = SCT_STATUS_OUT_OF_RESOURCES;
      break;
    }

    q = &((*q)->Next);
  }

  //
  // Freed all SCT_BOOT_OPTION_NODE objects.
  //

  DPRINTF_LO_ENUM ("FreeSctBootOptionList\n");
  FreeSctBootOptionList (AllSctBootOptions);

  //
  // Save the updated BootOrder variable.
  //

  Status = gRT->SetVariable (
                  EFI_BOOT_ORDER_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  TempAttributes,
                  NumberOfOptions * sizeof (UINT16),
                  LocalBootOrder);

  DPRINTF_LO_ENUM ("\n7 - End of LoadOption Enumeration.\n");
  mEnumerateAllHappened = TRUE;

  return Status;

} // EnumerateAllLoadOptions

//
// FUNCTION NAME.
//      RecoverBootOption - Recover one BootOption as valid.
//
// FUNCTIONAL DESCRIPTION.
//      This function will recover the FilePathList of one BootOption according to
//      the comparison of description string.
//      Since the BootOption enumeration will be executed *ONLY* when entering
//      BootPage or BootMenu so the FilePathList could be invalid (ex:the original
//      USB MSD connects to different port) so BootManager will try to update the
//      FilePathList based on the description strings of all present devices in the
//      system.
//
// ENTRY PARAMETERS.
//      OptionNumber    - UINT16 Boot Option Number.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
RecoverBootOption (IN UINT16 OptionNumber)
{
  BOOLEAN Found;
  SCT_STATUS Status;
  UINT8 GroupIndex;
  CHAR16 *Description;
  PLOAD_OPTION_OBJECT p;
  EFI_HANDLE *BlockIoHandles;
  UINTN i, NumberBlockIoHandles;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  Status = GetBootOption (OptionNumber, &p);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DPRINTF_LO_ENUM ("  Original BootOption:");
  DISPLAY_OPTION_INFORMATION (p, L"   ");

  //
  // Initialize the local variables.
  //

  BlockIoHandles = NULL;
  NumberBlockIoHandles = 0;
  Found = FALSE;
  DevicePath = NULL;
  Description = NULL;

  //
  // We only compare those devices that EFI_BLOCK_IO_PROTOCOL installed so far.
  //

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &NumberBlockIoHandles,
                  &BlockIoHandles);

  if (EFI_ERROR (Status) || NumberBlockIoHandles == 0) {
    return SCT_STATUS_NOT_FOUND;
  }

  for (i = 0; i < NumberBlockIoHandles; i++) {
    DevicePath = DevicePathFromHandle (BlockIoHandles [i]);

    DEBUG_LO_ENUM ({
      CHAR16* Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
      DPRINTF_LO_ENUM ("   DevicePath [%s]\n", Str);
      SafeFreePool (Str);
    });

    GroupIndex = 0;
    Description = NULL;
    if (IsSupportedBootDevice (DevicePath, &Description, &GroupIndex)) {
      CHAR16 *GroupPrefix = GetDeviceGroupPrefix (GroupIndex);
      //
      // Compare the GroupPrefix string.
      //
      if ( (Description[0] != L'\0') && (StrStr (p->Description, GroupPrefix) != NULL) ) {
        DPRINTF_LO_ENUM ("  GroupPrefix is partial matched\n");
        DPRINTF_LO_ENUM ("   p->Description       = [%s] (%d)\n", p->Description, p->DescriptionLength/2);
        DPRINTF_LO_ENUM ("   p->Attributes        = [%x]\n", p->Attributes);
        DPRINTF_LO_ENUM ("  GroupPrefix           = [%s] (%d)\n", GroupPrefix, GroupIndex);
        DPRINTF_LO_ENUM ("      Description       = [%s]\n", Description);
        DPRINTF_LO_ENUM ("GroupPrefix+Description = [%s%s]\n", GroupPrefix, Description);
        SafeFreePool (Description);
        Found = TRUE;
        break;
      }
    }
    SafeFreePool (Description);
  }
  //
  // Freed the allocated resources.
  //
  SafeFreePool (BlockIoHandles);

  Status = EFI_NOT_FOUND;
  if (Found) {
    //
    // Update the original BootOption in DB.
    //
    DPRINTF_LO_ENUM ("  Update the original BootOption[0x%04x] in [%s](%d)\n",
      p->OptionNumber, p->Description, p->DescriptionLength/2);
    Status = CreateOption (
               p->OptionNumber,
               p->OptionType,
               p->Attributes,
               p->Description,
               DevicePath,
               p->OptionalDataLength,
               p->OptionalData,
               NULL);
  }

  return Status;
} // RecoverBootOption

//
// FUNCTION NAME.
//      UpdateLoadOptionCrcTable - Update LoadOption CRC table.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help to update LoadOption CRC table.
//
// ENTRY PARAMETERS.
//      OrgCrcValue     - original CRC value.
//      NewCrcValue     - new CRC value.
//
// EXIT PARAMETERS.
//      Function Return - EFI_STATUS Code.
//

EFI_STATUS
EFIAPI
UpdateLoadOptionCrcTable (
  IN UINT32 OrgCrcValue,
  IN UINT32 NewCrcValue
  )
{
  UINTN i;
  UINT32 *CrcTable;
  EFI_STATUS Status;
  UINTN CrcTableSize;
  UINT32 Attributes;

  DPRINTF_LO_ENUM (" UpdateLoadOptionCrcTable OrgCrc = 0x%x, NewCrc = 0x%x\n",
    OrgCrcValue,
    NewCrcValue);

  CrcTableSize = 0;
  CrcTable = NULL;
  Status = SctLibGetVariable (
             L"LoadOptionCrcTable",
             &gSctBdsServicesProtocolGuid,
             &Attributes,
             &CrcTableSize,
             (VOID **)&CrcTable);
  DPRINTF_LO_ENUM ("  Get LoadOptionCrcTable returned %r.\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = EFI_NOT_FOUND;
  for (i = 0; i < CrcTableSize / sizeof (UINT32); i++) {
    DPRINTF_LO_ENUM ("  CrcTable [%d] = 0x%x\n", i, CrcTable [i]);
    if (CrcTable [i] == OrgCrcValue) {
      CrcTable [i] = NewCrcValue;
      Status = EFI_SUCCESS;
    }
  }

  if (EFI_ERROR (Status)) {
    SafeFreePool (CrcTable);
    return Status;
  }

  DPRINTF_LO_ENUM ("  Update LoadOption CRC table\n");
  Status = gRT->SetVariable (
                  L"LoadOptionCrcTable",
                  &gSctBdsServicesProtocolGuid,
                  Attributes,
                  CrcTableSize,
                  (VOID *)CrcTable);
  SafeFreePool (CrcTable);
  return Status;
} // UpdateLoadOptionCrcTable

//
// FUNCTION NAME.
//      GetBootOptionNumberByCrc - Get specific BootOption number via CRC value.
//
// FUNCTIONAL DESCRIPTION.
//      This function will search the specific BootOption via comparing the CRC value.
//
// ENTRY PARAMETERS.
//      Crc             - current CRC value of the BootOption.
//
// EXIT PARAMETERS.
//      Function Return - EFI_STATUS Code.
//      OptionNumber    - the associated option number.
//

EFI_STATUS
EFIAPI
GetBootOptionNumberByCrc (
  IN UINT32 Crc,
  OUT PUINT16 OptionNumber
  )
{
  PLOAD_OPTION_OBJECT p;

  p = mBootOptionListHead;
  while (TRUE) {
    if (p == NULL) {
      break;
    }
    if (p->RawCrc == Crc) {
      *OptionNumber = p->OptionNumber;
      return EFI_SUCCESS;
    }
    p = p->Next;
  }

  return EFI_NOT_FOUND;
} // GetBootOptionNumberByCrc


#if 0
//
// FUNCTION NAME.
//      EnumerateAllBootOptions - Search all device paths for bootable devices.
//
// FUNCTIONAL DESCRIPTION.
//      This function looks at each handle supporting the device path protocol
//      and identifies potentially bootable devices.
//
//      Each handle will be examined for the protocols which could result in a
//      bootable device. These protocols are:
//              EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
//              EFI_LOAD_FILE_PROTOCOL
//              EFI_BLOCK_IO_PROTOCOL
//
//      Each handle which supports a potentially bootable protocol will be
//      converted into a boot load option and added to the store if there does
//      not exist an option in the store that has the same device path as this
//      handle.
//
//      Here is the applicable text from the UEFI Specification, Version 2.3,
//      Section 3.3:
//              If no valid boot options exist, the boot manager will enumerate
//              all removable media devices followed by all fixed media devices.
//              The order within each group is undefined. These new default boot
//              options are not saved to non volatile storage. The boot manager
//              will then attempt to boot from each boot option.
//      The Boot Manager defines a configuration option that controls if these
//      enumerated options are saved or not.
//
//      Generally, this function will not be used if Boot Option Protocols are
//      used to abstract device paths. The enumeration happens in the Boot
//      Option Protocol instances instead.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
EFIAPI
EnumerateAllBootOptions (VOID)
{
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  UINTN i;
  SCT_STATUS Status ;
  UINTN NumberOfHandles;
  EFI_HANDLE *HandleBuffer;
  UINT16 NewOption;
  UINT16 LocalBootOrder [CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER]; // copy of BootOrder Variable.
  UINTN NumberOfOptions;                // the number of elements in
                                        // the LocalBootOrder array.
  UINT32 TempAttributes;

  DPRINTF_LO ("EnumerateAllBootOptions:\n");

  //
  // Get the current BootOrder or initialize LocalBootOrder.
  //

  NumberOfOptions = sizeof (UINT16) * CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER;
  Status = gRT->GetVariable (
                  EFI_BOOT_ORDER_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  &TempAttributes,
                  &NumberOfOptions,
                  LocalBootOrder);
  if (EFI_ERROR (Status)) {
    DPRINTF_LO ("  Couldn't get BootOrder variable, %r.\n", Status);
    NumberOfOptions = 0;
  } else {
    TempAttributes = EFI_VARIABLE_NON_VOLATILE |
                     EFI_VARIABLE_BOOTSERVICE_ACCESS |
                     EFI_VARIABLE_RUNTIME_ACCESS;
    NumberOfOptions = NumberOfOptions / sizeof (UINT16);
  }

  //
  // Add any new removable media.
  //

  Status = GetRemovableBlockIo (&NumberOfHandles, &HandleBuffer);
  DPRINTF_LO ("  GetRemovableBlockIo returned %r, NumberOfHandles = 0x%x, HandleBuffer @ 0x%x.\n",
    Status, NumberOfHandles, HandleBuffer);
  if (!EFI_ERROR (Status)) {
    for (i = 0; i < NumberOfHandles; i++) {
      Status = AddOptionByHandle (HandleBuffer [i], &NewOption);
      if (EFI_ERROR (Status)) {
        DPRINTF_LO ("  AddOptionByHandle returned %r.\n", Status);
        continue;
      }
      if ((NumberOfOptions + 1) < CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER) {
        LocalBootOrder [NumberOfOptions++] = NewOption;
      } else {
        DPRINTF_LO ("  Out of options, increase CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER.\n");
        return SCT_STATUS_OUT_OF_RESOURCES;
      }
    }
  SafeFreePool (HandleBuffer);
  }

  //
  // Add any new Simple File System or Load File supporting handles.
  //

  Status = GetNonRemovableMediaBootableDevices (&NumberOfHandles, &HandleBuffer);
  DPRINTF_LO ("  GetNonRemovableMediaBootableDevices returned %r, NumberOfHandles = 0x%x, HandleBuffer @ 0x%x.\n",
    Status, NumberOfHandles, HandleBuffer);
  if (!EFI_ERROR (Status)) {
    for (i = 0; i < NumberOfHandles; i++) {
      Status = AddOptionByHandle (HandleBuffer [i], &NewOption);
      if (EFI_ERROR (Status)) {
        DPRINTF_LO ("  AddOptionByHandle returned %r.\n", Status);
        continue;
      }
      if ((NumberOfOptions + 1) < CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER) {
        LocalBootOrder [NumberOfOptions++] = NewOption;
      } else {
        DPRINTF_LO ("  Out of options, increase CONFIG_SYSTEM_BOOT_MANAGER_MAX_BOOT_ORDER.\n");
        return SCT_STATUS_OUT_OF_RESOURCES;
      }
    }
  SafeFreePool (HandleBuffer);
  }

  //
  // Save the BootOrder variable.
  //

  Status = gRT->SetVariable (
                  EFI_BOOT_ORDER_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  TempAttributes,
                  NumberOfOptions * sizeof (UINT16),
                  LocalBootOrder);
  return Status;

#else
  return SCT_STATUS_UNSUPPORTED;
#endif
} // EnumerateAllBootOptions
#endif

#if 0 // OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
//
// FUNCTION NAME.
//      RebuildOptionByCrc - Rebuild the Boot Option if the CRC value is not same as CRCTable.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called during driver initialization to initialize
//      the load option database.
//
//      Windows OS restore Boot####, so maybe the Boot Option is not same as this platform behavior.
//      If the Boot Option Crc value is not same as LoadOptionCrctable, system rebuild it.
//
// ENTRY PARAMETERS.
//      Option          - a pointer to PLOAD_OPTION_OBJECT.
//      CrcTable        - a pointer to CrcTable.
//      PreDefinedLoadOptions - a pointer to PreDefinedLoadOptions.
//      PreDefineLength - the length of PreDefineLoadOptions.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

BOOLEAN
EFIAPI
RebuildOptionByCrc (
  PLOAD_OPTION_OBJECT Option,
  UINT32 *CrcTable,
  UINT16 *PreDefinedLoadOptions,
  UINT16 PreDefineLength,
  PUINT16 BootOrder,
  UINTN BootOrderSize
  )
{
  UINTN i;
  UINT8 Index;
  BOOLEAN IsRebuild;
  SCT_STATUS Status;
  CHAR16 VariableName [9];             // Boot####\0 is longer than Boot####\0.
  PBOOT_MANAGER_CONFIGURATION p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  Index = 0;
  IsRebuild = FALSE;
  while (TRUE) {
    p = &mBootManagerConfigurationTable [Index];

    if (p->Flags & SCT_BM_FLAGS_END) {
      break;
    }
    DPRINTF_LO (" Index = 0x%x\n", Index);
    if (((UINT16)Index + CONFIG_SYSTEM_BOOT_MANAGER_LOAD_OPTION_START_NUMBER) == Option->OptionNumber) {
      if ((p->Flags & SCT_BM_PRE_DEFINED_SLOT) == 0) {
        return FALSE;
      } // if ((p->Flags & SCT_BM_PRE_DEFINED_SLOT) == 0) {
      for (i = 0; i < PreDefineLength; i++) {
        if (Option->OptionNumber == PreDefinedLoadOptions [i]) {
          if (Option->RawCrc == CrcTable [i]) {
            return FALSE;
          } else {

            //
            // if Crc doesn't match, we need to rebuild BootOption by BmConfigTable.
            // Because Win10 maybe set incorrect Boot#### variable.
            //

            DevicePath = NULL;
            DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
            Status = CreateOption (
                       Option->OptionNumber,
                       p->OptionType,
                       p->OptionAttributes,
                       p->Description,
                       DevicePath,
                       0,
                       NULL,
                       NULL);

            SafeFreePool (DevicePath);
            if (!EFI_ERROR (Status)) {

              //
              // Update LoadOption CRC table.
              //

              if (CrcTable [i] != Option->RawCrc) {
                UpdateLoadOptionCrcTable (CrcTable [i], Option->RawCrc);
              }

              return TRUE;
            }
          } // if (Option->RawCrc == CrcTable [i]) {

        } // if (Option->OptionNumber == PreDefinedLoadOptions [i]) {
      } // for (i = 0; i < PreDefineLength; i++) {
    } // if ((UINT16)Index + CONFIG_SYSTEM_BOOT_MANAGER_LOAD_OPTION_START_NUMBER)) == Option->OptionNumber)
    Index++;
  } // while (TRUE)

  //
  // if OptionNumber is not exist in BmConfigTable, but Description is exist we need to remove it.
  //

  if ((StrnCmp (Option->Description, CONFIG_BootGroupingTab_USB_HDD, StrLen (CONFIG_BootGroupingTab_USB_HDD)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_USB_CD, StrLen (CONFIG_BootGroupingTab_USB_CD)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_USB_FDD, StrLen (CONFIG_BootGroupingTab_USB_FDD)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_ATA_HDD, StrLen (CONFIG_BootGroupingTab_ATA_HDD)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_ATAPI_CD, StrLen (CONFIG_BootGroupingTab_ATAPI_CD)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_PCI_LAN, StrLen (CONFIG_BootGroupingTab_PCI_LAN)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_USB_LAN, StrLen (CONFIG_BootGroupingTab_USB_LAN)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_PCI_SCSI, StrLen (CONFIG_BootGroupingTab_PCI_SCSI)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_SD_Card, StrLen (CONFIG_BootGroupingTab_SD_Card)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_eMMC_Card, StrLen (CONFIG_BootGroupingTab_eMMC_Card)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_BEV, StrLen (CONFIG_BootGroupingTab_BEV)) == 0) ||
    (StrnCmp (Option->Description, CONFIG_BootGroupingTab_NVMe, StrLen (CONFIG_BootGroupingTab_NVMe)) == 0)) {

    for (i = 0; i < BootOrderSize / sizeof (UINT16); i++) {
      if (BootOrder [i] == Option->OptionNumber) {
        return FALSE;
      }
    } // for (i = 0; i < BootOrderSize / sizeof (UINT16); i++) {
    UnicodeSPrint (VariableName, sizeof (VariableName), L"Boot%04x", Option->OptionNumber);
    SetEfiGlobalVariable (
      VariableName,
      EFI_VARIABLE_NON_VOLATILE|
      EFI_VARIABLE_BOOTSERVICE_ACCESS|
      EFI_VARIABLE_RUNTIME_ACCESS,
      0,
      NULL);
    RemoveOption (Option);

    if (Option != NULL)
      DestroyOption (Option);

    IsRebuild = TRUE;

  }
  return IsRebuild;
} // RebuildOptionByCrc

#endif// OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

#if 0 //OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
//
// FUNCTION NAME.
//      IsHttpBootDevice - Check if DevicePath is for http boot.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the input device path is for http boot
//      only.
//
// ENTRY PARAMETERS.
//      DevicePath      - Device path to be checked.
//
// EXIT PARAMETERS.
//      Boolean         - If TRUE, Legacy Boot Only.
//

BOOLEAN
IsHttpBootDevice (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  EFI_HANDLE Handle;
  SCT_STATUS Status;
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  if (DevicePath == NULL) {
    return FALSE;
  }

  if (IsDevicePathEnd (DevicePath)) {
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
  // Must support URI device path.
  //

  if (LastNode->Type == MESSAGING_DEVICE_PATH) {

    if (LastNode->SubType != MSG_URI_DP) {
      return FALSE;
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

  //
  // Must be totally matched.
  //

  if (!EFI_ERROR (Status) && IsDevicePathEnd (RemainingDevicePath)) {
    return TRUE;
  }

  return FALSE;
} // IsHttpBootDevice

#endif //OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
