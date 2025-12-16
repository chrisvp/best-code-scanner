//
// FILENAME.
//      Variable.c - SecureCore Technology(TM) Efi Global Variable Services Module.
//
// FUNCTIONAL DESCRIPTION.
//      This module provides variable services for Efi Global Variables.
//
//      The runtime services for accessing variables are difficult to use.
//      This module provides wrapper functions that handle memory allocation
//      and other tedious tasks.
//
//      These functions are all specific to the gEfiGlobalVariableGuid
//      name space.
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

static PBM_VARIABLE mBmVariableListHead = NULL;

//
// Prototypes for functions in other modules that are a part of this component.
//

extern
BOOLEAN
EFIAPI
RequiresProjectLoad (VOID);

//
// Data shared with other modules *within* this component.
//

//
// Data defined in other modules and used by this module.
//

#if OPTION_SYSTEM_BOOT_MANAGER_CACHE_ESSENTIAL_VARIABLES

extern EFI_BOOT_MODE mBootMode;

#endif

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      InitializeVariable - Initialize Variable Module.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called during driver initialization to initialize
//      the variable services.
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
EFIAPI
InitializeVariable (VOID)
{
  DPRINTF_INIT ("InitializeVariable.\n");
  return SCT_STATUS_SUCCESS;
} // InitializeVariable


//
// FUNCTION NAME.
//      SetEfiGlobalVariable - Wrapper function for gRT->SetVariable.
//
// FUNCTIONAL DESCRIPTION.
//      This function sets a variable in the gEfiGlobalVariableGuid
//      name space.
//
// ENTRY PARAMETERS.
//      VariableName    - a pointer to a CHAR16 string for the variable name.
//      Attributes      - the variable attributes.
//      DataSize        - the size of the variable data.
//      Data            - a pointer to the variable data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
SetEfiGlobalVariable (
  IN PCHAR16 VariableName,
  IN UINT32 Attributes,
  IN UINTN DataSize,
  IN PVOID Data
  )
{
  DPRINTF_VAR ("SetEfiGlobalVariable:%s.\n", VariableName);
  return gRT->SetVariable (
                VariableName,
                &gEfiGlobalVariableGuid,
                Attributes,
                DataSize,
                Data);
} // SetEfiGlobalVariable

//
// FUNCTION NAME.
//      IsOptionVariable - Check a variable name to see if it is an option.
//
// FUNCTIONAL DESCRIPTION.
//      UEFI Specification, Version 2.3, Chapter 3 defines three kind of
//      global variables that follow the same conventions, but have dynamic
//      names. The option variables all take the form prefix#### where ####
//      is a text representation of a 16-bit hex number.
//
//      There are three prefixes described in the specification:
//              Driver  - driver load options.
//              Boot    - boot load options.
//              Key     - hotkey options.
//
// ENTRY PARAMETERS.
//      Prefix          - a pointer to a Unicode string for the option prefix.
//      VariableName    - a pointer to a Unicode string for the variable name.
//
// EXIT PARAMETERS.
//      Function Return - TRUE if this variable was an option, else FALSE.
//      OptionNumber    - the integer value of ####.
//

BOOLEAN
EFIAPI
IsOptionVariable (
  IN PCHAR16 Prefix,
  IN PCHAR16 VariableName,
  OUT PUINT16 OptionNumber OPTIONAL
  )
{
  PCHAR16 p, q;
  UINTN i;
  UINT8 n;
  UINT16 tOptionNumber;

  DPRINTF_VAR ("IsOptionVariable:%s, %s.\n", Prefix, VariableName);

  //
  // First match the prefix part, "Driver", "Boot" or "Key".
  //

  p = VariableName;
  q = Prefix;
  while (TRUE) {
    if (!*p) {
      return FALSE;
    }
    if (!*q) {
      break;                            // prefix matched.
    }
    if (*p != *q) {
      return FALSE;
    }
    p++;
    q++;
  }

  //
  // Match the number part, "####". Four hex numbers define the option number.
  // The spec defines exactly four hex number with printable hexadecimal representation
  // using the digits 0-9, and the upper case versions of the characters A-F (0000-FFFF).
  //

  tOptionNumber = 0;
  for (i = 0; i < 4; i++) {
    if (!*p) {
      return FALSE;
    }

    //
    // [0-9A-F]{4}.
    //

    if ((*p >= L'0') && (*p <= L'9')) {
      n = (UINT8)(*p - L'0');
    } else if ((*p >= L'A') && (*p <= L'F')) {
      n = (UINT8)(*p - L'A' + 0x0A);
    } else {
      return FALSE;
    }
    tOptionNumber <<= 4;                // move over one nibble.
    tOptionNumber = tOptionNumber + n;
    p++;
  }

  //
  // p should point to the end of the string now.
  //

  if (*p) {
    return FALSE;
  }

  //
  // Provide the option number if the caller asked for it.
  //

  if (OptionNumber != NULL) {
    *OptionNumber = tOptionNumber;
  }
  DPRINTF_VAR ("IsOptionVariable:TRUE 0x%x.\n", tOptionNumber);
  return TRUE;
} // IsOptionVariable

#if OPTION_SYSTEM_BOOT_MANAGER_CACHE_ESSENTIAL_VARIABLES
//
// FUNCTION NAME.
//      StoreOptionNumbers - Save one of the Boot####, Key####, and Driver#### variable names.
//
// FUNCTIONAL DESCRIPTION.
//      This function traverses the mBmVariableListHead linked list, and creates
//      an array of integers.  The first integer is the number of integers we
//      stored.  Integers after the count are the number portion of
//      a Boot####, Key####, or Driver#### variable.  The passed-in OptionType
//      determines which variable we will process.  The output array is formatted
//      as {OptionCount,nnnn,...} .  We return a pointer to one place past the
//      last data we stored, so if we are called N times, the result is
//      N concatenated first-word-length arrays.
//
// ENTRY PARAMETERS.
//      EntryPtr    - Points to the count word of the array we will populate.
//      OptionType  - Which BM_VARIABLE structures to process.
//      mBmVariableListHead -> linked list of BM_VARIABLE structures.
//
// EXIT PARAMETERS.
//      Function Return - Pointer past last UINT16 we stored.
//

UINT16 *
StoreOptionNumbers (
  OUT UINT16 *EntryPtr,
  IN UINT8 OptionType
)
{
  BM_VARIABLE *p;
  UINT16 *CountPtr;

  p = mBmVariableListHead;
  CountPtr = EntryPtr++;
  *CountPtr = 0;
  while (p != NULL) {                   // Step through BM_VARIABLE list.
    if (p->OptionType == OptionType) {
      *EntryPtr++ = p->OptionNumber;
      (*CountPtr)++;                    // Increment FWL name count.
    }
    p = p->Next;
  }
  return EntryPtr;
} // StoreOptionNumbers

//
// FUNCTION NAME.
//      SaveNames - Save the Boot####, Key####, and Driver#### variable names.
//
// FUNCTIONAL DESCRIPTION.
//      This function traverses the mBmVariableList linked list, and creates
//      an array of integers, where each integer is the number portion of
//      a Boot####, Key####, or Driver#### variable.  The format of the array
//      is { {BootCount,bbbb,...} {KeyCount,kkkk,...} {DriverCount,dddd,...} } .
//      This array is then stored in variable "BmEssentialVariableNames", for
//      use during S4 resume.  At that time, mBmVariableList is created by
//      BuildListFromNames, which calls GetVariable on the names in
//      BmEssentialVariableNames.  This saves time because we don't have to
//      scan every name in the variable space.
//
// ENTRY PARAMETERS.
//      mBmVariableListHead -> linked list of BM_VARIABLE structures.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

VOID
SaveNames (VOID)
{
  EFI_STATUS Status;
  UINTN EntryCount;
  UINT16 *EntryBase;
  UINT16 *EntryPtr;
  UINTN EntryArrayBytes;
  BM_VARIABLE *p;

  //
  // If we can tell Boots, Keys, and Drivers apart,
  // we don't need to save the entire name, just its number.
  //
  // The array we're going to save is three concatenated
  // UINT16 arrays, each one first-word-length.
  //

  //
  // Count BM_VARIABLEs so we can allocate the array.
  //

  EntryCount = 0;
  p = mBmVariableListHead;
  while (p != NULL) {
    EntryCount++;
    p = p->Next;
  }

  if (EntryCount == 0) {                // No BM_VARIABLES, delete cache.
    gRT->SetVariable (
           L"BmEssentialVariableNames",
           &gSctBdsServicesProtocolGuid,
           EFI_VARIABLE_NON_VOLATILE |
           EFI_VARIABLE_BOOTSERVICE_ACCESS |
           EFI_VARIABLE_RUNTIME_ACCESS,
           0,
           NULL);
    return;
  }

  //
  // One UINT16 per BM_VARIABLE, plus one to record the count of each type.
  //

  EntryArrayBytes = (EntryCount+SCT_BM_LO_MAX_TYPE) * sizeof (UINT16);

  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  EntryArrayBytes,
                  (VOID **) &EntryBase);
  if (EFI_ERROR (Status)) {
    return;
  }

  //
  // Store nnnn from each Boot####, keeping track of how many.
  // All Boot####, then all Key####, then all Driver####.
  //

  EntryPtr = StoreOptionNumbers (EntryBase, BOOT_OPTION_TYPE);
  EntryPtr = StoreOptionNumbers (EntryPtr, KEY_OPTION_TYPE);
  EntryPtr = StoreOptionNumbers (EntryPtr, DRIVER_OPTION_TYPE);
  EntryPtr = StoreOptionNumbers (EntryPtr, SYSPREP_OPTION_TYPE);

  gRT->SetVariable (
         L"BmEssentialVariableNames",
         &gSctBdsServicesProtocolGuid,
         EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_RUNTIME_ACCESS,
         EntryArrayBytes,
         EntryBase);

  SafeFreePool(EntryBase);
} // SaveNames

//
// FUNCTION NAME.
//      BuildEntryFromNumber - Create one BM_VARIABLE from Boot####, Key####, or Driver####.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets one Boot####, Key####, or Driver#### variable,
//      and uses the data to create one BM_VARIABLE in mBmVariableList.
//
// ENTRY PARAMETERS.
//      Format                The variable name: "Boot%04X", "Key%04X", or "Driver%04X".
//      OptionNumber          The number portion of the variable name.
//      OptionType            BOOT_OPTION_TYPE, KEY_OPTION_TYPE, or DRIVER_OPTION_TYPE.
//      p                     Pointer to list to which we should append the BM_VARIABLE.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
BuildEntryFromNumber (
  IN CHAR16 *Format,
  IN UINT16 OptionNumber,
  IN UINT8 OptionType,
  OUT BM_VARIABLE **p
)
{
  EFI_STATUS Status;
  VOID *DataBuffer;
  UINTN DataSize;
  CHAR16 *VariableName;

#define MAX_N_LENGTH 12                 // "SysPrep####\0" is the max length.(Boot####, Key####, Driver####).

  //
  // Allocate ram for the variable name.
  // This ram is freed by FreeBmEssentialVariables.
  //

  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  MAX_N_LENGTH * sizeof(CHAR16),
                  (VOID **) &VariableName);
  if (EFI_ERROR (Status))
    return Status;

  UnicodeSPrint (VariableName, MAX_N_LENGTH * sizeof(CHAR16), Format, OptionNumber);

  //
  // SctLibGetEfiGlobalVariable allocates ram for the variable data.
  // This ram is freed by FreeBmEssentialVariables.
  //

  Status = SctLibGetEfiGlobalVariable (
             VariableName,
             NULL,
             &DataSize,
             (VOID **) &DataBuffer);
  if (EFI_ERROR(Status)) {
    SafeFreePool (VariableName);
    return Status;
  }

  //
  // Allocate ram for a BM_VARIABLE structure.
  // This ram is freed by FreeBmEssentialVariables.
  //

  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  sizeof (BM_VARIABLE),
                  (VOID **) p);
  if (EFI_ERROR (Status)) {
    SafeFreePool (VariableName);
    SafeFreePool (DataBuffer);
    return Status;
  }

  (*p)->OptionType = OptionType;
  (*p)->DataSize = DataSize;
  (*p)->OptionNumber = OptionNumber;
  (*p)->DataBuffer = DataBuffer;
  (*p)->VariableName = VariableName;
  (*p)->Next = NULL;

  DPRINTF_VAR ("  VariableName = %s\n", (*p)->VariableName);
  DPRINTF_VAR ("  OptionType   = %d\n", (*p)->OptionType);
  DPRINTF_VAR ("  DataSize     = 0x%x\n", (*p)->DataSize);
  DPRINTF_VAR ("  OptionNumber = %d\n", (*p)->OptionNumber);
  DPRINTF_VAR ("  DataBuffer   = 0x%x\n\n", (*p)->DataBuffer);

  return EFI_SUCCESS;
} // BuildEntryFromNumber

//
// FUNCTION NAME.
//      BuildListFromNames - BmVariableList from cached Boot####, Key####, or Driver#### names.
//
// FUNCTIONAL DESCRIPTION.
//      This function reads each Boot####, Key####, and Driver#### variable whose name
//      is found in BmEssentialVariableNames, and calls BuildEntryFromName to create
//      the BM_VARIABLE's in mBmVariableList.
//
// ENTRY PARAMETERS.
//      BmEssentialVariableNames exists.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      mBmVariableListHead populated with linked list of BM_VARIABLE's.
//

EFI_STATUS
BuildListFromNames (VOID)
{
  UINTN i;
  EFI_STATUS Status;
  UINT16 *EntryBase;
  UINT16 *EntryPtr;
  UINT16 BootCount;
  UINT16 KeyCount;
  UINT16 DriverCount;
  UINT16 SysPrepCount;
  BM_VARIABLE **p;
  UINTN DataSize;
  PUINT16 OptionOrder;
  BOOLEAN Found;

  DPRINTF_VAR ("\n");
  p = &mBmVariableListHead;

  Status = SctLibGetVariable (
             L"BmEssentialVariableNames",
             &gSctBdsServicesProtocolGuid,
             NULL,                  // don't care about attributes.
             NULL,                  // don't care about size.
             &EntryBase);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  EntryPtr = EntryBase;
  BootCount = *EntryPtr++;

  DPRINTF_VAR ("  Cached BootCount = %d\n", BootCount);

  //
  // Check if all BootOption numbers are cached.
  //

  OptionOrder = NULL;
  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,
             &DataSize,
             (VOID **) &OptionOrder);
  if (!EFI_ERROR (Status)) {
    for (i = 0; i < DataSize / sizeof (UINT16); i++) {

      EntryPtr = EntryBase;
      BootCount = *EntryPtr++;
      Found = FALSE;

      while (BootCount--) {
        if (*EntryPtr++ == OptionOrder [i]) {
          Found = TRUE;
          break;
        }
      }
      if (!Found) {
        SafeFreePool (OptionOrder);
        DPRINTF_VAR ("  Return NOT FOUND\n");
        return EFI_NOT_FOUND;
      }
    }
    SafeFreePool (OptionOrder);
  }

  EntryPtr = EntryBase;
  BootCount = *EntryPtr++;
  while (BootCount--) {
    Status = BuildEntryFromNumber (
                L"Boot%04x",
                *EntryPtr++,
                BOOT_OPTION_TYPE,
                p);
    if (EFI_ERROR(Status))
      goto ErrorExit;

    p = &((*p)->Next);
  }

  KeyCount = *EntryPtr++;
  while (KeyCount--) {
    Status = BuildEntryFromNumber (
                L"Key%04x",
                *EntryPtr++,
                KEY_OPTION_TYPE,
                p);
    if (EFI_ERROR(Status))
      goto ErrorExit;

    p = &((*p)->Next);
  }

  DriverCount = *EntryPtr++;
  while (DriverCount--) {
    Status = BuildEntryFromNumber (
                L"Driver%04x",
                *EntryPtr++,
                DRIVER_OPTION_TYPE,
                p);
    if (EFI_ERROR(Status))
      goto ErrorExit;

    p = &((*p)->Next);
  }

  SysPrepCount = *EntryPtr++;
  while (SysPrepCount--) {
    Status = BuildEntryFromNumber (
               L"SysPrep%04x",
               *EntryPtr++,
               SYSPREP_OPTION_TYPE,
                p);
    if (EFI_ERROR(Status))
      goto ErrorExit;

    p = &((*p)->Next);
  }

ErrorExit:
  SafeFreePool(EntryBase);

  return Status;
} // BuildListFromNames
#endif

//
// FUNCTION NAME.
//      DiscoverBmEssentialVariable - Get the essential variables of BootManager.
//
// FUNCTIONAL DESCRIPTION.
//      This function will retrieve driver load options, boot load options and
//      hotkey options and construct a linkedlist to store them for future usage.
//
// ENTRY PARAMETERS.
//      Force           - Force to discover whole variables in any case.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
DiscoverBmEssentialVariable (IN BOOLEAN Force)
{
  UINTN DataSize;
  PBM_VARIABLE *p;
  VOID* DataBuffer;
  SCT_STATUS Status;
  UINT32 Attributes;
  PCHAR16 VariableName;
  UINT16 OptionNumber;
  UINTN VariableNameSize;
  BOOLEAN IsEssential;
  PCHAR16 CurrentVariableName;

  CurrentVariableName = NULL;
  IsEssential = FALSE;

  DPRINTF_VAR ("\n");

#if OPTION_SYSTEM_BOOT_MANAGER_CACHE_ESSENTIAL_VARIABLES

  //
  // If it's not S4, or if BmEssentialVariableNames does not exist,
  // construct mBmVariableList normally, and also save the names in
  // BmEssentialVariableNames.
  // If it's S4 and BmEssentialVariableNames exists,
  // construct mBmVariableList by calling BuildListFromNames, which calls
  // SctLibGetEfiGlobalVariable with each name stored in BmEssentialVariableNames.
  //
  // There is one corner case where this scheme will create an incorrect list:
  // if the OS creates, deletes, or modifies a Boot####, Key####, or Driver####,
  // then immediately does S4, without an intervening normal POST, the
  // S4 resume will construct BmVariableList based on the previous boot, which
  // does not include the recent changes.  Since most vendors want S4 resume
  // to boot to the previous boot device anyway, this is rarely a problem.
  //

  if (!Force &&
    mBootMode == BOOT_ON_S4_RESUME &&
    BuildListFromNames () == EFI_SUCCESS) {
    DPRINTF_VAR ("  S4 boot path and cached data is correct\n");
    return EFI_SUCCESS;
  }
#endif

  p = &mBmVariableListHead;

  while (TRUE) {

    DataBuffer = NULL;
    VariableName = NULL;
    DataSize = 0;
    VariableNameSize = 0;
    OptionNumber = 0;

    Status = SctLibGetNextEfiGlobalVariable (
               CurrentVariableName,
               &VariableNameSize,
               &VariableName,
               &Attributes,
               &DataSize,
               &DataBuffer);

    if (!IsEssential) {
      SafeFreePool (CurrentVariableName);
    }
    if (EFI_ERROR (Status)) {
      break;
    }
    CurrentVariableName = VariableName;

#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK
#if OPTION_SYSTEM_BOOT_MANAGER_DEFAULT_BOOT_ORDER_CHECK_RESTORE_BOOT_OPTION

    //
    // Throw away "Boot####" and "Key####" option variables if load default is required.
    //

    if (!Force &&
      ((IsOptionVariable (L"Boot", VariableName, &OptionNumber))||
       (IsOptionVariable (L"Key", VariableName, &OptionNumber))) &&
      RequiresProjectLoad ()) {

      IsEssential = FALSE;
      SafeFreePool (DataBuffer);
      continue;

    }
#endif
#endif

    if (IsOptionVariable (L"Boot", VariableName, &OptionNumber) ||
        IsOptionVariable (L"Key", VariableName, &OptionNumber) ||
        IsOptionVariable (L"SysPrep", VariableName, &OptionNumber) ||
        IsOptionVariable (L"Driver", VariableName, &OptionNumber)) {

      Status = (gBS->AllocatePool) (
                      EfiBootServicesData,
                      sizeof (BM_VARIABLE),
                      (VOID **) p);

      if (EFI_ERROR (Status)) {
        return EFI_OUT_OF_RESOURCES;
      }

      if (StrStr (VariableName, L"Boot") != NULL) {

        (*p)->OptionType = BOOT_OPTION_TYPE;

      } else if (StrStr (VariableName, L"Key") != NULL){

        (*p)->OptionType = KEY_OPTION_TYPE;

      } else if (StrStr (VariableName, L"SysPrep") != NULL){

        (*p)->OptionType = SYSPREP_OPTION_TYPE;

      } else {

        (*p)->OptionType = DRIVER_OPTION_TYPE;

      }

      (*p)->DataSize = DataSize;
      (*p)->OptionNumber = OptionNumber;
      (*p)->DataBuffer = DataBuffer;
      (*p)->VariableName = VariableName;
      (*p)->Next = NULL;

      DPRINTF_VAR ("  VariableName = %s\n", (*p)->VariableName);
      DPRINTF_VAR ("  OptionType   = %d\n", (*p)->OptionType);
      DPRINTF_VAR ("  DataSize     = 0x%x\n", (*p)->DataSize);
      DPRINTF_VAR ("  OptionNumber = %d\n", (*p)->OptionNumber);
      DPRINTF_VAR ("  DataBuffer   = 0x%x\n\n", (*p)->DataBuffer);

      p = &((*p)->Next);
      IsEssential = TRUE;
    } else {
      IsEssential = FALSE;
      SafeFreePool (DataBuffer);
    }
  }

#if OPTION_SYSTEM_BOOT_MANAGER_CACHE_ESSENTIAL_VARIABLES
  //
  // Cache variable names so we can skip the namespace scan on S4 resume.
  //

  SaveNames ();
#endif

  return Status;

} // DiscoverBmEssentialVariable

//
// FUNCTION NAME.
//      GetBmEssentialVariableListHead - Get the head of variable Linkedlist.
//
// FUNCTIONAL DESCRIPTION.
//      This function will return the head of variable list.
//
// ENTRY PARAMETERS.
//      Head            - Pointer points to the head of variable list.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      Head            - Pointer points to the head of variable list.
//

SCT_STATUS
EFIAPI
GetBmEssentialVariableListHead (IN OUT PBM_VARIABLE *Head)
{
  DPRINTF_VAR ("\n");
  *Head = mBmVariableListHead;
  return EFI_SUCCESS;

} // GetBmEssentialVariableListHead

//
// FUNCTION NAME.
//      FreeBmEssentialVariable - Get the head of variable Linkedlist.
//
// FUNCTIONAL DESCRIPTION.
//      This function will free the resource allocated for essential variables of BootManager.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
FreeBmEssentialVariable (VOID)
{
  PBM_VARIABLE p;
  PBM_VARIABLE q;
  p = mBmVariableListHead;

  DPRINTF_VAR ("\n");
  while (TRUE) {
    if (p == NULL) {
      break;
    }
    q = p;
    p = p->Next;

    DPRINTF_VAR ("  VariableName  = %s\n", q->VariableName);
    DPRINTF_VAR ("  OptionType    = %d\n", q->OptionType);
    DPRINTF_VAR ("  DataSize      = 0x%x\n", q->DataSize);
    DPRINTF_VAR ("  OptionNumber  = %d\n", q->OptionNumber);
    DPRINTF_VAR ("  DataBuffer    = 0x%x\n\n", q->DataBuffer);

    SafeFreePool (q->VariableName);
    SafeFreePool (q->DataBuffer);
    SafeFreePool (q);
  }

  mBmVariableListHead = NULL;
  return EFI_SUCCESS;
} // FreeBmEssentialVariable

//
// FUNCTION NAME.
//      RemoveDuplicatedBootEntry - Remove the duplicated option number in BootOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function will remove the duplicated option numbers and
//      update BootOrder variable.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - Number of duplicated option number.
//

UINT16
EFIAPI
RemoveDuplicatedBootEntry (VOID)
{
  UINTN i;
  UINTN j;
  UINTN NewLength;
  EFI_STATUS Status;
  PUINT16 BootOrder;
  UINTN BootOrderSize;
  UINT32 Attributes;
  UINT16 DuplicatedNumber;

  BootOrder = NULL;
  BootOrderSize = 0;

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             &Attributes,
             &BootOrderSize,
             (VOID **)&BootOrder);
  if (EFI_ERROR (Status) || BootOrderSize == 0) {
    return 0;
  }

  DuplicatedNumber = 0;
  NewLength = 1;
  for (i = 1; i < BootOrderSize / sizeof (UINT16); i++) {
    for (j = 0; j < NewLength; j++) {

      if (BootOrder [i] == BootOrder [j]) {
        DuplicatedNumber++;
        break;
      }
    }
    if (j == NewLength) {
      BootOrder [NewLength++] = BootOrder [i];
    }
  }

  if (DuplicatedNumber > 0) {

    //
    // Update BootOrder variable.
    //

    Status = gRT->SetVariable (
                    EFI_BOOT_ORDER_VARIABLE_NAME,
                    &gEfiGlobalVariableGuid,
                    Attributes,
                    BootOrderSize - DuplicatedNumber * sizeof (UINT16),
                    (VOID *)BootOrder);
  }

  SafeFreePool (BootOrder);
  return DuplicatedNumber;
} // RemoveDuplicatedBootEntry

//
// FUNCTION NAME.
//      RemoveAllBootManagerVariable - Remove all essential variables of Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      This function will remove below variables from the system.
//      BootOrder,
//      Boot####,
//      Key####,
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
EFIAPI
RemoveAllBootManagerVariable (VOID)
{
  EFI_STATUS Status;
  PBM_VARIABLE p;
  UINT32 Attributes;

  Attributes = \
    EFI_VARIABLE_NON_VOLATILE | \
    EFI_VARIABLE_BOOTSERVICE_ACCESS | \
    EFI_VARIABLE_RUNTIME_ACCESS;

  Status = gRT->SetVariable (
                  EFI_BOOT_ORDER_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  Attributes,
                  0,
                  NULL);
  Status = gRT->SetVariable (
                  L"LastBootOrder",
                  &gSctBdsServicesProtocolGuid,
                  Attributes,
                  0,
                  NULL);

  DiscoverBmEssentialVariable (TRUE);
  GetBmEssentialVariableListHead (&p);

  //
  // Delete all Boot####, Key#### , SysPrep####, and Driver####.
  //

  while (TRUE) {

    if (p == NULL) {
      break;
    }

    Status = gRT->SetVariable (
                    p->VariableName,
                    &gEfiGlobalVariableGuid,
                    Attributes,
                    0,
                    NULL);
    p = p->Next;
  }
  FreeBmEssentialVariable ();
  return Status;
} // RemoveAllBootManagerVariable

//
// FUNCTION NAME.
//      AddBootOptionToBootOrder - Update BootOrder.
//
// FUNCTIONAL DESCRIPTION.
//      This function will add one BootOption into BootOrder.
//
// ENTRY PARAMETERS.
//      OptionNumber    - BootOption number to be added.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
AddBootOptionToBootOrder (IN UINT16 OptionNumber)
{
  EFI_STATUS Status;
  PUINT16 OrgBootOrder;
  PUINT16 NewBootOrder;
  UINTN OrgBootOrderSize;
  UINTN NewBootOrderSize;

  DPRINTF_VAR (" Add 0x%x\n", OptionNumber);
  OrgBootOrder = NULL;
  OrgBootOrderSize = 0;
  OrgBootOrder = SctLibGetVariableAndSize (
                   EFI_BOOT_ORDER_VARIABLE_NAME,
                   &gEfiGlobalVariableGuid,
                   &OrgBootOrderSize);

  DPRINTF_VAR ("  OrgBootOrderSize = 0x%x\n", OrgBootOrderSize);

  NewBootOrderSize = OrgBootOrderSize + sizeof (UINT16);
  DPRINTF_VAR ("  NewBootOrderSize = 0x%x\n", NewBootOrderSize);

  NewBootOrder = AllocatePool (NewBootOrderSize);
  if (NewBootOrder == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  if (OrgBootOrder != NULL && OrgBootOrderSize > 0) {
    CopyMem (NewBootOrder, OrgBootOrder, OrgBootOrderSize);
  }

  NewBootOrder [(NewBootOrderSize / sizeof (UINT16)) - 1] = OptionNumber;
  Status = gRT->SetVariable (
                  EFI_BOOT_ORDER_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  NewBootOrderSize,
                  NewBootOrder);

  SafeFreePool (OrgBootOrder);
  SafeFreePool (NewBootOrder);
  return Status;
} // AddBootOptionToBootOrder

//
// Private (static) routines used by this component.
//
