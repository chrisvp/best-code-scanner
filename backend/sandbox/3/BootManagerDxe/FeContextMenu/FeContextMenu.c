//
// FILENAME.
//      FeContextMenu.c - Context Menu registered by Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      This module implement the functionality of context menu of file explorer.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"
#include "FeContextMenu.h"

extern EFI_HANDLE mImageHandle;
extern unsigned char ConfirmDialogBin [];

//
// Private data types used by this module are defined here and any
// static items are declared here.
//

static EFI_HANDLE mBoHiiDriverHandle = NULL;
static EFI_HII_HANDLE mBoHiiHandle = NULL;
static CHAR16 *MessageEmptyDescription = L"Description is empty";
static CHAR16 *MessageCreateSuccessfully = L"Create Boot Option successfully";

static EFI_GUID mBootOptionCreatePackageListFileGuid = SCT_BOOT_OPTION_CREATE_PACKAGELIST_FILE_GUID;
static EFI_GUID mBootOptionCreatePageGuid = SYSTEM_BOOT_OPTION_CREATE_FORMSET_GUID;

static HII_VENDOR_DEVICE_PATH mContextMenuHiiDevicePath = {
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_VENDOR_DP,
      {
        (UINT8) (sizeof (VENDOR_DEVICE_PATH)),
        (UINT8) ((sizeof (VENDOR_DEVICE_PATH)) >> 8)
      }
    },
    SYSTEM_BOOT_OPTION_CREATE_FORMSET_GUID
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    {
      (UINT8) (END_DEVICE_PATH_LENGTH),
      (UINT8) ((END_DEVICE_PATH_LENGTH) >> 8)
    }
  }
};

//
// Protocol used by this file.
//

static SCT_BDS_SERVICES_PROTOCOL *mBdsProt = NULL;
static EFI_FORM_BROWSER2_PROTOCOL *mFb2Prot = NULL;
static EFI_HII_DATABASE_PROTOCOL *mHiiDb = NULL;
static SCT_TEXT_SETUP_BROWSER2_PROTOCOL *mTextSetup2Prot = NULL;

//
// Prototypes for functions in other modules that are a part of this component.
//

extern
EFI_STATUS
EFIAPI
AddBootOptionToBootOrder (IN UINT16 OptionNumber);

extern
EFI_STATUS
EFIAPI
ReadFileToBuffer (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePath,
  OUT UINTN *BufferSize,
  OUT VOID **Buffer
  );

//
// Data shared with other modules *within* this component.
//

//
// Data defined in other modules and used by this module.
//

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
//      CreateBootOption - Create one BootOption.
//
// FUNCTIONAL DESCRIPTION.
//      This function will add one BootOption into BootOrder.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path of BootOption.
//      Description     - the description of BootOption.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
CreateBootOption (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN EFI_STRING Description
  )
{
  EFI_STATUS Status;
  SCT_BDS_SERVICES_BOOT_OPTION BootOption;

  if (DevicePath == NULL || Description == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  gBS->SetMem (&BootOption, sizeof (SCT_BDS_SERVICES_BOOT_OPTION), 0);

  BootOption.OptionNumber = 0xffff;
  BootOption.Description = (CHAR16*)Description;
  BootOption.FilePathList = DevicePath;
  BootOption.OptionalData = NULL;
  BootOption.OptionalDataLength = 0;
  BootOption.Attributes = LOAD_OPTION_ACTIVE | LOAD_OPTION_CATEGORY_BOOT;

  Status = mBdsProt->SetBootOption (&BootOption);

  if (EFI_ERROR (Status)) {
    return Status;
  }

  return AddBootOptionToBootOrder (BootOption.OptionNumber);

} // CreateBootOption

EFI_STATUS
EFIAPI
BoCreationExtractConfig (
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN CONST EFI_STRING Request,
  OUT EFI_STRING *Progress,
  OUT EFI_STRING *Results
  )
{
  if (Progress == NULL || Results == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Progress = Request;

  if (Request != NULL) {

    //
    // UEFI SCT Bug Fix - ExtractConfig() returns EFI_INVALID_PARAMETER with Request
    //                   been <MultiConfigRequest>.
    //

    if (StrStr (Request, L"&GUID=") != NULL) {
      *Progress = StrStr (Request, L"&GUID=");
      return EFI_INVALID_PARAMETER;
    }
  }

  return EFI_NOT_FOUND;

} // BoCreationExtractConfig

EFI_STATUS
EFIAPI
BoCreationRouteConfig (
  IN  CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN  CONST EFI_STRING Configuration,
  OUT EFI_STRING *Progress
  )
{
  return EFI_SUCCESS;
} // BoCreationRouteConfig

EFI_STATUS
EFIAPI
BoCreationCallback (
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  EFI_STATUS Status;
  CHAR16 *Description;
  CHAR16 *FilePathStr;
  EFI_DEVICE_PATH_PROTOCOL *FilePath;

  Status = EFI_UNSUPPORTED;
  if (Action == EFI_BROWSER_ACTION_CHANGED) {

    if (QuestionId == QUESTION_BOOT_OPTION_DESCRIPTION) {
      Description = NULL;
      Description = HiiGetString (mBoHiiHandle, Value->string, NULL);

      if (Description != NULL) {

        SctStrTrim (Description, L' ');
        if (StrLen (Description) != 0) {

          //
          // Create a Boot Option with user's input description.
          //

          FilePathStr = NULL;
          FilePathStr = HiiGetString (
                          mBoHiiHandle,
                          STRING_TOKEN (SYSTEM_FILE_EXPLORER_FILE_PATH),
                          NULL);

          if (FilePathStr != NULL) {
            FilePath = NULL;
            FilePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (FilePathStr);
            if (FilePath != NULL) {
              Status = CreateBootOption (FilePath, Description);
              mTextSetup2Prot->ShowMessageBox (
                                 L"Create Boot Option",
                                 SCT_MSGBOX_TYPE_INFO,
                                 1,
                                 &MessageCreateSuccessfully);
              FreePool (FilePath);
            }
            FreePool (FilePathStr);
          }

        } else {

          mTextSetup2Prot->ShowMessageBox (
                             L"Create Boot Option",
                             SCT_MSGBOX_TYPE_WARN,
                             1,
                             &MessageEmptyDescription);
        }
        FreePool (Description);
      }
      *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    }
  }

  return Status;
} // BoCreationCallback

EFI_HII_CONFIG_ACCESS_PROTOCOL mBootOptionCreationConfigAccess =
{
  BoCreationExtractConfig,
  BoCreationRouteConfig,
  BoCreationCallback
};

//
// FUNCTION NAME.
//      ContextMenuCreateBootOptionHandler - .
//
// FUNCTIONAL DESCRIPTION.
//      This function will create a boot option based on the input device path.
//
// ENTRY PARAMETERS.
//      FileName        - The name of selected file.
//      PhysicalDevicePath - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
ContextMenuCreateBootOptionHandler (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);
  CHAR16 *FilePathStr;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;

  if (PhysicalDevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Create one BootOption.
  //

  FilePathStr = NULL;
  FilePathStr = BM_CONVERT_DEVICE_PATH_TO_TEXT (PhysicalDevicePath, FALSE, TRUE);
  if (FilePathStr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  HiiSetString (
    mBoHiiHandle,
    STRING_TOKEN (SYSTEM_FILE_EXPLORER_FILE_PATH),
    FilePathStr,
    NULL);

  Status = mFb2Prot->SendForm (
                       mFb2Prot,
                       &mBoHiiHandle,
                       1,
                       &mBootOptionCreatePageGuid,
                       BOOT_OPTION_MAKER_FORM_ID,
                       NULL,
                       &ActionRequest);
  FreePool (FilePathStr);
  return EFI_SUCCESS;

} // ContextMenuCreateBootOptionHandler

#if OPTION_SYSTEM_FORM_BROWSER_METRO_VIEW

//
// FUNCTION NAME.
//      ContextMenuLoadImageHandler - .
//
// FUNCTIONAL DESCRIPTION.
//      This function will load and start an image based on the input device path.
//
// ENTRY PARAMETERS.
//      FileName        - The name of selected file.
//      PhysicalDevicePath - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
ContextMenuLoadImageHandler (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;
  PCHAR16 ExitData;
  UINTN ExitDataSize;
  EFI_HANDLE FileImageHandle;

  if (PhysicalDevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // LoadImage and StartImage.
  //

  Status = gBS->LoadImage (
                  FALSE,
                  mImageHandle,
                  PhysicalDevicePath,
                  NULL,
                  0,
                  &FileImageHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return gBS->StartImage (
                FileImageHandle,
                &ExitDataSize,
                &ExitData);

} // ContextMenuLoadImageHandler
#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL && OPTION_SYSTEM_FILE_EXPLORER

STATIC
UINTN
GetEnrollType (IN EFI_STRING FileName)
{
  UINTN EnrollType;
  CHAR16 *p;
  UINTN Len;

  EnrollType = SCT_ENROLL_TYPE_NONE;
  p = FileName;
  Len = StrLen (FileName);
  p += (Len - 4);
  DPRINTF_INIT ("p = %s\n", p);
  if (StrCmp (p, L".efi") == 0) {
    EnrollType = SCT_ENROLL_TYPE_EFI;
  } else if (StrCmp (p, L".cer") == 0) {
    EnrollType = SCT_ENROLL_TYPE_CER;
  } else if (StrCmp (p, L".der") == 0) {
    EnrollType = SCT_ENROLL_TYPE_CER;
  } else if (StrCmp (p - 1, L".auth") == 0) {
    EnrollType = SCT_ENROLL_TYPE_AUTH;
  }
  DPRINTF_INIT ("EnrollType = %d\n", EnrollType);

  return EnrollType;
}

//
// FUNCTION NAME.
//      ContextMenuEnrollDb - Context menu for enrolling db.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help the user to enroll a key to signature database (db).
//
//      The user can select a file with .efi, .cer and .der file name extension and the
//      associated hash value or CA (x509) will be enrolled to db.
//
// ENTRY PARAMETERS.
//      FileName        - The name of selected file.
//      PhysicalDevicePath - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
ContextMenuEnrollDb (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;
  UINTN FileSize;
  UINT8 *Buffer;
  CHAR16 Str [0x100];
  EFI_STRING Msg [1];
  SCT_MSGBOX_TYPE Type;
  UINTN EnrollType;

  DPRINTF_INIT ("{\n");

  FileSize = 0;
  Buffer = NULL;
  EnrollType = GetEnrollType (FileName);
  if (EnrollType == SCT_ENROLL_TYPE_NONE) {
    return EFI_INVALID_PARAMETER;
  }

  SetMem (Str, sizeof (Str), 0);
  Status = ReadFileToBuffer (
             PhysicalDevicePath,
             &FileSize,
             (VOID **)&Buffer);

  if (!EFI_ERROR (Status)) {

    //
    // Enroll to db.
    //

    Status = EnrollDb (Buffer, FileSize, EnrollType, SignatureTypeDb);
    if (EFI_ERROR (Status)) {
      DPRINTF_ERROR ("Calling EnrollDb failed, status %r\n", Status);
    }

    if (Status == EFI_SUCCESS) {
      UnicodeSPrint (Str, sizeof (Str), L"Enroll %s to db successfully, size = 0x%x", FileName, FileSize);
      Type = SCT_MSGBOX_TYPE_INFO;
    } else {
      UnicodeSPrint (Str, sizeof (Str), L"Failed to enroll %s to db", FileName);
      Type = SCT_MSGBOX_TYPE_ERROR;
    }

    Msg [0] = Str;
    mTextSetup2Prot->ShowMessageBox (
                       L"Enroll DB",
                       Type,
                       1,
                       Msg);
  }
  FreePool (Buffer);
  DPRINTF_INIT ("}\n");
  return Status;

} // ContextMenuEnrollDb

//
// FUNCTION NAME.
//      ContextMenuEnrollDbx - Context menu for enrolling dbx.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help the user to enroll a key to signature database (dbx).
//
//      The user can select a file with .efi, .cer and .der file name extension and the
//      associated hash value or CA (x509) will be enrolled to db.
//
// ENTRY PARAMETERS.
//      FileName        - The name of selected file.
//      PhysicalDevicePath - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
ContextMenuEnrollDbx (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;
  UINTN FileSize;
  UINT8 *Buffer;
  CHAR16 Str [0x100];
  EFI_STRING Msg [1];
  SCT_MSGBOX_TYPE Type;
  UINTN EnrollType;

  DPRINTF_INIT ("{\n");

  FileSize = 0;
  Buffer = NULL;
  EnrollType = GetEnrollType (FileName);
  if (EnrollType == SCT_ENROLL_TYPE_NONE) {
    return EFI_INVALID_PARAMETER;
  }

  SetMem (Str, sizeof (Str), 0);
  Status = ReadFileToBuffer (
             PhysicalDevicePath,
             &FileSize,
             (VOID **)&Buffer);

  if (!EFI_ERROR (Status)) {

    //
    // Enroll to dbx.
    //

    Status = EnrollDb (Buffer, FileSize, EnrollType, SignatureTypeDbx);
    if (EFI_ERROR (Status)) {
      DPRINTF_ERROR ("Calling EnrollDb failed, status %r\n", Status);
    }

    if (Status == EFI_SUCCESS) {
      UnicodeSPrint (Str, sizeof (Str), L"Enroll %s to dbx successfully, size = 0x%x", FileName, FileSize);
      Type = SCT_MSGBOX_TYPE_INFO;
    } else {
      UnicodeSPrint (Str, sizeof (Str), L"Failed to enroll %s to dbx", FileName);
      Type = SCT_MSGBOX_TYPE_ERROR;
    }

    Msg [0] = Str;
    mTextSetup2Prot->ShowMessageBox (
                       L"Enroll DBX",
                       Type,
                       1,
                       Msg);
  }
  FreePool (Buffer);
  DPRINTF_INIT ("}\n");
  return Status;

} // ContextMenuEnrollDbx

//
// FUNCTION NAME.
//      ContextMenuEnrollDbt - Context menu for enrolling dbt.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help the user to enroll a key to signature database (dbt).
//
//      The user can select a file with .efi, .cer and .der file name extension and the
//      associated hash value or CA (x509) will be enrolled to dbt.
//
// ENTRY PARAMETERS.
//      FileName        - The name of selected file.
//      PhysicalDevicePath - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
ContextMenuEnrollDbt (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;
  UINTN FileSize;
  UINT8 *Buffer;
  CHAR16 Str [0x100];
  EFI_STRING Msg [1];
  SCT_MSGBOX_TYPE Type;
  UINTN EnrollType;

  DPRINTF_INIT ("{\n");

  FileSize = 0;
  Buffer = NULL;
  EnrollType = GetEnrollType (FileName);
  if (EnrollType == SCT_ENROLL_TYPE_NONE) {
    return EFI_INVALID_PARAMETER;
  }

  SetMem (Str, sizeof (Str), 0);
  Status = ReadFileToBuffer (
             PhysicalDevicePath,
             &FileSize,
             (VOID **)&Buffer);

  if (!EFI_ERROR (Status)) {

    //
    // Enroll to dbt
    //

    Status = EnrollDb (Buffer, FileSize, EnrollType, SignatureTypeDbt);
    if (EFI_ERROR (Status)) {
      DPRINTF_ERROR ("Calling EnrollDb failed, status %r\n", Status);
    }

    if (Status == EFI_SUCCESS) {
      UnicodeSPrint (Str, sizeof (Str), L"Enroll %s to dbt successfully, size = 0x%x", FileName, FileSize);
      Type = SCT_MSGBOX_TYPE_INFO;
    } else {
      UnicodeSPrint (Str, sizeof (Str), L"Failed to enroll %s to dbt", FileName);
      Type = SCT_MSGBOX_TYPE_ERROR;
    }

    Msg [0] = Str;
    mTextSetup2Prot->ShowMessageBox (
                       L"Enroll DBT",
                       Type,
                       1,
                       Msg);
  }
  FreePool (Buffer);
  DPRINTF_INIT ("}\n");
  return Status;

} // ContextMenuEnrollDbt

//
// FUNCTION NAME.
//      ContextMenuEnrollDbr - Context menu for enrolling dbr.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help the user to enroll a key to signature database (dbr).
//
//      The user can select a file with .efi, .cer and .der file name extension and the
//      associated hash value or CA (x509) will be enrolled to dbr.
//
// ENTRY PARAMETERS.
//      FileName        - The name of selected file.
//      PhysicalDevicePath - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
ContextMenuEnrollDbr (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;
  UINTN FileSize;
  UINT8 *Buffer;
  CHAR16 Str [0x100];
  EFI_STRING Msg [1];
  SCT_MSGBOX_TYPE Type;
  UINTN EnrollType;

  DPRINTF_INIT ("{\n");

  FileSize = 0;
  Buffer = NULL;
  EnrollType = GetEnrollType (FileName);
  if (EnrollType == SCT_ENROLL_TYPE_NONE) {
    return EFI_INVALID_PARAMETER;
  }

  SetMem (Str, sizeof (Str), 0);
  Status = ReadFileToBuffer (
             PhysicalDevicePath,
             &FileSize,
             (VOID **)&Buffer);

  if (!EFI_ERROR (Status)) {

    //
    // Enroll to dbr.
    //

    Status = EnrollDb (Buffer, FileSize, EnrollType, SignatureTypeDbr);
    if (EFI_ERROR (Status)) {
      DPRINTF_ERROR ("Calling EnrollDb failed, status %r\n", Status);
    }

    if (Status == EFI_SUCCESS) {
      UnicodeSPrint (Str, sizeof (Str), L"Enroll %s to dbr successfully, size = 0x%x", FileName, FileSize);
      Type = SCT_MSGBOX_TYPE_INFO;
    } else {
      UnicodeSPrint (Str, sizeof (Str), L"Failed to enroll %s to dbr", FileName);
      Type = SCT_MSGBOX_TYPE_ERROR;
    }

    Msg [0] = Str;
    mTextSetup2Prot->ShowMessageBox (
                       L"Enroll DBR",
                       Type,
                       1,
                       Msg);
  }
  FreePool (Buffer);
  DPRINTF_INIT ("}\n");
  return Status;

} // ContextMenuEnrollDbr
#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL_PK && OPTION_SYSTEM_FILE_EXPLORER

//
// FUNCTION NAME.
//      ContextMenuEnrollPk - Context menu for enrolling PK.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help the user to enroll PK.
//
//      The user can select a file with .cer and .der file name extension and the
//      associated hash value or CA (x509) will be enrolled to PK.
//
// ENTRY PARAMETERS.
//      FileName                        - The name of selected file.
//      PhysicalDevicePath              - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return                 - EFI status code.
//

EFI_STATUS
ContextMenuEnrollPk (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;
  UINTN FileSize;
  UINT8 *Buffer;
  CHAR16 Str [0x100];
  EFI_STRING Msg [1];
  SCT_MSGBOX_TYPE Type;
  UINTN EnrollType;

  DPRINTF_INIT ("{\n");

  FileSize = 0;
  Buffer = NULL;
  EnrollType = GetEnrollType (FileName);
  if (EnrollType == SCT_ENROLL_TYPE_NONE) {
    return EFI_INVALID_PARAMETER;
  }

  SetMem (Str, sizeof (Str), 0);
  Status = ReadFileToBuffer (
             PhysicalDevicePath,
             &FileSize,
             (VOID **)&Buffer);

  if (!EFI_ERROR (Status)) {

    //
    // Enroll PK.
    //

    Status = EnrollPk (Buffer, FileSize, EnrollType);
    if (EFI_ERROR (Status)) {
      DPRINTF_ERROR ("Calling EnrollPk failed, status %r\n", Status);
    }

    if (Status == EFI_SUCCESS) {
      UnicodeSPrint (Str, sizeof (Str), L"Enroll %s to PK successfully, size = 0x%x", FileName, FileSize);
      Type = SCT_MSGBOX_TYPE_INFO;
    } else {
      UnicodeSPrint (Str, sizeof (Str), L"Failed to enroll %s to PK", FileName);
      Type = SCT_MSGBOX_TYPE_ERROR;
    }

    Msg [0] = Str;
    mTextSetup2Prot->ShowMessageBox (
                       L"Enroll PK",
                       Type,
                       1,
                       Msg);
  }
  FreePool (Buffer);
  DPRINTF_INIT ("}\n");
  return Status;

} // ContextMenuEnrollPk
#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL_KEK && OPTION_SYSTEM_FILE_EXPLORER

//
// FUNCTION NAME.
//      ContextMenuEnrollKek - Context menu for enrolling KEK.
//
// FUNCTIONAL DESCRIPTION.
//      This function will help the user to enroll KEK.
//
//      The user can select a file with .cer and .der file name extension and the
//      associated hash value or CA (x509) will be enrolled to KEK.
//
// ENTRY PARAMETERS.
//      FileName                        - The name of selected file.
//      PhysicalDevicePath              - The full device path of selected file.
//
// EXIT PARAMETERS.
//      Function Return                 - EFI status code.
//

EFI_STATUS
ContextMenuEnrollKek (
  IN EFI_STRING FileName,
  IN EFI_DEVICE_PATH_PROTOCOL *PhysicalDevicePath
  )
{
  EFI_STATUS Status;
  UINTN FileSize;
  UINT8 *Buffer;
  CHAR16 Str [0x100];
  EFI_STRING Msg [1];
  SCT_MSGBOX_TYPE Type;
  UINTN EnrollType;

  DPRINTF_INIT ("{\n");

  FileSize = 0;
  Buffer = NULL;
  EnrollType = GetEnrollType (FileName);
  if (EnrollType == SCT_ENROLL_TYPE_NONE) {
    return EFI_INVALID_PARAMETER;
  }

  SetMem (Str, sizeof (Str), 0);
  Status = ReadFileToBuffer (
             PhysicalDevicePath,
             &FileSize,
             (VOID **)&Buffer);

  if (!EFI_ERROR (Status)) {

    //
    // Enroll KEK.
    //

    Status = EnrollKek (Buffer, FileSize, EnrollType);
    if (EFI_ERROR (Status)) {
      DPRINTF_ERROR ("Calling EnrollKek failed, status %r\n", Status);
    }

    if (Status == EFI_SUCCESS) {
      UnicodeSPrint (Str, sizeof (Str), L"Enroll %s to KEK successfully, size = 0x%x", FileName, FileSize);
      Type = SCT_MSGBOX_TYPE_INFO;
    } else {
      UnicodeSPrint (Str, sizeof (Str), L"Failed to enroll %s to KEK", FileName);
      Type = SCT_MSGBOX_TYPE_ERROR;
    }

    Msg [0] = Str;
    mTextSetup2Prot->ShowMessageBox (
                       L"Enroll KEK",
                       Type,
                       1,
                       Msg);
  }
  FreePool (Buffer);
  DPRINTF_INIT ("}\n");
  return Status;

} // ContextMenuEnrollKek
#endif

//
// FUNCTION NAME.
//      InstallDefaultContextMenu - Install one context menu for creating a boot option.
//
// FUNCTIONAL DESCRIPTION.
//      This function will register one context menu so that the user can create one boot option
//      from the selected file.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
InstallDefaultContextMenu (VOID)
{
  EFI_STATUS Status;
  EFI_HANDLE DummyHandle;
  SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *FeContextMenu;
  DPRINTF_INIT ("{\n");

  DummyHandle = NULL;

  Status = gBS->LocateProtocol (
                  &gEfiHiiDatabaseProtocolGuid,
                  NULL,
                  (VOID **) &mHiiDb);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Locating gEfiHiiDatabaseProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gEfiFormBrowser2ProtocolGuid,
                  NULL,
                  (VOID **)&mFb2Prot);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Locating gEfiFormBrowser2ProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gTextSetupBrowser2ProtocolGuid,
                  NULL,
                  (VOID **)&mTextSetup2Prot);

  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Locating gTextSetupBrowser2ProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gSctBdsServicesProtocolGuid,
                  NULL,
                  (VOID **)&mBdsProt);

  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Locating gSctBdsServicesProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mBoHiiDriverHandle,
                  &gEfiDevicePathProtocolGuid,
                  &mContextMenuHiiDevicePath,
                  &gEfiHiiConfigAccessProtocolGuid,
                  &mBootOptionCreationConfigAccess,
                  NULL);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gEfiDevicePathProtocolGuid and gEfiHiiConfigAccessProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

  //
  // Prepare HII resource for Boot option creation dialog.
  //

  mBoHiiHandle = HiiAddPackages (
                   &mBootOptionCreatePackageListFileGuid,
                   mBoHiiDriverHandle,
                   MODULE_STRING_ARRAY,
                   ConfirmDialogBin,
                   NULL);

  if (mBoHiiHandle == NULL) {
    DPRINTF_ERROR ("Calling HiiAddPackages failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu = \
    (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    DPRINTF_INIT ("}\n");
    return EFI_OUT_OF_RESOURCES;
  }

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Create Boot Option";
  FeContextMenu->FileType = L".efi";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuCreateBootOptionHandler;
  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *)FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

#if OPTION_SYSTEM_FORM_BROWSER_METRO_VIEW

  //
  // Context menu for loading and starting an image.
  //

  FeContextMenu = \
    (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    DPRINTF_INIT ("}\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Load Image";
  FeContextMenu->FileType = L".efi";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuLoadImageHandler;

  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *)FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }
#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL && OPTION_SYSTEM_FILE_EXPLORER

  //
  // Context menu for enrolling a certificate or digital signature.
  //

  FeContextMenu = \
    (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Enroll DB";
  FeContextMenu->FileType = L".efi,.cer,.der,.auth";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuEnrollDb;

  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *) FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL && OPTION_SYSTEM_FILE_EXPLORER

  //
  // Context menu for enrolling a certificate or digital signature.
  //

  FeContextMenu = \
    (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Enroll DBX";
  FeContextMenu->FileType = L".efi,.cer,.der,.auth";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuEnrollDbx;

  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *) FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL && OPTION_SYSTEM_FILE_EXPLORER

  //
  // Context menu for enrolling a certificate or digital signature.
  //

  FeContextMenu = \
    (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Enroll DBT";
  FeContextMenu->FileType = L".efi,.cer,.der,.auth";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuEnrollDbt;

  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *) FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

#endif

#if 0 //OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL // System doesn't support DBR now, enable it in the future.

  //
  // Context menu for enrolling a certificate or digital signature.
  //

  FeContextMenu = \
    (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Enroll DBR";
  FeContextMenu->FileType = L".efi,.cer,.der,.auth";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuEnrollDbr;

  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *) FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL_PK && OPTION_SYSTEM_FILE_EXPLORER

  //
  // Context menu for enrolling a certificate or digital signature.
  //

  FeContextMenu = (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)
                  AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Enroll PK";
  FeContextMenu->FileType = L".cer,.der,.auth";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuEnrollPk;

  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *) FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

#endif

#if OPTION_SYSTEM_SECURE_BOOT_PAGE_ENROLL_KEK && OPTION_SYSTEM_FILE_EXPLORER

  //
  // Context menu for enrolling a certificate or digital signature.
  //

  FeContextMenu = (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL *)
                  AllocateZeroPool (sizeof (SCT_FILE_EXPLORER_CONTEXT_MENU_PROTOCOL));

  if (FeContextMenu == NULL) {
    DPRINTF_ERROR ("EFI_OUT_OF_RESOURCES\n");
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Context menu for creating Boot Option.
  //

  FeContextMenu->HiiHandle = NULL;
  FeContextMenu->DisplayString = L"Enroll KEK";
  FeContextMenu->FileType = L".cer,.der,.auth";
  FeContextMenu->StringId = 0;
  FeContextMenu->Handler = ContextMenuEnrollKek;

  DummyHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &DummyHandle,
                  &gSctFileExplorerContextMenuProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  (VOID *) FeContextMenu);
  if (EFI_ERROR (Status)) {
    DPRINTF_ERROR ("Install gSctFileExplorerContextMenuProtocolGuid failed, status %r\n", Status);
    DPRINTF_INIT ("}\n");
    return Status;
  }

#endif

  DPRINTF_INIT ("}\n");
  return Status;
} // InstallDefaultContextMenu

//
// FUNCTION NAME.
//      BmRegisterContextMenu - Register context menus provided by BootManager.
//
// FUNCTIONAL DESCRIPTION.
//      This function will be invoked when gEfiHiiPlatformSetupFormsetGuid is
//      installed.
//
// ENTRY PARAMETERS.
//      Event           - Event received when entering Form Browser.
//      Context         - Data passed when event is signaled.
//
// EXIT PARAMETERS.
//      None.
//

VOID
EFIAPI
BmRegisterContextMenu (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{

  InstallDefaultContextMenu ();

  //
  // Close event in any case.
  //

  gBS->CloseEvent (Event);

} // BmRegisterContextMenu
