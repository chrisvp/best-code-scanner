//
// FILENAME.
//      Hotkey.c - SecureCore Technology(TM) Hotkey Services Supporting the Boot Manager Component.
//
// FUNCTIONAL DESCRIPTION.
//      This module provides services for managing hotkeys.
//
//      Hotkeys, as implemented in this module, are defined in the UEFI
//      specification version 2.3.1, section 3.1.6. The specification defines
//      the relationship between hotkeys and load options.
//
//      The specification assumes that the system has support for the simple
//      text input ex protocol, which provides event services for keys and
//      provides state information for the shift keys: shift, ctrl, alt, logo
//      menu and SysReq. Our implementation makes no such assumption. Instead
//      we will require the text ex protocol only if the hotkey needs shift key
//      information. If the text ex protocol is available this driver makes use
//      of it for the notification services. Otherwise the boot manager must
//      use the Check request to ask this module to service any keys that may
//      be pending (polling mode).
//
// NOTICE.
//      Copyright (C) 2020-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

//
// Data shared with other modules *within* this component.
//

EFI_HII_HANDLE mHiiImageHandle = NULL;  // HII handle of our Image Package.
EFI_HII_IMAGE_PROTOCOL *mHiiImage = NULL;
SCT_HII_IMAGE_DISPLAY_PROTOCOL *mImageDisplay = NULL;


//
// Public API functions implemented by this component.
//


//
// FUNCTION NAME.
//      InitializeHotkeyImage - Initialize hotkey images.
//
// FUNCTIONAL DESCRIPTION.
//      This function will collect all hotkey images and install them into Hii
//      database for display.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
InitializeHotkeyImage (VOID)
{
  SCT_STATUS Status;
  HOTKEY_VARIABLE *HotkeyVariablePtr;
  UINTN DataSize;

  DPRINTF_HK ("InitializeHotkeyImage:\n");

  Status = gBS->LocateProtocol (
                  &gEfiHiiImageProtocolGuid,
                  NULL,
                  (VOID **) &mHiiImage);

  if (EFI_ERROR (Status)) {
    DPRINTF_HK ("  Can't find gEfiHiiImageProtocolGuid. Exit (%r).\n", Status);
    mHiiImage = NULL;
    return Status;
  }

  Status = gBS->LocateProtocol (
                  &gSctHiiImageDisplayProtocolGuid,
                  NULL,
                  (VOID **) &mImageDisplay);

  if (EFI_ERROR (Status)) {
    DPRINTF_HK ("  Can't find Image Display protocol. Exit (%r).\n", Status);
    mImageDisplay = NULL;
    return Status;
  }

  DPRINTF_HK (" LoadPackage %x.\n", mImageDisplay);

#if (OPTION_SYSTEM_SPLASH_STATUS_BAR)
  Status = mImageDisplay->LoadPackage (
                            mImageDisplay,
                            &gEfiCallerIdGuid,
                            MODULE_IMAGE_ARRAY,
                            &mHiiImageHandle);

  DPRINTF_HK (" LoadPackage for Image result: (%r).\n", Status);
#endif

  DataSize = sizeof (HOTKEY_VARIABLE);
  Status = SctLibGetVariable (
             SCT_HOTKEY_VARIABLE_NAME,
             &gSctHotkeyVariableGuid,
             NULL,
             &DataSize,
             (VOID **) &HotkeyVariablePtr);

  if (EFI_ERROR (Status)) {
    DPRINTF_HK ("  SctLibGetVariable for SctHotkeyVariable failed %r.\n", Status);
    HotkeyVariablePtr =  AllocateZeroPool (DataSize);
    if (HotkeyVariablePtr == NULL) {
      DPRINTF_HK (" AllocateZeroPool failed: (%r).\n", Status);
      return SCT_STATUS_OUT_OF_RESOURCES;
    }
  }

  HotkeyVariablePtr->HiiImage = mHiiImage;
  HotkeyVariablePtr->HiiImageHandle = mHiiImageHandle;

#if OPTION_SYSTEM_SPLASH_STATUS_BAR

  HotkeyVariablePtr->StatusBarImageId = IMAGE_TOKEN(STATUS_BAR_HOTKEY);
  HotkeyVariablePtr->StatusBarWaitImageId = IMAGE_TOKEN(STATUS_BAR_HOTKEY_WAIT);

#else

  HotkeyVariablePtr->StatusBarImageId = 0xffff;
  HotkeyVariablePtr->StatusBarWaitImageId = 0xffff;

#endif
  Status = gRT->SetVariable (
                  SCT_HOTKEY_VARIABLE_NAME,
                  &gSctHotkeyVariableGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  DataSize,
                  (VOID *)HotkeyVariablePtr);

  if (EFI_ERROR (Status)) {
    DPRINTF_HK ("  SetVariable for SctHotkeyVariable failed %r.\n", Status);
  }

  return Status;

} // InitializeHotkeyImage

