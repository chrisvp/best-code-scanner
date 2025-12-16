//
// FILENAME.
//      Console.c - SecureCore Technology(TM) Console Services.
//
// FUNCTIONAL DESCRIPTION.
//      This module provides console management services for the Boot Manager.
//
//      The Efi Variables ConOut, ConIn and ErrOut are managed by this driver.
//      This module provides services for adding and removing device paths to
//      these variables; and an initialization routine is provided for each
//      variable. The initialization routine will purge the variable of devices
//      that can no longer be connected and connect all the devices that can
//      be connected and are listed in the variable.
//
//      Console management currently spans several drivers. The services in
//      this module rely on the behavior of these other drivers:
//
//      ConSplitter     - This driver hooks the System Table entries for ConIn,
//                        ConOut and StdErr. These entries correspond to the
//                        Efi Variables ConIn, ConOut and ErrOut, which are
//                        Governed by this module. This driver looks for
//                        special GUID values attached to handles
//
//      ConPlatform     - This driver uses the driver binding protocol to get
//                        notification when a controller handle has the simple
//                        text protocol installed. When that happens this
//                        driver will add the device path from the controller
//                        handle to the appropriate variables: ConInDev,
//                        ConOutDev or ErrOutDev. Then this driver checks the
//                        variables ConOut, ConIn and ErrOut to see if the
//                        controller's device path is listed and if so this
//                        driver will install a GUID on the handle to signal
//                        to the ConSplitter driver that this handle should
//                        be included in the aggregation of input or output
//                        devices.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

//typedef struct _LIGHT_STATUS_KEY {
//  EFI_KEY_TOGGLE_STATE  ToggleState;
//  EFI_HANDLE            RegisteredHandle;
//} LIGHT_STATUS_KEY;


//
// Private data types used by this module are defined here and any
// static items are declared here.
//

SCT_STATUS
MsTaskDisplaySplashScreen (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  );

static BOOT_MANAGER_CONNECTION_DEVICE mConsoleInList [] = {
  CONFIG_BmConInDefault
};

#if !OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE
static BOOT_MANAGER_CONNECTION_DEVICE mConsoleOutList [] = {
  CONFIG_BmConOutDefault
};
#endif //#if !OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE

static BOOT_MANAGER_CONNECTION_DEVICE mStandardErrList [] = {
  CONFIG_BmErrOutDefault
};

static VOID *mStoDeviceRegistration = NULL;
static EFI_EVENT mStoDeviceAvailableEvent = NULL;

//SCT_STATUS
//UnRegisterPauseHotkey(VOID);

//static EFI_EVENT mConInDeviceAvailableEvent;
//static VOID *mConInDeviceRegistration;
//static EFI_SET_STATE mConSplitterTextInSetState = NULL;
//static LIGHT_STATUS_KEY mToggleStatusKeyRegister [] = {
//  {EFI_SCROLL_LOCK_ACTIVE, NULL},
//  {EFI_NUM_LOCK_ACTIVE, NULL},
//  {EFI_CAPS_LOCK_ACTIVE, NULL},
//  {EFI_NUM_LOCK_ACTIVE | EFI_CAPS_LOCK_ACTIVE, NULL},
//  {EFI_NUM_LOCK_ACTIVE | EFI_CAPS_LOCK_ACTIVE | EFI_SCROLL_LOCK_ACTIVE, NULL},
//  {EFI_NUM_LOCK_ACTIVE|EFI_SCROLL_LOCK_ACTIVE, NULL},
//  {EFI_SCROLL_LOCK_ACTIVE|EFI_CAPS_LOCK_ACTIVE, NULL},
//  {EFI_TOGGLE_STATE_VALID | EFI_KEY_STATE_EXPOSED, NULL}
//};

static BOOT_MANAGER_IGNORE_DEFERRED_IMAGE mIgnoreDeferredVgaImageList [] = {
  CONFIG_BmIgnoreDeferredVgaImageList
};

//
// Prototypes for functions in other modules that are a part of this component.
//

EFI_EVENT mSimpleTextInExEvent;
VOID *mSimpleTextInExDeviceRegistration;
EFI_HANDLE mNotifyHandle = NULL;

UINTN mDeferredVgaHandle = 0;
EFI_HANDLE *gDeferredImageBuffer = NULL;

extern
SCT_STATUS
EFIAPI
SetEfiGlobalVariable (
  IN PCHAR16 VariableName,
  IN UINT32 Attributes,
  IN UINTN DataSize,
  IN PVOID Data
  );

extern
EFI_DEVICE_PATH_PROTOCOL *
EFIAPI
ExpandOneDevicePath (IN EFI_DEVICE_PATH_PROTOCOL  *DevicePath);

extern
SCT_STATUS
EFIAPI
ConnectAllPciDevices (VOID);

extern
BOOLEAN
EFIAPI
IsBmDevicePathValid (
  IN CONST EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINTN MaxSize
  );


//
// Data shared with other modules *within* this component.
//

#ifndef SCT_MODULE_CSMMODULE
EFI_GUID gEfiLegacyBiosGuid = EFI_LEGACY_BIOS_GUID;
#endif

extern EFI_HANDLE *mContextOverrideDriver;
extern EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *mTextInEx;

//
// Data defined in other modules and used by this module.
//

extern BOOLEAN mCsmSupported;

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

SCT_STATUS
ConnectConsoleVariable (IN PCHAR16 VariableName);

SCT_STATUS
RemoveDevicePathFromConsoleVariable (
  IN PCHAR16 VariableName,
  IN EFI_DEVICE_PATH_PROTOCOL *RemovePath
  );

SCT_STATUS
AddDevicePathToConsoleVariable (
  IN PCHAR16 VariableName,
  IN EFI_DEVICE_PATH_PROTOCOL *AddPath
  );

SCT_STATUS
EFIAPI
ConnectConsoleByVariable (IN PCHAR16 VariableName);

SCT_STATUS
RegisterStoDeviceNotify (VOID);

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE
SCT_STATUS
AutoDetectPciVgaDevice (VOID);
#endif

static
SCT_STATUS
SelectDefaultVideoOutputDevice (
  IN EFI_HANDLE Handle,
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath OPTIONAL
  );

static
BOOLEAN
IsGopProduced (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

//
// Public API functions implemented by this component.
//

BOOLEAN
EFIAPI
CompareDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL *dp1,
  IN EFI_DEVICE_PATH_PROTOCOL *dp2
  );

SCT_STATUS
EFIAPI
GetGopAlternativeChild (
  IN EFI_HANDLE VgaHandle,
  OUT EFI_DEVICE_PATH_PROTOCOL **RemainingDevicePath);

BOOLEAN
IsHotPlugDevice (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath);

BOOLEAN
IsTerminalDevice (IN EFI_DEVICE_PATH_PROTOCOL * DevicePath);

EFI_STATUS
STATIC
BmKickOutGopDrivers (VOID);

EFI_STATUS
EFIAPI
GetEfiVgaDeferredImages (VOID);

BOOLEAN
IsManagedByThunk (
  IN EFI_HANDLE DeviceHandle
  );


//
// FUNCTION NAME.
//      WaitForKeystroke - Waite for any keystroke.
//
// FUNCTIONAL DESCRIPTION.
//      Callback function for SimpleTextInEx.RegisterKeyNotify register events
//      for a PAUSE keystroke. This function will be called when PAUSE keystroke
//      occurs, and then pause until press any key.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function return - EFI status code.
//

EFI_STATUS
EFIAPI
WaitForKeystroke (IN EFI_KEY_DATA *KeyData)
{
  EFI_TPL Tpl;
  UINTN Index;
  EFI_STATUS Status;

  DPRINTF_CON ("Entry.\n");

  //
  // Set to application TPL to get USB KB event.
  //

  Tpl = SetTpl (TPL_APPLICATION);

  //
  // Clear PAUSE_SCAN code first
  //
  mTextInEx->ReadKeyStrokeEx (mTextInEx, KeyData);


  while (TRUE) {
    Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &Index);
    if (!EFI_ERROR (Status)) {
      break;
    }
  }

  SetTpl (Tpl);     // Restore to original TPL.

  DPRINTF_CON ("Exit.\n");
  return EFI_SUCCESS;
} // WaitForKeystroke


//
// FUNCTION NAME.
//      RegisterPauseHotkey - Register the key to STI to support pause during P.O.S.T.
//
// FUNCTIONAL DESCRIPTION.
//      This function will register a key to support pause during P.O.S.T.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

extern
SCT_STATUS
RegisterPauseHotkey (VOID)
{
  EFI_KEY_DATA KeyData;

  KeyData.Key.ScanCode = SCAN_PAUSE;
  KeyData.Key.UnicodeChar = 0x00;
  KeyData.KeyState.KeyShiftState = 0x00;
  KeyData.KeyState.KeyToggleState = 0x00;

  if (mTextInEx == NULL) {
    return EFI_UNSUPPORTED;
  }

  return mTextInEx->RegisterKeyNotify (
                      mTextInEx,
                      &KeyData,
                      WaitForKeystroke,
                      &mNotifyHandle);
} // RegisterPauseHotkey


//
// FUNCTION NAME.
//      UnRegisterPauseHotkey - UnRegister the key to STI to support pause during P.O.S.T.
//
// FUNCTIONAL DESCRIPTION.
//      This function will Unregister a key to support pause during P.O.S.T.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//


SCT_STATUS
UnRegisterPauseHotkey (VOID)
{

  if (mTextInEx == NULL) {
    return EFI_UNSUPPORTED;
  }

  if (mNotifyHandle == NULL) {
    return EFI_NOT_STARTED;
  }

  return mTextInEx->UnregisterKeyNotify (
                      mTextInEx,
                      mNotifyHandle);
} // UnRegisterPauseHotkey


//
// FUNCTION NAME.
//      SimpleTextInExDeviceDiagnosticsNotify - Simple Text In Ex device events notification.
//
// FUNCTIONAL DESCRIPTION.
//      Callback function for SimpleTextInEx protocol install events.
//      It registers a function which will be called when PAUSE keystroke
//      occurs.
//
// ENTRY PARAMETERS.
//      Event           - the event that is signaled.
//      Context         - not used here.
//
// EXIT PARAMETERS.
//      None.
//

VOID
EFIAPI
SimpleTextInExDeviceDiagnosticsNotify (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  UINTN BufferSize;
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  EFI_KEY_DATA KeyData;
  EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *mConInEx;

  DPRINTF_CON ("Entry.\n");

  BufferSize = sizeof (EFI_HANDLE);
  KeyData.Key.ScanCode = SCAN_PAUSE;
  KeyData.Key.UnicodeChar = 0x00;
  KeyData.KeyState.KeyShiftState = 0x00;
  KeyData.KeyState.KeyToggleState = 0x00;

  Status = gBS->LocateHandle (
                  ByRegisterNotify,
                  NULL,
                  mSimpleTextInExDeviceRegistration,
                  &BufferSize,
                  &Handle);
  if (EFI_ERROR (Status)) {
    DPRINTF_CON ("No mSimpleTextInExDeviceRegistration exists.\n");
    return;
  }

  Status = gBS->HandleProtocol (
                  Handle,
                  &gEfiSimpleTextInputExProtocolGuid,
                  (VOID **)&mConInEx);
  if (EFI_ERROR(Status)) {
    DPRINTF_CON ("This handle doesn't contain gEfiSimpleTextInputExProtocolGuid protocol, status: %r.\n", Status);
    return;
  }

  Status = mConInEx->RegisterKeyNotify (
                       mConInEx,
                       &KeyData,
                       WaitForKeystroke,
                       &mNotifyHandle);
  if (EFI_ERROR(Status)) {
    DPRINTF_CON ("Failed to RegisterKeyNotify, status: %r.\n", Status);
    return;
  }

  DPRINTF_CON ("Exit.\n");
  return;
} // SimpleTextInExDeviceDiagnosticsNotify


//
// FUNCTION NAME.
//      InitializePauseSupport - Initialize Pause key support.
//
// FUNCTIONAL DESCRIPTION.
//      This function initializes the pause key support in Boot Manager.
//      It takes advantage of the Simple Text Input Ex protocol. So the
//      OPTION_SYSTEM_ISA_PS2_KEYBOARD_STI2 support is the prerequisite.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function return - EFI status code.
//

EFI_STATUS
InitializePauseSupport (VOID)
{
  EFI_STATUS Status;

  //
  // Register notification event and handler routine for Simple Text Input
  // extension devices.
  //

  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  SimpleTextInExDeviceDiagnosticsNotify,
                  NULL,
                  &mSimpleTextInExEvent);
  if (EFI_ERROR (Status)) {
    DPRINTF_CON ("Failed to create SimpleTextInExDeviceDiagnosticsNotify event, status: %r.\n", Status);
    return Status;;
  }

  Status = gBS->RegisterProtocolNotify (
                  &gEfiSimpleTextInputExProtocolGuid,
                  mSimpleTextInExEvent,
                  &mSimpleTextInExDeviceRegistration);
  if (EFI_ERROR (Status)) {
    DPRINTF_CON ("Failed to register gEfiSimpleTextInputExProtocolGuid event, status: %r.\n", Status);
    return Status;
  }

  return Status;
} // InitializePauseSupport

//
// FUNCTION NAME.
//      InitializeConsole - Initialize Console Module.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called during driver initialization to initialize
//      the console services.
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
InitializeConsole (VOID)
{
  DPRINTF_INIT ("InitializeConsole.\n");
  return SCT_STATUS_SUCCESS;
} // InitializeConsole


//
// FUNCTION NAME.
//      ConInInit - Initialize Console Input based on ConIn settings.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets the ConIn variable and walks through all the device
//      paths attempting to connect each controller. If the controller fails to
//      connect the device path is removed from ConIn immediately.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

SCT_STATUS
EFIAPI
ConInInit (VOID)
{
  return ConnectConsoleByVariable (EFI_CON_IN_VARIABLE_NAME);
} // ConInInit


//
// FUNCTION NAME.
//      ConInAdd - Add a device path to the ConIn variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates the ConIn variable with a device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path to be added.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConInAdd (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  return AddDevicePathToConsoleVariable (EFI_CON_IN_VARIABLE_NAME, DevicePath);
} // ConInAdd


//
// FUNCTION NAME.
//      ConInRemove - Remove a device path from the ConIn variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates the ConIn variable, removing a device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path to be removed.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConInRemove (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  return RemoveDevicePathFromConsoleVariable (EFI_CON_IN_VARIABLE_NAME, DevicePath);
} // ConInRemove


//
// FUNCTION NAME.
//      ConOutInit - Initialize Console Output based on ConOut settings.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets the ConOut variable and walks through all the device
//      paths attempting to connect each controller. If the controller fails to
//      connect the device path is removed from ConOut immediately.
//
//      If none of the device paths connect successfully this function returns
//      an error. If one or more controllers are successfully connected this
//      function returns success.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConOutInit (VOID)
{
  EFI_STATUS Status;
  Status = ConnectConsoleByVariable (EFI_CON_OUT_VARIABLE_NAME);
  BmKickOutGopDrivers ();
  GetEfiVgaDeferredImages ();
  return Status;
} // ConOutInit


//
// FUNCTION NAME.
//      ConOutAdd - Add a device path to the ConOut variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates the ConOut variable with a device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path to be added.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConOutAdd (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  return AddDevicePathToConsoleVariable (EFI_CON_OUT_VARIABLE_NAME, DevicePath);
} // ConOutAdd


//
// FUNCTION NAME.
//      ConOutRemove - Remove a device path from the ConOut variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates the ConOut variable, removing a device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - The device path to be removed.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConOutRemove (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  return RemoveDevicePathFromConsoleVariable (EFI_CON_OUT_VARIABLE_NAME, DevicePath);
} // ConOutRemove


//
// FUNCTION NAME.
//      ErrOutInit - Initialize Standard Error based on ErrOut settings.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets the ErrOut variable and walks through all the device
//      paths attempting to connect each controller. If the controller fails to
//      connect the device path is removed from ErrOut immediately.
//
//      If none of the device paths connect successfully this function returns
//      an error. If one or more controllers are successfully connected this
//      function returns success.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ErrOutInit (VOID)
{
  return ConnectConsoleByVariable (EFI_ERR_OUT_VARIABLE_NAME);
} // ErrOutInit


//
// FUNCTION NAME.
//      ErrOutAdd - Add a device path to the ErrOut variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates the ErrOut variable with a device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path to be added.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ErrOutAdd (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  return AddDevicePathToConsoleVariable (EFI_ERR_OUT_VARIABLE_NAME, DevicePath);
} // ErrOutAdd


//
// FUNCTION NAME.
//      ErrOutRemove - Remove a device path from the ErrOut variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates the ErrOut variable, removing a device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - the device path to be removed.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ErrOutRemove (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  return RemoveDevicePathFromConsoleVariable (EFI_ERR_OUT_VARIABLE_NAME, DevicePath);
} // ErrOutRemove

//
// Private (static) routines used by this component.
//


//
// FUNCTION NAME.
//      CollectAllConsoles - Collect all SimpleTextIn/Out Protocol to Consoles.
//
// FUNCTIONAL DESCRIPTION.
//      This function will search every simpletxt device in current system,
//      and make every simpletxt device as pertain console device.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

VOID
CollectAllConsoles (VOID)
{
  EFI_STATUS Status;
  UINTN Index;
  EFI_DEVICE_PATH_PROTOCOL  *ConDevicePath;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  EFI_DEVICE_PATH_PROTOCOL *LastDevicePathNode;

  Index         = 0;
  HandleCount   = 0;
  HandleBuffer  = NULL;
  ConDevicePath = NULL;

  DPRINTF_CON ("  CollectAllConsoles Console Start \n");

  //
  // Update ConIn varables.
  //

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleTextInProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  if (!EFI_ERROR (Status) && HandleCount > 0) {

    for (Index = 0; Index < HandleCount; Index++) {
      ConDevicePath = NULL;
      ConDevicePath = DevicePathFromHandle (HandleBuffer [Index]);

#if 0
      //
      // Do not add terminal device path if UCR is disabled.
      //

      if (mSystemConRedirect.UcrStatus == SCT_CONSOLE_REDIRECTION_STATUS_DISABLED &&
        IsTerminalDevice (ConDevicePath)) {
        continue;
      }
#endif

      if (ConDevicePath != NULL) {
        if (!IsHotPlugDevice (ConDevicePath))
          ConInAdd (ConDevicePath);
      }
    }

    SafeFreePool(HandleBuffer);
    HandleBuffer = NULL;
    HandleCount = 0;
  }

  //
  // Update ConOut/ErrOut variables.
  //

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleTextOutProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  if (!EFI_ERROR (Status) && HandleCount > 0) {
    for (Index = 0; Index < HandleCount; Index++) {

      ConDevicePath = NULL;
      ConDevicePath = DevicePathFromHandle (HandleBuffer [Index]);

      if (ConDevicePath == NULL) {
        continue;
      }

#if 0
      //
      // Do not add terminal device path if UCR is disabled.
      //

      if (mSystemConRedirect.UcrStatus == SCT_CONSOLE_REDIRECTION_STATUS_DISABLED &&
        IsTerminalDevice (ConDevicePath)) {
        continue;
      }
#endif

      //
      // Don't add ACPI_ADR device path to ConOut and ErrOut variables because
      // we don't expect there will multiple video output devices in system.
      //

      LastDevicePathNode = GetLastDeviceNode (ConDevicePath);

      if (LastDevicePathNode != NULL &&
        LastDevicePathNode->Type == ACPI_DEVICE_PATH &&
        LastDevicePathNode->SubType == ACPI_ADR_DP) {

        DPRINTF_CON ("  Skip video output devices\n");
        continue;
      }
      ConOutAdd (ConDevicePath);
      ErrOutAdd (ConDevicePath);
    }
    SafeFreePool (HandleBuffer);
  }

  DPRINTF_CON ("  CollectAllConsoles Console End \n");
} // CollectAllConsoles



//
// FUNCTION NAME.
//      ConnectConsoleVariable - Connect each device path in a variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets a variable and walks through all the device
//      paths attempting to connect each controller. If the controller fails to
//      connect the device path is removed from the variable immediately.
//
//      If none of the device paths connect successfully this function returns
//      SCT_STATUS_NOT_FOUND.
//
//      If one or more controllers fail to load then that controller is removed
//      from the variable and this function returns SCT_STATUS_DEVICE_ERROR
//      after processing all devices.
//
//      If all controllers are successfully connected this function returns
//      SCT_STATUS_SUCCESS.
//
//      This function only processes variables in the gEfiGlobalVariableGuid
//      name space.
//
// ENTRY PARAMETERS.
//      VariableName    - the name of the variable to process.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
ConnectConsoleVariable (IN PCHAR16 VariableName)
{
  PCI_TYPE00 Pci;
  BOOLEAN AcpiAdr;
  SCT_STATUS Status;
  EFI_HANDLE Handle;
  UINT32 Attributes;
  UINTN VariableSize;
  BOOLEAN IsConnected;
  UINTN DevicePathSize;
  SCT_STATUS ReturnStatus;
  BOOLEAN IsConOutConnection = FALSE;
  EFI_PCI_IO_PROTOCOL *PciIo;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *VariableValue;
  EFI_DEVICE_PATH_PROTOCOL *DevicePathPosition;
  EFI_DEVICE_PATH_PROTOCOL *ExpandedDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *LastDevicePathNode;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_CON ("ConnectConsoleVariable: %s.\n", VariableName);

//#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND == 0
//  if (StrCmp (VariableName, EFI_CON_IN_VARIABLE_NAME ) == 0 ) {
//    return  SCT_STATUS_DEVICE_ERROR;
//  }
//#endif //OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND

  Status = SctLibGetEfiGlobalVariable (VariableName, &Attributes, &VariableSize, (VOID **) &VariableValue);
  if (EFI_ERROR (Status) || (VariableSize == 0)) {
    DPRINTF_CON ("  Can't find %s, %r.\n", VariableName, Status);
    return SCT_STATUS_NOT_FOUND;
  }

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE_ALWAYS
  if (StrCmp (VariableName, EFI_CON_OUT_VARIABLE_NAME ) == 0 ) {
    return  SCT_STATUS_NOT_FOUND;
  }
#else //OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE_ALWAYS
  if (StrCmp (VariableName, EFI_CON_OUT_VARIABLE_NAME ) == 0 ) {
    IsConOutConnection = TRUE;
  }
#endif //OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE_ALWAYS

  ReturnStatus = SCT_STATUS_DEVICE_ERROR;
  DevicePathPosition = VariableValue;
  for (DevicePath = GetNextDevicePathInstance (&DevicePathPosition, &DevicePathSize);
       DevicePath != NULL;
       DevicePath = GetNextDevicePathInstance (&DevicePathPosition, &DevicePathSize)
    ) {

    IsConnected = FALSE;
    AcpiAdr = FALSE;

    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
      DPRINTF_CON ("  %s.\n", Str);
      SafeFreePool (Str);
    });

    if (IsTerminalDevice (DevicePath)) {
      //
      // If UCR is disabled, Remove DevicePath From Console Variable.
      //
      if (mSystemConRedirect.UcrStatus == SCT_CONSOLE_REDIRECTION_STATUS_DISABLED) {
        RemoveDevicePathFromConsoleVariable (VariableName, DevicePath);
        continue;
      }
      //
      // If UCR is Enabled, do not connect terminal device by Console Variable.
      // Because we can not for sure the UcrType was match with this Console Variable.
      //
      if (mSystemConRedirect.UcrStatus == SCT_CONSOLE_REDIRECTION_STATUS_ENABLED) {
        continue;
      }
    }

    //
    // ConOut devices do not need to expand.
    //

    DPRINTF_CON ("IsConOutConnection:%d.\n", IsConOutConnection);

    if (IsConOutConnection == TRUE) {
      ExpandedDevicePath = DevicePath;
    } else {
      ExpandedDevicePath = ExpandOneDevicePath (DevicePath);
    }
    RemainingDevicePath = DuplicateDevicePath (ExpandedDevicePath);

    //
    // Check if the DevicePath excluded AcpiAdr is already connected to GOP
    //

    if (!IsConOutConnection || !IsGopProduced (ExpandedDevicePath)) {

      Status = ConnectDevicePath (ExpandedDevicePath, &Handle);
      DPRINTF_CON ("  ConnectDevicePath Result %r, Handle:0x%x\n", Status, Handle);

      if(!EFI_ERROR (Status) && (Handle != NULL)) {
        IsConnected = TRUE;
      }

      if((Status == EFI_NOT_FOUND) && (Handle != NULL)) {
        ConOutRemove (DevicePath);
        continue;
      }

      if (IsConOutConnection) {

        LastDevicePathNode = GetLastDeviceNode (DevicePath);
        if (LastDevicePathNode != NULL &&
          LastDevicePathNode->Type == ACPI_DEVICE_PATH &&
          LastDevicePathNode->SubType == ACPI_ADR_DP) {

          AcpiAdr = TRUE;
        }

        //
        // Refer to UEFI spec 2.3.1 - 11.10 Rules for PCI/AGP Devices
        // For ConOut connection, We will look for output device in the following cases,
        //
        // Case1: Connect failed w/ AcpiAdr, proceed to check reset device handle.
        //        The case can be assumed that output device is not available in the DevicePath.
        // Case2: Connect successfully w/o AcpiAdr
        //
        // In the case, we will do,
        //
        // 1. Connect with NULL RemainingDevicePath
        // 2. Select an output device from device paths which are created by GOP at #1 with EDID
        //    discovered protocol. It will be passed as RemainingDevicePath
        // 3. Reconnect with the RemainingDevicePath
        //

        if (((!IsConnected && (Handle != NULL) && AcpiAdr) ||
            (IsConnected && !AcpiAdr))) {

          //
          // Here, we check if the handle is for PCI device. If so, check the PCI class code
          // since the handle may be PCI root port or bridge.
          // If not, it is not a PCI device so we assume it is other graphic controller's
          // device path
          //

          PciIo = NULL;
          Pci.Hdr.ClassCode [0] = 0;
          Pci.Hdr.ClassCode [1] = 0;
          Pci.Hdr.ClassCode [2] = 0;
          Status = gBS->OpenProtocol (
                          Handle,
                          &gEfiPciIoProtocolGuid,
                          (VOID **) &PciIo,
                          mImageHandle,
                          NULL,
                          EFI_OPEN_PROTOCOL_GET_PROTOCOL);
          if (!EFI_ERROR (Status) && PciIo != NULL) {

            DPRINTF_CON ("  Rest handle is a PCI device\n");
            Status = PciIo->Pci.Read (
                                  PciIo,
                                  EfiPciIoWidthUint32,
                                  0,
                                  sizeof (Pci) / sizeof (UINT32),
                                  &Pci);
          } else {

            //
            // Make sure this handle is not a PciRootBridge.
            //

            Status = gBS->OpenProtocol (
                            Handle,
                            &gEfiPciRootBridgeIoProtocolGuid,
                            NULL,
                            mImageHandle,
                            NULL,
                            EFI_OPEN_PROTOCOL_TEST_PROTOCOL);
          }

          if ((PciIo == NULL && Status == EFI_UNSUPPORTED) ||
              (!EFI_ERROR (Status) && (IS_PCI_VGA (&Pci) || IS_PCI_OLD_VGA (&Pci) || IS_PCI_GFX (&Pci)))) {

            //
            // Set Status to EFI_SUCCESS to allow scanning for default
            // video output device.
            //
            Status = EFI_SUCCESS;

            if (!IsConnected) {
               if (!IsManagedByThunk (Handle) && (PcdGetBool (PcdBypassDisconnectGopHandler) == FALSE) ) {
                DPRINTF_CON ("Not ConnectByThunk.\n");
                //
                // When Vga control is not managed by thunk driver, it can disconnect device.
                // Disconnect the controller first to make sure it is not managed by any drivers and
                // all the possible output devices connected to this controller will be enumerated also.
                //
                gBS->DisconnectController (Handle, NULL, NULL);
              } // if (!IsManagedByThunk (Handle))

              //
              // Retry to connect with NULL RemainingDevicePath and non-recursive
              // if it is not connected
              //
              Status = gBS->ConnectController (
                               Handle,
                               mContextOverrideDriver,
                               NULL,
                               FALSE);
            }

            IsConnected = FALSE;
            if (!EFI_ERROR (Status)) {

              //
              // All child handles produced by VGA bus driver (THUNK or GOP) are available.
              // Then get RemainingDevicePath from GetGopAltChild() by OEM/ODM
              //

              RemainingDevicePath = NULL;
              GetGopAlternativeChild (Handle, &RemainingDevicePath);

              //
              // Observe STO protocol's installation at the connection to regist new DevicePath
              // to ConOut. This is necessary for ConSpliter
              //

              RegisterStoDeviceNotify ();
              Status = SelectDefaultVideoOutputDevice (Handle, RemainingDevicePath);
              if (!EFI_ERROR (Status)) {
                IsConnected = TRUE;
              }
              if (mStoDeviceAvailableEvent != NULL) {
                gBS->CloseEvent (mStoDeviceAvailableEvent);
                mStoDeviceAvailableEvent = NULL;
              }
            }
          } else {
            IsConnected = FALSE;
          }
        }
      }
    } else {

      //
      // GOP is already produced.  Set the status to EFI_SUCCESS to avoid
      // deleting ConOut variable.
      //

      ReturnStatus = EFI_SUCCESS;
    }

    DUMP_ALL_DEVICE_PATHS;
    if (IsConOutConnection != TRUE) {
      SafeFreePool (ExpandedDevicePath);
    }
    if (IsConnected) {
      ReturnStatus = SCT_STATUS_SUCCESS;
    } else {
      //if (StrCmp (VariableName, EFI_CON_IN_VARIABLE_NAME) == 0 && IsHotPlugDevice (DevicePath)) {
      //  ReturnStatus = SCT_STATUS_NOT_FOUND;
      if (IsConOutConnection)
      if (ReturnStatus == SCT_STATUS_DEVICE_ERROR) {
        ConOutRemove (DevicePath);
        break;
      }
    }
  }

  SafeFreePool (VariableValue);
  return ReturnStatus;
} // ConnectConsoleVariable


//
// FUNCTION NAME.
//      RemoveDevicePathFromConsoleVariable - Delete device path from variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets a console variable, finds the first occurrence of the
//      device path in the console variable, removes it, repacks the variable
//      and saves it.
//
//      This function only processes variables in the gEfiGlobalVariableGuid
//      name space.
//
// ENTRY PARAMETERS.
//      VariableName    - the console variable to process.
//      DevicePath      - a single-instance device path to be removed.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
RemoveDevicePathFromConsoleVariable (
  IN PCHAR16 VariableName,
  IN EFI_DEVICE_PATH_PROTOCOL *RemovePath
  )
{
  SCT_STATUS Status;

  UINTN VariableSize;
  UINT32 VariableAttributes;
  EFI_DEVICE_PATH_PROTOCOL *VariableValue;
  UINTN DevicePathSize;

  EFI_DEVICE_PATH_PROTOCOL *p, *q, *r;
  EFI_DEVICE_PATH_PROTOCOL *NewPath;

  DPRINTF_CON ("RemoveDevicePathFromConsoleVariable: %s, \n", VariableName);
  if (!IsBmDevicePathValid (RemovePath, 0)) {
    DPRINTF_CON ("RemovePath is not correct");
    return SCT_STATUS_NOT_FOUND;
  }
  DEBUG_CON ({
    CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (RemovePath, FALSE, TRUE);
    DPRINTF_CON ("%s.\n", Str);
    SafeFreePool (Str);
  });

  Status = SctLibGetEfiGlobalVariable (VariableName, &VariableAttributes, &VariableSize, (VOID **) &VariableValue);
  if (EFI_ERROR(Status)) {
    DPRINTF_CON ("  Can't find %s, %r.\n", VariableName, Status);
    return SCT_STATUS_NOT_FOUND;
  }
  DPRINTF_CON ("  VariableAttributes = 0x%x, &VariableSize = 0x%x.\n", VariableAttributes, VariableSize);
  DPRINTF_CON ("  VariableValue @ 0x%x:", VariableValue);
  if (!IsBmDevicePathValid (VariableValue, VariableSize)) {
    DPRINTF_CON ("Console variable is not correct, Type= 0x%x.\n", DevicePathType (VariableValue));
    DPRINTF_CON ("Delete Console variable!!!\n");
    Status = SetEfiGlobalVariable (VariableName, VariableAttributes, 0, NULL);
    return SCT_STATUS_NOT_FOUND;
  }
  DEBUG_CON ({
    CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (VariableValue, FALSE, TRUE);
    DPRINTF_CON ("%s.\n", Str);
    SafeFreePool (Str);
  });

  NewPath = NULL;
  p = VariableValue;
  while (TRUE) {
    q = GetNextDevicePathInstance (&p, &DevicePathSize);
    if (q == NULL) {
      break;
    }
    if (!CompareDevicePath (q, RemovePath)) {
      r = NewPath;                      // save a pointer to the buffer to free.
      NewPath = AppendDevicePathInstance (NewPath, q);
      SafeFreePool (r);                 // free the old buffer.
    }
    SafeFreePool (q);                   // free this instance.
  }

  SafeFreePool (VariableValue);         // free the old variable buffer.
  VariableSize = GetDevicePathSize (NewPath);
  DPRINTF_CON ("  VariableAttributes = 0x%x, &VariableSize = 0x%x.\n", VariableAttributes, VariableSize);
  DPRINTF_CON ("  VariableValue @ 0x%x:", NewPath);
  DEBUG_CON ({
    CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (NewPath, FALSE, TRUE);
    DPRINTF_CON ("%s.\n", Str);
    SafeFreePool (Str);
  });
  Status = SetEfiGlobalVariable (VariableName, VariableAttributes, VariableSize, NewPath);
  SafeFreePool (NewPath);               // free the new variable buffer.
  return Status;
} // RemoveDevicePathFromConsoleVariable


//
// FUNCTION NAME.
//      IsDevicePathExisted - Check if a device path has already existed
//      in the other one.
//
// FUNCTIONAL DESCRIPTION.
//      This function will go through device path Dp1 to see if Dp2 is in it.
//
// ENTRY PARAMETERS.
//      Dp1             - Main device path
//      Dp2             - Sub device path
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN.
//

BOOLEAN
IsDevicePathExisted (
  IN EFI_DEVICE_PATH_PROTOCOL *Dp1,
  IN EFI_DEVICE_PATH_PROTOCOL *Dp2
  )
{
  EFI_DEVICE_PATH_PROTOCOL *p;
  EFI_DEVICE_PATH_PROTOCOL *q;
  UINTN DevicePathSize;

  if ((Dp1 == NULL) || (Dp2 == NULL)) {
    return FALSE;
  }

  p = Dp1;
  q = GetNextDevicePathInstance (&p, &DevicePathSize);

  for (; q != NULL; q = GetNextDevicePathInstance (&p, &DevicePathSize)) {
    if (CompareDevicePath (q, Dp2)) {
      SafeFreePool (q);
      return TRUE;
    }
    SafeFreePool (q);
  }
  return FALSE;
}


//
// FUNCTION NAME.
//      CheckDeviceExist - Check if a device path is still presenting
//      in the system.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if a device path exists or not.
//
// ENTRY PARAMETERS.
//      DevicePath  - Device Path to be evaluated
//
// EXIT PARAMETERS.
//      Function Return - EFI_STATUS.
//

EFI_STATUS
CheckDeviceExist (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL  *RemainingDevicePath;

  DeviceHandle = NULL;
  RemainingDevicePath = DevicePath;
  Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &DeviceHandle);
  DPRINTF_CON ("LocateDevicePath Status:[%r]\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DEBUG_CON ({
    DPRINTF_CON ("DeviceHandle:[0x%x]\n", Status, DeviceHandle);
    if (RemainingDevicePath) {
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (RemainingDevicePath, FALSE, TRUE);
      DPRINTF_CON ("RemainingDevicePath = [%s], StrLen = (%d).\n", Str, StrLen(Str));
      SafeFreePool (Str);
    }
  });

  if (IsDevicePathEnd (RemainingDevicePath)) {
    Status = EFI_SUCCESS;
  } else {
    Status = EFI_MEDIA_CHANGED;
  }

  return Status;
}


//
// FUNCTION NAME.
//      AddDevicePathToConsoleVariable - Add a device path to a variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function adds a console device path to a console variable. If the
//      variable does not exist it will be created.
//
//      Only variables whose data is a multi-instance device path should be
//      modified with this function.
//
//      This function only processes variables in the gEfiGlobalVariableGuid
//      name space.
//
// ENTRY PARAMETERS.
//      VariableName    - the console variable to process.
//      DevicePath      - a single-instance device path to be added.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
AddDevicePathToConsoleVariable (
  IN PCHAR16 VariableName,
  IN EFI_DEVICE_PATH_PROTOCOL *AddPath
  )
{
  SCT_STATUS Status;
  UINTN VariableSize;
  UINT32 VariableAttributes;
  EFI_DEVICE_PATH_PROTOCOL *VariableValue;
  UINTN DevicePathSize;
  EFI_DEVICE_PATH_PROTOCOL *NewPath;
  EFI_DEVICE_PATH_PROTOCOL *CleanedVariableValue;
  EFI_DEVICE_PATH_PROTOCOL *TerminalDp;
  EFI_DEVICE_PATH_PROTOCOL *p;
  EFI_DEVICE_PATH_PROTOCOL *q;
  BOOLEAN ProcessDpRequired;
  BOOLEAN SetVariableRequired;

  ProcessDpRequired = TRUE;
  SetVariableRequired = FALSE;

  DPRINTF_CON ("Entry\n");
  DPRINTF_CON ("VariableName: %s\n", VariableName);

  DEBUG_CON ({
    CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (AddPath, FALSE, TRUE);
    DPRINTF_CON ("Path %s.\n", Str);
    SafeFreePool (Str);
  });

  if (AddPath == NULL) {
    return EFI_SUCCESS;
  }

  Status = SctLibGetEfiGlobalVariable (
             VariableName,
             &VariableAttributes,
             &VariableSize,
             (VOID **) &VariableValue);
  if (EFI_ERROR (Status)) {
    DPRINTF_CON ("Can't find %s, %r.\n", VariableName, Status);
    VariableSize = 0;
    VariableValue = NULL;
    VariableAttributes = VARIABLE_ATTRIBUTE_NV_BS_RT;

  } else {
    DPRINTF_CON ("VariableAttributes = 0x%x, &VariableSize = 0x%x.\n", VariableAttributes, VariableSize);
    DPRINTF_CON ("VariableValue @ 0x%x:\n", VariableValue);
    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (VariableValue, FALSE, TRUE);
      DPRINTF_CON ("VariableText %s.\n", Str);
      SafeFreePool (Str);
    });

    //
    // Filter invalid and duplicated device paths
    //
    CleanedVariableValue = NULL;
    p = VariableValue;
    q = GetNextDevicePathInstance (&p, &DevicePathSize);
    for (; q != NULL; q = GetNextDevicePathInstance (&p, &DevicePathSize)) {
      Status = CheckDeviceExist (q);
      if (EFI_ERROR (Status)) {
        // This device path is no longer existed, remove it from console variable.
        SetVariableRequired = TRUE;
      } else {
        if (IsDevicePathExisted (CleanedVariableValue, q)) {
          // Duplicated device path found in console variable. Remove it.
          SetVariableRequired = TRUE;
        } else {
          CleanedVariableValue = AppendDevicePathInstance (CleanedVariableValue, q);
        }
      }

      if (CompareDevicePath (q, AddPath)) {
        // The AddPath has already been listed in the variable. No need to process the variable again.
        ProcessDpRequired = FALSE;
        DPRINTF_CON ("Duplicated \n");
      }

      SafeFreePool (q);
    }

    SafeFreePool (VariableValue);
    VariableValue = CleanedVariableValue;

    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (VariableValue, FALSE, TRUE);
      DPRINTF_CON ("[After clean up] VariableText %s.\n", Str);
      SafeFreePool (Str);
    });
  }

  DPRINTF_CON ("ProcessDpRequired: %d\n", ProcessDpRequired);
  DPRINTF_CON ("SetVariableRequired: %d\n", SetVariableRequired);

  if (!ProcessDpRequired) {
    NewPath = VariableValue;
  } else {
    //
    // Process all device paths
    //
    if (VariableValue == NULL) {
      NewPath = AppendDevicePathInstance (NULL, AddPath);
    } else {
      p = VariableValue;
      q = GetNextDevicePathInstance (&p, &DevicePathSize);
      NewPath = NULL;
      TerminalDp = NULL;
      for (; q != NULL; q = GetNextDevicePathInstance (&p, &DevicePathSize)) {
        if (IsTerminalDevice (q)) {
          TerminalDp = AppendDevicePathInstance (TerminalDp, q);
        } else {
          NewPath = AppendDevicePathInstance (NewPath, q);
        }
        SafeFreePool (q);                   // free this instance.
      } // for

#if OPTION_SUPPORT_MULTI_TERMINAL_DEVICE_PATH
      //
      // If OPTION_SUPPORT_MULTI_TERMINAL_DEVICE_PATH is 1,
      // we keep all discovered terminal device path in console variable.
      // Device path combination order:
      //   if AddPath is terminal device:
      //     AddPath -> Previously discovered terminal device (TerminalDp) -> Other remaining device paths (NewPath).
      //   else:
      //     Previously discovered terminal device (TerminalDp) -> AddPath -> Other remaining device paths (NewPath).
      //
      if (IsTerminalDevice (AddPath)) {
        if (TerminalDp == NULL) {
          TerminalDp = AppendDevicePathInstance (NULL, AddPath);
        } else {
          TerminalDp = AppendDevicePathInstance (AddPath, TerminalDp);
        }
        if (NewPath == NULL) {
          NewPath = AppendDevicePathInstance (NULL, TerminalDp);
        } else {
          NewPath = AppendDevicePathInstance (TerminalDp, NewPath);
        }
      } else {
        if (NewPath == NULL) {
          NewPath = AppendDevicePathInstance (NULL, AddPath);
        } else {
          NewPath = AppendDevicePathInstance (NewPath, AddPath);
        }
        if (TerminalDp != NULL) {
          NewPath = AppendDevicePathInstance (TerminalDp, NewPath);
        }
      }
#else // OPTION_SUPPORT_MULTI_TERMINAL_DEVICE_PATH
      //
      // If OPTION_SUPPORT_MULTI_TERMINAL_DEVICE_PATH is 0,
      // we only keep 1 terminal device path in console variable
      // Device path combination order:
      //   if AddPath is terminal device:
      //     AddPath -> Other remaining device paths.
      //   else:
      //     Previously discovered terminal device (TerminalDp) -> AddPath -> Other remaining device paths (NewPath).
      //
      if (IsTerminalDevice (AddPath)) {
        if (NewPath == NULL) {
          NewPath = AppendDevicePathInstance (NULL, AddPath);
        } else {
          NewPath = AppendDevicePathInstance (AddPath, NewPath);
        }
      } else {
        if (NewPath == NULL) {
          NewPath = AppendDevicePathInstance (NULL, AddPath);
        } else {
          NewPath = AppendDevicePathInstance (AddPath, NewPath);
        }
        if (TerminalDp != NULL) {
          NewPath = AppendDevicePathInstance (TerminalDp, NewPath);
        }
      }
#endif// OPTION_SUPPORT_MULTI_TERMINAL_DEVICE_PATH

      SafeFreePool (TerminalDp);            // Free old variable buffer.
      SafeFreePool (VariableValue);         // Free old variable buffer.
    }

    SetVariableRequired = TRUE;
  }

  if (SetVariableRequired) {
    VariableSize = GetDevicePathSize (NewPath);

    DPRINTF_CON ("Setting:%s.\n", VariableName);
    DPRINTF_CON ("VariableAttributes = 0x%x, VariableSize = 0x%x.\n", VariableAttributes, VariableSize);
    DPRINTF_CON ("VariableValue @ 0x%x:\n", NewPath);
    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (NewPath, FALSE, TRUE);
      DPRINTF_CON ("New Path %s.\n", Str);
      SafeFreePool (Str);
    });

  //
  // Write the new variable value and cleanup. Return with the status of the
  // call to SetVariable.
  //

    Status = SetEfiGlobalVariable (
               VariableName,
               VariableAttributes,
               VariableSize,
               NewPath);
  }

  SafeFreePool (NewPath);               // free new variable buffer.
  return Status;
} // AddDevicePathToConsoleVariable


//
// FUNCTION NAME.
//      GetConsoleByVariable - Get Console by Variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function call GetConsoleVariable to get the device paths
//      in the VariableName.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
GetConsoleByVariable (
  IN PCHAR16 VariableName,
  OUT UINTN  *VariableSize
  )
{
  UINTN DataSize;
  SCT_STATUS Status;

  DPRINTF_CON ("GetConsoleByVariable: %s.\n", VariableName);

  DataSize = 0;
  Status = SctLibGetEfiGlobalVariable (
             VariableName,
             NULL,
             &DataSize,
             NULL);

  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }


  *VariableSize = DataSize;
  DPRINTF_CON ("GetConsoleByVariable: Size=%x.\n", DataSize);

  return EFI_SUCCESS;
} // GetConsoleByVariable

//
// FUNCTION NAME.
//      ConnectConsoleRedirectByVariable - connect ConsoleRedirection by Variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function call to connect ConsoleRedirection.
//      in the VariableName.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//


SCT_STATUS
EFIAPI
ConnectConsoleRedirectByVariable (
  IN PCHAR16 VariableName,
  IN UINTN  VariableSize
  )
{
  UINTN DataSize;
  SCT_STATUS Status;

  DPRINTF_CON ("ConnectConsoleRedirectByVariable: %s., Size=%x\n", VariableName, VariableSize);

  DataSize = 0;
  Status = SctLibGetEfiGlobalVariable (
             VariableName,
             NULL,
             &DataSize,
             NULL);

  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  if (VariableSize != DataSize) {
    ConInInit ();
    ConOutInit ();
    ErrOutInit ();
  }

  DPRINTF_CON ("ConnectConsoleRedirectByVariable: DataSize=%x.\n", DataSize);

  return EFI_SUCCESS;
} // ConnectConsoleRedirectByVariable

//
// FUNCTION NAME.
//      ConnectConsoleByVariable - Initialize Console by Variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function call ConnectConsoleVariable to connect the device paths
//      in the VariableName.
//
//      If the VariableName fails to provide any connectable devices this function
//      loads the project defaults.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConnectConsoleByVariable (IN PCHAR16 VariableName)
{
  EFI_HANDLE Handle;
  SCT_STATUS Status, rc;
  PBOOT_MANAGER_CONNECTION_DEVICE p;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *LastDevicePathNode;
  EFI_DEVICE_PATH_PROTOCOL *ControllerDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *ExpandedDevicePath;

  DPRINTF_CON ("(%s) {\n", VariableName);

  Status = ConnectConsoleVariable (VariableName);
  if (!EFI_ERROR (Status)) {
    DPRINTF_CON ("  The console variable connected successfully.\n");
    return Status;
  } else {
    rc = Status;
  }

  //
  // Get the Connection list for this variable.
  //

  if (StrCmp (VariableName, EFI_CON_IN_VARIABLE_NAME) == 0) {
    p = mConsoleInList;
  } else if (StrCmp (VariableName, EFI_CON_OUT_VARIABLE_NAME) == 0) {
#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE
    RegisterStoDeviceNotify ();
    Status = AutoDetectPciVgaDevice ();
    DPRINTF_CON ("  AutoDetectPciVgaDevice Ret [%r]\n", Status);
    if (mStoDeviceAvailableEvent != NULL) {
      gBS->CloseEvent (mStoDeviceAvailableEvent);
      mStoDeviceAvailableEvent = NULL;
    }
    return Status;
#else
    p = mConsoleOutList;
#endif
  } else if (StrCmp (VariableName, EFI_ERR_OUT_VARIABLE_NAME) == 0) {
    p = mStandardErrList;
  } else {
    DPRINTF_CON ("  Not recognized as a console variable.\n");
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Process the connection list for this variable. If any connection succeeds
  // the return code will be success, otherwise the return code will be not
  // found.
  //

  rc = SCT_STATUS_NOT_FOUND;
  while (p->TextDevicePath != NULL) {
    DevicePath = NULL;
    DevicePath = BM_CONVERT_TEXT_TO_DEVICE_PATH (p->TextDevicePath);
    if (DevicePath == NULL) {
      DPRINTF_CON ("  Failed to convert %s to a device path.\n", p->TextDevicePath);
      p++;
      continue;
    }

    //
    // Expand this device path.
    //

    ExpandedDevicePath = ExpandOneDevicePath (DevicePath);

    if (StrCmp (VariableName, EFI_CON_OUT_VARIABLE_NAME) == 0) {
      ControllerDevicePath = DuplicateDevicePath (ExpandedDevicePath);
      LastDevicePathNode = GetLastDeviceNode (ControllerDevicePath);
      if (LastDevicePathNode != NULL &&
          LastDevicePathNode->Type == ACPI_DEVICE_PATH &&
          LastDevicePathNode->SubType == ACPI_ADR_DP) {
        SetDevicePathEndNode (LastDevicePathNode);
        if (!IsGopProduced (ControllerDevicePath)) {

          //
          // Connect VGA without RemainingDevicePath first.
          //

          Status = ConnectDevicePath (ControllerDevicePath, &Handle);
        }
      }
      SafeFreePool (ControllerDevicePath);
    }

    //
    // We must add the device path to the ConIn variable before connection
    // so that the ConPlatform driver will add the GUID to the handle that
    // signals the ConSplitter driver to use this device.
    //
#if OPTION_SYSTEM_BOOT_MANAGER_ADD_HOTPLUG_CON_IN
    AddDevicePathToConsoleVariable (VariableName, ExpandedDevicePath);
#else
    if (StrCmp (VariableName, EFI_CON_IN_VARIABLE_NAME) == 0)
      if (!IsHotPlugDevice (ExpandedDevicePath))
        AddDevicePathToConsoleVariable (VariableName, ExpandedDevicePath);
#endif

    //
    // Now connect the device path.
    //

    Status = ConnectDevicePath (ExpandedDevicePath, &Handle);

    //
    // If the device path fails to connect remove it from the ConIn variable.
    //

    if (EFI_ERROR(Status)) {
      DPRINTF_CON ("  Failed to connect %s:%s.\n", VariableName, p->TextDevicePath);
      RemoveDevicePathFromConsoleVariable (VariableName, ExpandedDevicePath);

    } else {
      rc = SCT_STATUS_SUCCESS;
    }

    //
    // Free resources and advance p to the next Connect object.
    //

    SafeFreePool (DevicePath);
    SafeFreePool (ExpandedDevicePath);
    p++;
  }

  return rc;
} // ConnectConsoleByVariable

//
// FUNCTION NAME.
//      IsHotPlugDevice - Check if the device supports hot-plug through its device path.
//
// FUNCTIONAL DESCRIPTION.
//      This function could be updated to check more types of Hot Plug devices.
//      Currently, it checks USB and PCCard device.
//
// ENTRY PARAMETERS.
//      DevicePath      - Pointer to device's device path.
//
// EXIT PARAMETERS.
//      TRUE            - The devcie is a hot-plug device.
//      FALSE           - The devcie is not a hot-plug device.
//

BOOLEAN
IsHotPlugDevice (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  EFI_DEVICE_PATH_PROTOCOL *CheckDevicePath;

  CheckDevicePath = DevicePath;
  while (!IsDevicePathEnd (CheckDevicePath)) {

    //
    // Check device whether is hot plug device or not throught Device Path.
    //

    if ((DevicePathType (CheckDevicePath) == MESSAGING_DEVICE_PATH) &&
        (DevicePathSubType (CheckDevicePath) == MSG_USB_DP ||
         DevicePathSubType (CheckDevicePath) == MSG_USB_CLASS_DP ||
         DevicePathSubType (CheckDevicePath) == MSG_USB_WWID_DP)) {

      //
      // If Device is USB device.
      //

      return TRUE;
    }
    if ((DevicePathType (CheckDevicePath) == HARDWARE_DEVICE_PATH) &&
        (DevicePathSubType (CheckDevicePath) == HW_PCCARD_DP)) {

      //
      // If Device is PCCard.
      //

      return TRUE;
    }

    CheckDevicePath = NextDevicePathNode (CheckDevicePath);
  }
  return FALSE;
} // IsHotPlugDevice

#if OPTION_SYSTEM_BOOT_MANAGER_ADD_HOTPLUG_CON_IN
//
// FUNCTION NAME.
//      AddAllHotPlugConInDeviceToVariable - Store all ConIn device paths to variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function will retrieve all handles with Simple Text Input protocol
//      attached and also check to see if the device is a Hot Plug Device.
//      If the devices are met, store their corresponding device path to
//      ConIn variable.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
AddAllHotPlugConInDeviceToVariable (VOID)
{
  UINTN Index;
  UINTN HandleCount;
  SCT_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  DPRINTF_CON ("Start \n");

  Index = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleTextInProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  if (EFI_ERROR(Status) || HandleCount == 0) {
    DPRINTF_CON ("  There is no any device with SimpleTextInProtocol installed");
    return Status;
  }

  for (Index = 0; Index < HandleCount; Index++) {

    DevicePath = NULL;
    Status = gBS->HandleProtocol (
                    HandleBuffer [Index],
                    &gEfiDevicePathProtocolGuid,
                    (VOID**)&DevicePath);
    if (EFI_ERROR (Status) || DevicePath == NULL || !IsHotPlugDevice (DevicePath)) {
      continue;
    }

    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
      DPRINTF_CON ("  %s.\n", Str);
      SafeFreePool (Str);
    });

    Status = ConInAdd (DevicePath);
    DPRINTF_CON ("  ConInAdd Result:%r \n", Status);
    if (EFI_ERROR (Status)) {
      break;
    }
  }

  if (HandleBuffer != NULL) {
    FreePool (HandleBuffer);
  }
  DPRINTF_CON ("End \n");

  return Status;
} // AddAllHotPlugConInDeviceToVariable
#endif //OPTION_SYSTEM_BOOT_MANAGER_ADD_HOTPLUG_CON_IN

//
// FUNCTION NAME.
//      UpdateConOutVariable - Callback function to store device path to ConOut variable.
//
// FUNCTIONAL DESCRIPTION.
//      This function will be invoked when any EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL protocol
//      be installed onto the handle.
//      This function will also store the corresponding device path attached on
//      the handle into ConOut variable.
//
// ENTRY PARAMETERS.
//      Event           - Event instance (It is not used)
//      Context         - Event Context (It is not used)
//
// EXIT PARAMETERS.
//      None.
//

VOID
EFIAPI
UpdateConOutVariable (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  EFI_STATUS Status;
  EFI_HANDLE Handle;
  UINTN HandleBufferSize;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  BOOLEAN IsGopConOutFound;

  DPRINTF_CON ("\n");
  IsGopConOutFound = FALSE;

  while (TRUE) {

    HandleBufferSize = sizeof (Handle);
    Handle = NULL;
    DevicePath = NULL;

    Status = gBS->LocateHandle (
                    ByRegisterNotify,
                    &gEfiSimpleTextOutProtocolGuid,
                    mStoDeviceRegistration,
                    &HandleBufferSize,
                    &Handle);
    if (EFI_ERROR (Status) || Handle == NULL) {
      break;
    }

    //
    // Get the devicePath from the handle.
    //

    DevicePath = DevicePathFromHandle (Handle);

    if (DevicePath == NULL) {
      continue;
    }

    //
    // Check EFI_GRAPHIC_OUTPUT_PROTOCOL.
    //

    Status = gBS->OpenProtocol (
                    Handle,             // the handle being tested.
                    &gEfiGraphicsOutputProtocolGuid,
                    NULL,               // interface.
                    mImageHandle,       // the handle who is testing.
                    NULL,               // no controller handle.
                    EFI_OPEN_PROTOCOL_TEST_PROTOCOL);

    DPRINTF_CON ("  Test EFI_GRAPHIC_OUTPUT_PROTOCOL result %r\n", Status);
    if (EFI_ERROR (Status)) {
      continue;
    }

    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
      DPRINTF_CON ("  %s.\n", Str);
      SafeFreePool (Str);
    });

    //
    // Add devicePath into "ConOut" variable.
    //

    IsGopConOutFound = TRUE;
    Status = ConOutAdd (DevicePath);
    DPRINTF_CON (" ConOutAdd Return %r\n", Status);
    ErrOutAdd (DevicePath);
  }

  if (IsGopConOutFound) {
    gBS->CloseEvent (Event);
    mStoDeviceAvailableEvent = NULL;
  }

} // UpdateConOutVariable


//
// FUNCTION NAME.
//      RegisterStoDeviceNotify - Register a callback function for EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL protocol.
//
// FUNCTIONAL DESCRIPTION.
//      This function will register a callback function for the notification when
//      EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL protocol installed.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

SCT_STATUS
RegisterStoDeviceNotify (VOID)
{
  SCT_STATUS Status;

  DPRINTF_CON ("\n");

  //
  // Register a callback for any EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL installed.
  //

  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  UpdateConOutVariable,
                  NULL,
                  &mStoDeviceAvailableEvent);

  if (EFI_ERROR (Status)) {
    mStoDeviceAvailableEvent = NULL;
    return Status;
  }

  return gBS->RegisterProtocolNotify (
                &gEfiSimpleTextOutProtocolGuid,
                mStoDeviceAvailableEvent,
                &mStoDeviceRegistration);

} // RegisterStoDeviceNotify

#if OPTION_SYSTEM_BOOT_MANAGER_AUTO_DETECT_VGA_DEVICE


//
// FUNCTION NAME.
//      AutoDetectPciVgaDevice - Detect PCI VGA device automatically.
//
// FUNCTIONAL DESCRIPTION.
//      This function will detect the PCI VGA devices and initialize the found
//      VGA to support console.
//      This function will be invoked when BootManager failed to initialize the
//      VGA console out devices according to "ConOut" variable.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
AutoDetectPciVgaDevice (VOID)
{
  UINTN Index;
  PCI_TYPE00 Pci;
  SCT_STATUS Status;
  EFI_HANDLE *PciHandles;
  UINTN NumberOfPciHandle;
  EFI_PCI_IO_PROTOCOL *PciIo;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;

  DPRINTF_CON ("\n");
  Status = EFI_NOT_FOUND;

  //
  // Connect all PCI devices first.
  //

  ConnectAllPciDevices ();

  //
  // Locate all PCI devices.
  //

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &NumberOfPciHandle,
                  &PciHandles);

  if (EFI_ERROR (Status) || NumberOfPciHandle == 0) {
    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index < NumberOfPciHandle; Index++) {

    DEBUG_CON ({
      EFI_DEVICE_PATH_PROTOCOL *DevicePath= NULL;
      Status = gBS->HandleProtocol (
                      PciHandles [Index],
                      &gEfiDevicePathProtocolGuid,
                      (VOID **)&DevicePath);
      if (!EFI_ERROR (Status)) {
        CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
        DPRINTF_CON ("  %s.\n", Str);
        SafeFreePool (Str);
      }
    });

    Status = gBS->HandleProtocol (
                    PciHandles [Index],
                    &gEfiPciIoProtocolGuid,
                    (VOID **)&PciIo);

    if (!EFI_ERROR (Status)) {

      Status = PciIo->Pci.Read (
                            PciIo,
                            EfiPciIoWidthUint32,
                            0,
                            sizeof (Pci) / sizeof (UINT32),
                            &Pci);
      if (!EFI_ERROR (Status)) {

        DPRINTF_CON ("  PCI CLASS CODE    = 0x%x\n", Pci.Hdr.ClassCode [2]);
        DPRINTF_CON ("  PCI SUBCLASS CODE = 0x%x\n", Pci.Hdr.ClassCode [1]);

        if (IS_PCI_VGA (&Pci) || IS_PCI_OLD_VGA (&Pci) || IS_PCI_GFX (&Pci)) {

          DPRINTF_CON ("  \nPCI VGA Device Found\n");

          //
          // Try to connect VGA device.
          //

          Status = gBS->ConnectController (
                          PciHandles [Index],
                          mContextOverrideDriver,
                          NULL,
                          FALSE);
          DPRINTF_CON ("  ConnectController Returned %r\n", Status);

          RemainingDevicePath = NULL;
          GetGopAlternativeChild (PciHandles [Index], &RemainingDevicePath);

          DEBUG_CON ({
            if (!EFI_ERROR (Status)) {
              CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (RemainingDevicePath, FALSE, TRUE);
              DPRINTF_CON (" Alternative Child Dp  %s.\n", Str);
              SafeFreePool (Str);
            }
          });

          SelectDefaultVideoOutputDevice (PciHandles [Index], RemainingDevicePath);

          //
          // If the event has been closed, it means there is one handle with
          // EFI_GRAPHIC_OUTPUT_PROTOCOL and EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL produced
          // during ConnectController.
          //

          if (mStoDeviceAvailableEvent == NULL) {
            break;
          }
        }
      }
    }
  }

  if (Index != NumberOfPciHandle) {
    Status = EFI_SUCCESS;
  }

  //
  // Freed the allocated resources.
  //

  SafeFreePool (PciHandles);

  return Status;
} // AutoDetectPciVgaDevice

#endif


//
// FUNCTION NAME.
//      SignalConsoleReady - Signal that console is ready for display.
//
// FUNCTIONAL DESCRIPTION.
//      Signal that console is ready for display.
//
// ENTRY PARAMETERS.
//      None
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
SignalConsoleReady (VOID)
{
  EFI_STATUS Status;
  EFI_HANDLE ConsoleReadyHandle;


  DPRINTF_CON ("SignalConsoleReady\n");
  ConsoleReadyHandle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &ConsoleReadyHandle,
                  &gSctConsoleReadyProtocolGuid,
                  NULL,
                  NULL);

  return Status;
} // SignalConsoleReady

//
// FUNCTION NAME.
//      ReConnectVgaToThunkDriver - Re-connect the VGA to Thunk driver.
//
// FUNCTIONAL DESCRIPTION.
//      This function will disconnect the EFI VGA driver and let VGA Thunk driver
//      take control of the current VGA device.
//
//      This function will expect there is ONLY one physical GOP instance in the system.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
ReConnectVgaToThunkDriver (VOID)
{
  UINTN i;
  UINTN Index;
  VOID *Interface;
  EFI_STATUS Status;
  EFI_HANDLE VgaHandle;
  UINTN EntryCount;
  UINTN NumberOfHandles;
  EFI_HANDLE *HandleBuffer;
  EFI_HANDLE *ConnectHandleBuffer;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *OpenInfoBuffer;

  DPRINTF_CON ("\n");
  DevicePath = NULL;

  //
  // Get current GOP device handle.
  //

  NumberOfHandles = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiGraphicsOutputProtocolGuid,
                  NULL,
                  &NumberOfHandles,
                  &HandleBuffer);
  DPRINTF_CON ("  Number of GOP handles = %d\n", NumberOfHandles);

  if (EFI_ERROR (Status) || NumberOfHandles == 0) {
    return EFI_NOT_FOUND;
  }

  //
  // Check if current GOP device handle is produced by Thunk driver.
  //

  for (i = 0; i < NumberOfHandles; i++)  {

    DevicePath = NULL;
    DevicePath = DevicePathFromHandle (HandleBuffer [i]);
    if (DevicePath == NULL) {
      continue;
    }

    //
    // Find the parent VGA handle.
    //

    RemainingDevicePath = DevicePath;
    VgaHandle = NULL;
    Status = gBS->LocateDevicePath (
                    &gEfiPciIoProtocolGuid,
                    &RemainingDevicePath,
                    &VgaHandle);

    if (!EFI_ERROR (Status) && VgaHandle != NULL) {

      //
      // Check if this handle is managed by legacy THUNK driver.
      //

      Status = gBS->OpenProtocolInformation (
                      VgaHandle,
                      &gEfiPciIoProtocolGuid,
                      &OpenInfoBuffer,
                      &EntryCount);
      if (EFI_ERROR (Status)) {
        continue;
      }

      for (Index = 0; Index < EntryCount; Index++) {
        if ((OpenInfoBuffer [Index].Attributes & EFI_OPEN_PROTOCOL_BY_DRIVER) != 0) {
          Status = gBS->HandleProtocol (
                          OpenInfoBuffer [Index].AgentHandle,
                          &gEfiLegacyBiosGuid,
                          (VOID **)&Interface);
          if (!EFI_ERROR (Status)) {
            DPRINTF_CON ("  Thunk driver has already managed the VGA.\n");
            SafeFreePool (HandleBuffer);
            FreePool (OpenInfoBuffer);
            return EFI_SUCCESS;
          }
        }
      }
      FreePool (OpenInfoBuffer);
    }
  }

  SafeFreePool (HandleBuffer);

  //
  // Find the parent handle.
  //

  if (DevicePath == NULL) {
    return EFI_NOT_FOUND;
  }

  //
  // GOP is not produced by Video Thunk Driver.
  //

  DEBUG_CON ({
    CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
    DPRINTF_CON ("  %s.\n", Str);
    SafeFreePool (Str);
  });

  RemainingDevicePath = DevicePath;
  VgaHandle = NULL;
  Status = gBS->LocateDevicePath (
                  &gEfiPciIoProtocolGuid,
                  &RemainingDevicePath,
                  &VgaHandle);

  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  RemainingDevicePath = DuplicateDevicePath (RemainingDevicePath);
  if (RemainingDevicePath == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Disconnect the EFI driver.
  //

  Status = gBS->DisconnectController (VgaHandle, NULL, NULL);
  DPRINTF_CON ("  DisconnectController %r\n", Status);

  //
  // Find all the Thunk Drivers.
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
    SafeFreePool (RemainingDevicePath);
    return EFI_NOT_FOUND;
  }

  Status = (gBS->AllocatePool) (
                  EfiBootServicesData,
                  sizeof (EFI_HANDLE) * (NumberOfHandles + 1),
                  (VOID **)&ConnectHandleBuffer);
  if (EFI_ERROR (Status)) {
    SafeFreePool (HandleBuffer);
    SafeFreePool (RemainingDevicePath);
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (
    ConnectHandleBuffer,
        HandleBuffer,
        sizeof (EFI_HANDLE) * NumberOfHandles);
  ConnectHandleBuffer [NumberOfHandles] = NULL;
  SafeFreePool (HandleBuffer);

  //
  // Connect VGA to Thunk drivers.
  //

  Status = gBS->ConnectController (
                  VgaHandle,
                  ConnectHandleBuffer,
                  RemainingDevicePath,
                  TRUE);
  DPRINTF_CON ("  ConnectController %r\n", Status);
  SafeFreePool (ConnectHandleBuffer);
  SafeFreePool (RemainingDevicePath);
  return Status;

} // ReConnectVgaToThunkDriver

//
// FUNCTION NAME.
//      SelectDefaultVideoOutputDevice - Try to activate a default video output device.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to activate a default video output device.
//
//      If *RemainingDevicePath* parameter is provided, this function will start
//      the device via ConnectController immediately.
//
// ENTRY PARAMETERS.
//      Handle          - PCI Controller handle.
//      RemainingDevicePath - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

static
SCT_STATUS
SelectDefaultVideoOutputDevice (
  IN EFI_HANDLE Handle,
  IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath OPTIONAL)
{
  EFI_DEVICE_PATH_PROTOCOL *LastDevicePathNode;

  //
  // Check input parameters first.
  //

  if (Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Endpoint *MUST* be a device path with ACPI_DEVICE_PATH type and ACPI_ADR_DP sub-type
  // or End of Device Path Node
  //

  LastDevicePathNode = GetLastDeviceNode (RemainingDevicePath);

  if ((RemainingDevicePath != NULL) &&
      (((LastDevicePathNode->Type == ACPI_DEVICE_PATH) &&
        (LastDevicePathNode->SubType == ACPI_ADR_DP)) ||
       (LastDevicePathNode->Type == END_DEVICE_PATH_TYPE))) {

    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (RemainingDevicePath, FALSE, TRUE);
      DPRINTF_CON ("  RemainingDevicePath = %s.\n", Str);
      SafeFreePool (Str);
    });

    return gBS->ConnectController (
                  Handle,
                  NULL,
                  RemainingDevicePath,
                  TRUE);
  }

  return gBS->ConnectController (
                Handle,
                NULL,
                NULL,
                TRUE);
} // SelectDefaultVideoOutputDevice


//
// FUNCTION NAME.
//      IsGopProduced - Check if the VGA controller has produced any GOP.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the associated VGA controller has
//      produced any EFI_GRAPHIC_OUTPUT_PROTOCOL.
//
// ENTRY PARAMETERS.
//      DevicePath - Pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      BOOLEAN - Yes, the VGA controller has produced any GOP.
//

static
BOOLEAN
IsGopProduced (IN EFI_DEVICE_PATH_PROTOCOL *DevicePath)
{
  UINTN Index;
  UINTN HandleCount;
  EFI_STATUS Status;
  BOOLEAN Connected;
  EFI_HANDLE *HandleBuffer;
  EFI_DEVICE_PATH_PROTOCOL *CtrlDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *GopCtrlDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *LastDevicePathNode;

  Connected = FALSE;

  CtrlDevicePath = DuplicateDevicePath (DevicePath);
  LastDevicePathNode = GetLastDeviceNode (CtrlDevicePath);

  if (LastDevicePathNode != NULL &&
    LastDevicePathNode->Type == ACPI_DEVICE_PATH &&
    LastDevicePathNode->SubType == ACPI_ADR_DP) {

    SetDevicePathEndNode (LastDevicePathNode);
  }

  HandleCount = 0;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiGraphicsOutputProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  if (!EFI_ERROR (Status) && HandleCount > 0) {

    for (Index = 0; Index < HandleCount; Index++) {

      GopCtrlDevicePath = NULL;
      GopCtrlDevicePath = DevicePathFromHandle (HandleBuffer [Index]);

      if (GopCtrlDevicePath != NULL) {

        GopCtrlDevicePath = DuplicateDevicePath (GopCtrlDevicePath);
        LastDevicePathNode = GetLastDeviceNode (GopCtrlDevicePath);

        if (LastDevicePathNode != NULL &&
          LastDevicePathNode->Type == ACPI_DEVICE_PATH &&
          LastDevicePathNode->SubType == ACPI_ADR_DP) {

          SetDevicePathEndNode (LastDevicePathNode);
        }

        if (CompareDevicePath (CtrlDevicePath, GopCtrlDevicePath)) {
          Connected = TRUE;
          SafeFreePool (GopCtrlDevicePath);
          break;
        }
        SafeFreePool (GopCtrlDevicePath);
      }
    }

    SafeFreePool(HandleBuffer);
  }

  SafeFreePool (CtrlDevicePath);
  return Connected;

} // IsGopProduced


//
// FUNCTION NAME.
//      GetGopAlternativeChild - Get alternative RemainingDevicePath.
//
// FUNCTIONAL DESCRIPTION.
//      This function will retrieve the prefer remaining device path.
//      The implementation can choose the proper video output device according
//      to EDID information.
//
// ENTRY PARAMETERS.
//      VgaPciHandle.   - VGA handle.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      RemainingDevicePath - prefer child device path.
//

SCT_STATUS
EFIAPI
GetGopAlternativeChild (
  IN EFI_HANDLE VgaHandle,
  OUT EFI_DEVICE_PATH_PROTOCOL **RemainingDevicePath
  )
{
  UINTN i;
  EFI_STATUS Status;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  PSCT_CONFIGURE_CONSOLE_PROTOCOL p;

  if (VgaHandle == NULL || RemainingDevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get number of protocols installed.
  //

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctConfigureConsoleProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  if (EFI_ERROR (Status) || HandleCount == 0) {
    return EFI_NOT_FOUND;
  }

  for (i = 0; i < HandleCount; i++) {

    //
    // Get the protocol instance.
    //

    Status = gBS->OpenProtocol (
                    HandleBuffer [i],
                    &gSctConfigureConsoleProtocolGuid,
                    (VOID **) &p,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);

    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = p->GetGopAltChild (VgaHandle, RemainingDevicePath);
    if (!EFI_ERROR (Status)) {
      SafeFreePool (HandleBuffer);
      return Status;
    }
  }

  SafeFreePool (HandleBuffer);
  return EFI_UNSUPPORTED;
} // GetGopAlternativeChild


//
// FUNCTION NAME.
//      ConfigureConOutBeforeBoot - Determine whether clearing screen before boot or not.
//
// FUNCTIONAL DESCRIPTION.
//      This function will determine whether clearing screen or not according to
//      current boot path.
//
// ENTRY PARAMETERS.
//      DevicePath.     - current boot device path.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      ClearScreen     - BOOLEAN.
//

SCT_STATUS
EFIAPI
ConfigureConOutBeforeBoot (
  IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  OUT BOOLEAN *ClearScreen
  )
{
  UINTN i;
  EFI_STATUS Status;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  PSCT_CONFIGURE_CONSOLE_PROTOCOL p;

  if (DevicePath == NULL || ClearScreen == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get number of protocols installed.
  //

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctConfigureConsoleProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  if (EFI_ERROR (Status) || HandleCount == 0) {
    return EFI_NOT_FOUND;
  }

  for (i = 0; i < HandleCount; i++) {

    //
    // Get the protocol instance.
    //

    Status = gBS->OpenProtocol (
                    HandleBuffer [i],
                    &gSctConfigureConsoleProtocolGuid,
                    (VOID **) &p,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);

    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = p->ConfigConOutBeforeBoot (DevicePath, ClearScreen);
    if (!EFI_ERROR (Status)) {
      SafeFreePool (HandleBuffer);
      return Status;
    }
  }

  SafeFreePool (HandleBuffer);
  return EFI_UNSUPPORTED;
} // ConfigureConOutBeforeBoot

//
// FUNCTION NAME.
//      IsTerminalDevice - Determine if the device path is represented as a terminal device.
//
// FUNCTIONAL DESCRIPTION.
//      This function will determine if the input device path is represented as a terminal device.
//
// ENTRY PARAMETERS.
//      DevicePath.     - a pointer points to EFI_DEVICE_PATH_PROTOCOL.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN.
//

BOOLEAN
IsTerminalDevice (IN EFI_DEVICE_PATH_PROTOCOL * DevicePath)
{
  EFI_DEVICE_PATH_PROTOCOL *LastNode;
  VENDOR_DEVICE_PATH *Node;

  if (DevicePath == NULL) {
    return FALSE;
  }

  LastNode = GetLastDeviceNode (DevicePath);

  if (LastNode == NULL) {
    return FALSE;
  }

  Node = (VENDOR_DEVICE_PATH *)LastNode;

  if (Node->Header.Type != MESSAGING_DEVICE_PATH ||
      Node->Header.SubType != MSG_VENDOR_DP ||
      DevicePathNodeLength (&Node->Header) != sizeof (VENDOR_DEVICE_PATH)) {
    return FALSE;
  }

  //
  // only supports PC ANSI, VT100, VT100+ and VT-UTF8 terminal types.
  //

  if (!CompareGuid (&Node->Guid, &gEfiPcAnsiGuid) &&
      !CompareGuid (&Node->Guid, &gEfiVT100Guid) &&
      !CompareGuid (&Node->Guid, &gEfiVT100PlusGuid) &&
      !CompareGuid (&Node->Guid, &gEfiVTUTF8Guid)) {
    return FALSE;
  }

  return TRUE;
} // IsTerminalDevice

//
// FUNCTION NAME.
//      BmKickOutGopDrivers - Unload the native GOP drivers.
//
// FUNCTIONAL DESCRIPTION.
//      The function will try to unload the native GOP drivers provided by
//      PCI OPROM if it has been managed by VGA THUNK driver.
//
//      This routine basically uses the EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_PROTOCOL to
//      get the native GOP drivers found during PCI Bus enumeration so it can not guarantee
//      all of the possible GOP drivers will be unloaded.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
STATIC
BmKickOutGopDrivers (VOID)
{
  UINTN i;
  UINTN Index;
  UINTN EntryCount;
  EFI_STATUS ReturnStatus;
  EFI_STATUS Status;
  VOID *Interface;
  UINTN NumberOfHandles;
  EFI_HANDLE *GopHandleBuffers;
  EFI_HANDLE PciHandle;
  EFI_HANDLE DriverImageHandle;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *OpenInfoBuffer;
  EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_PROTOCOL *BusSpecificDriverOverride;

  //
  // Get current GOP device handle.
  //

  NumberOfHandles = 0;
  GopHandleBuffers = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiGraphicsOutputProtocolGuid,
                  NULL,
                  &NumberOfHandles,
                  &GopHandleBuffers);
  DPRINTF_CON ("  Number of GOP handles = %d\n", NumberOfHandles);

  if (EFI_ERROR (Status) || NumberOfHandles == 0) {
    return EFI_NOT_FOUND;
  }

  ReturnStatus = EFI_NOT_FOUND;

  //
  // Check if current GOP device handle is produced by Thunk driver.
  //

  for (i = 0; i < NumberOfHandles; i++)  {

    DevicePath = NULL;
    DevicePath = DevicePathFromHandle (GopHandleBuffers [i]);
    if (DevicePath == NULL) {
      continue;
    }

    DEBUG_CON ({
      CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
      DPRINTF_CON ("  %s.\n", Str);
      SafeFreePool (Str);
    });

    RemainingDevicePath = DevicePath;
    PciHandle = NULL;
    Status = gBS->LocateDevicePath (
                    &gEfiPciIoProtocolGuid,
                    &RemainingDevicePath,
                    &PciHandle);

    if (!EFI_ERROR (Status) && PciHandle != NULL) {

      //
      // Check if this handle is managed by legacy THUNK driver.
      //

      Status = gBS->OpenProtocolInformation (
                      PciHandle,
                      &gEfiPciIoProtocolGuid,
                      &OpenInfoBuffer,
                      &EntryCount);
      if (EFI_ERROR (Status)) {
        continue;
      }

      for (Index = 0; Index < EntryCount; Index++) {
        if ((OpenInfoBuffer [Index].Attributes & EFI_OPEN_PROTOCOL_BY_DRIVER) != 0) {
          Status = gBS->HandleProtocol (
                          OpenInfoBuffer [Index].AgentHandle,
                          &gEfiLegacyBiosGuid,
                          (VOID **)&Interface);
          if (!EFI_ERROR (Status)) {
            DPRINTF_CON ("  Thunk driver has already managed this PCI VGA.\n");

            //
            // Try to kick off native GOP drivers.
            //

            Status = gBS->HandleProtocol (
                            PciHandle,
                            &gEfiBusSpecificDriverOverrideProtocolGuid,
                            (VOID **)&BusSpecificDriverOverride);
            if (!EFI_ERROR (Status)) {

              DPRINTF_CON (" gEfiBusSpecificDriverOverrideProtocolGuid found\n");

              //
              // Unload each driver.
              //

              DriverImageHandle = NULL;
              while (TRUE) {
                Status = BusSpecificDriverOverride->GetDriver (
                                                      BusSpecificDriverOverride,
                                                      &DriverImageHandle);
                DPRINTF_CON (" GetDriver returned %r\n", Status);
                if (EFI_ERROR (Status)) {
                  break;
                }
                DPRINTF_CON (" Try to unload driver 0x%x\n", DriverImageHandle);
                Status = gBS->UnloadImage (DriverImageHandle);
                DPRINTF_CON ("UnloadImage returned %r\n", Status);
                ReturnStatus = !EFI_ERROR (Status) ? Status : ReturnStatus;
              }
            }
          }
          break;
        }
      }
      FreePool (OpenInfoBuffer);
    }
  }

  SafeFreePool (GopHandleBuffers);
  return ReturnStatus;
} // BmKickOutGopDrivers

//
// FUNCTION NAME.
//      GetEfiVgaDeferredImages - Clarify the deferred image to find deferred Vga handle.
//
// FUNCTIONAL DESCRIPTION.
//      The function will try to Clarify the deferred image to find deferred Vga handle.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//                        Get deferred image return EFI_SUCCESS.
//

EFI_STATUS
EFIAPI
GetEfiVgaDeferredImages (VOID)
{
  UINTN Index;
  VOID *Image;
  UINTN ImageSize;
  UINTN ImageCount;
  UINTN ImageIndex;
  EFI_STATUS Status;
  UINTN HandleCount;
  BOOLEAN BootOption;
  EFI_HANDLE *Handles;
  UINTN VgaDeferredNum;
  EFI_HANDLE DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;     SUPPRESS_WARNING_IF_UNUSED (DevicePath);
  EFI_DEVICE_PATH_PROTOCOL *ImageDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_DEFERRED_IMAGE_LOAD_PROTOCOL *DeferredImage;

  DPRINTF_CON (":\n");

  //
  // Find all the deferred image load protocols.
  //

  HandleCount = 0;
  Handles = NULL;
  VgaDeferredNum = 0;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDeferredImageLoadProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles);
  DPRINTF_CON ("HandleCount:%d.St:%r\n", HandleCount, Status);

  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  ImageCount = 0;
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (Handles[Index], &gEfiDeferredImageLoadProtocolGuid, (VOID **) &DeferredImage);
    DPRINTF_CON ("HandleProtocol,Handle[%d]:0x%x.St:%r, ImageCount:%d\n", Index, Handles[Index], Status, ImageCount);

    if (EFI_ERROR (Status)) {
      continue;
    }

    for (ImageIndex = 0; ;ImageIndex++) {

      //
      // Load all the deferred images in this protocol instance.
      //

      ImageDevicePath = NULL;
      Status = DeferredImage->GetImageInfo (
                                DeferredImage,
                                ImageIndex,
                                &ImageDevicePath,
                                (VOID **) &Image,
                                &ImageSize,
                                &BootOption
                                );
      DPRINTF_BM ("DeferredImage,St:%r, ImageIndex:%d, ImageCount:%d\n", Status, ImageIndex, ImageCount);

      if (EFI_ERROR (Status)) {
        break;
      }
      DEBUG_BMR ({
        CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (ImageDevicePath, FALSE, TRUE);
        DPRINTF_BM ("ImageDevicePath - %s.\n", Str);
        SafeFreePool (Str);
      });

      //
      // Get the Handle for this device path.
      //

      RemainingDevicePath = ImageDevicePath;
      Status = gBS->LocateDevicePath (
                  &gEfiDevicePathProtocolGuid,
                  &RemainingDevicePath,
                  &DeviceHandle);
      DPRINTF_BM ("Locate,St:%r, DeviceHandle:0x%x\n", Status, DeviceHandle);
      if (EFI_ERROR (Status)) {
        break;
      }

      ImageCount++;
      DPRINTF_BM ("ImageCount:0x%x\n", ImageCount);
      DevicePath = DevicePathFromHandle (DeviceHandle);
      DEBUG_BMR ({
        CHAR16 *Str = BM_CONVERT_DEVICE_PATH_TO_TEXT (DevicePath, FALSE, TRUE);
        DPRINTF_BM ("DevicePath - %s.\n", Str);
        SafeFreePool (Str);
      });

      if (IsVgaDevices (NULL, &DeviceHandle)) {
        DPRINTF_CON ("  \nPCI VGA Device Found\n");
        if (!IsManagedByThunk (DeviceHandle)) {

          //
          // Only record the EFI VGA Handle. If it is managed by thunk driver, it is legacy Vga Bios, so skip.
          //

          if ((gDeferredImageBuffer != NULL) & (mDeferredVgaHandle < Max_NUMBER_OF_DEFERRED_IMAGE)){
            gDeferredImageBuffer [VgaDeferredNum++] = DeviceHandle;
            mDeferredVgaHandle++;
            DPRINTF_CON ("mDeferredVgaHandle:%d\n", mDeferredVgaHandle, DeviceHandle);
            DPRINTF_CON ("gDeferredImageBuffer [%d]:0x%x\n", VgaDeferredNum, gDeferredImageBuffer [VgaDeferredNum-1]);
          } // if (gDeferredImageBuffer != NULL) {
        } // if (!IsManagedByThunk (DeviceHandle)) {

      } // if (IsVgaDevices
    } // for (ImageIndex = 0; ;ImageIndex++)
  } // for (Index = 0; Index < HandleCount; Index++) {
  if (Handles != NULL) {
    FreePool (Handles);
  }

  DPRINTF_CON ("ImageCount:%d, VgaDeferredNum:%d\n", ImageCount, VgaDeferredNum);

  if (ImageCount == 0) {
    return EFI_NOT_FOUND;
  } else {
    return EFI_SUCCESS;
  }

} // GetEfiVgaDeferredImages


//
// FUNCTION NAME.
//      LoadDeferredImage - Load Deferred Image drivers.
//
// FUNCTIONAL DESCRIPTION.
//      The function will try to load the deferred drivers provided by
//      EFI OPROM if it has been deferred by secure driver.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
EFIAPI
LoadDeferredImage (VOID)
{
  UINTN i;
  UINT32 VendorId;
  EFI_STATUS Status;
  EFI_PCI_IO_PROTOCOL *PciIo;
  SCT_BDS_MILESTONE_DETERMINE_DEFERRED_IMAGE MilestoneDeferredData;

  EfiBootManagerDispatchDeferredImages ();
  DPRINTF_CON ("mDeferredVgaHandle:%d.\n", mDeferredVgaHandle);

  //
  // External EFI graphic image will be deferred.
  // If it's IGFX scenario, the ConnectController should have been done earlier.
  // So here we need to handle non-IGFX scenario.
  //

  if ((mDeferredVgaHandle != 0) & (gDeferredImageBuffer != NULL)) {

    //
    // Register callback for the notification when EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL protocol installed.
    //

    RegisterStoDeviceNotify ();

    //
    // Connect the GOP driver
    //

    for (i = 0; i < mDeferredVgaHandle; i++) {
      DPRINTF_CON ("gDeferredImageBuffer [%d]=0x%x\n", i, gDeferredImageBuffer [i]);

      if (gDeferredImageBuffer [i] == 0) {
        DPRINTF_CON ("There is no deferredImage, i=0x%x\n", i);
        break;
      }
      if (i > (Max_NUMBER_OF_DEFERRED_IMAGE - 1)) {
        DPRINTF_CON ("It can not handle!!! Overflow");
        break;
      }

      PciIo = NULL;
      Status = gBS->HandleProtocol (
                      gDeferredImageBuffer [i],
                      &gEfiPciIoProtocolGuid,
                      (VOID **)&PciIo);

      if (!EFI_ERROR (Status)) {
        PciIo->Pci.Read (
                 PciIo,
                 EfiPciIoWidthUint32,
                 0,
                 1,
                 &VendorId);

        //
        // For customers to determine which deferred images can be connected.
        //

        PERF_START (0, "MsTaskDetermineDeferredImage", "BootManager", 0);
        MilestoneDeferredData.Cardvid = (UINT16) VendorId & 0xFFFF;
        MilestoneDeferredData.Carddid = (UINT16) ((VendorId >> 16) & 0xFFFF);
        MilestoneDeferredData.Cardhandle = gDeferredImageBuffer [i];
        MilestoneDeferredData.Reconnect = TRUE;
        DPRINTF_CON ("CardVId:0x%x, CardDid:0x%x, CardHandle:0x%x\n",MilestoneDeferredData.Cardvid, MilestoneDeferredData.Carddid, MilestoneDeferredData.Cardhandle);

        SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_RECONNECT_DEFERRED_IMAGE, MsTaskDetermineDeferredImage, &MilestoneDeferredData, sizeof (MilestoneDeferredData));
        DPRINTF_CON ("After milestone,Reconnect:%d\n",MilestoneDeferredData.Reconnect);
        PERF_END (0, "MsTaskDetermineDeferredImage", "BootManager", 0);

        if (MilestoneDeferredData.Reconnect == TRUE) {
          Status = gBS->ConnectController (gDeferredImageBuffer [i], NULL, NULL, TRUE);
          DPRINTF_CON ("ConnectController.AFTER, St:%r, BufferIndex:0x%x\n", Status, i);
          DUMP_ALL_DEVICE_PATHS;
          DUMP_ALL_PROTOCOLS (gDeferredImageBuffer [i]);
        }
      } // if (!EFI_ERROR (Status))

    } // for (i = 0; i < mDeferredVgaHandle; i++) {

    mDeferredVgaHandle = 0;
    SafeFreePool (gDeferredImageBuffer);
    if (mStoDeviceAvailableEvent != NULL) {
      gBS->CloseEvent (mStoDeviceAvailableEvent);
      mStoDeviceAvailableEvent = NULL;
    }

    PERF_START (0, "Deferred VGA DisplaySplashScreen", "BootManager", 0);
    SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_SPLASH, MsTaskDisplaySplashScreen, NULL, 0);
    PERF_END (0, "Deferred VGA DisplaySplashScreen", "BootManager", 0);

  } // if ((mDeferredVgaHandle != 0) & (gDeferredImageBuffer != NULL))

  return EFI_SUCCESS;
}

//
// FUNCTION NAME.
//      PrepareDeferred - PrepareDeferred Deferred Image.
//
// FUNCTIONAL DESCRIPTION.
//      The function will try to allocate the deferred handles buffer.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
PrepareDeferred (VOID)
{
  UINTN NumberOfHandles;

  NumberOfHandles = Max_NUMBER_OF_DEFERRED_IMAGE;
  gDeferredImageBuffer = AllocateZeroPool ((NumberOfHandles) * sizeof (EFI_HANDLE));
  if (gDeferredImageBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}
//
// FUNCTION NAME.
//      VerifyConsoleVariable - Verify Consoles variables.
//
// FUNCTIONAL DESCRIPTION.
//      This function will verify all Console Variables, if variables are invalid,
//      it would delete this variable.
//
// ENTRY PARAMETERS.
//      VariableName    - the name of the variable to process.
//
// EXIT PARAMETERS.
//      Function Return - SCT_STATUS
//                        SCT_STATUS_DEVICE_DELETED - delete error console variable.
//
SCT_STATUS
VerifyConsoleVariable (
  CHAR16 *VariableName
  )
{
  SCT_STATUS Status;
  UINT32 Attributes;
  UINTN VariableSize;
  EFI_DEVICE_PATH_PROTOCOL *VariableValue;
  EFI_DEVICE_PATH_PROTOCOL *DevicePathPosition;

  DPRINTF_CON (":\n");
  Status = SctLibGetEfiGlobalVariable (VariableName, &Attributes, &VariableSize, (VOID **) &VariableValue);
  DPRINTF_CON ("Get Variable, %s,%r.\n", VariableName, Status);

  if (EFI_ERROR (Status)) {
    DPRINTF_CON ("  Can't find %s, %r.\n", VariableName, Status);
    return SCT_STATUS_NOT_FOUND;
  }

  DevicePathPosition = VariableValue;
  DPRINTF_CON ("DevicePath->Type= 0x%x.\n", DevicePathType (DevicePathPosition));
  if (!IsBmDevicePathValid (DevicePathPosition, VariableSize)) {
    DPRINTF_CON ("Console variable is not correct, Type= 0x%x.\n", DevicePathType (DevicePathPosition));
    DPRINTF_CON ("Delete Console variable!!!\n");

    Status = SetEfiGlobalVariable (VariableName, Attributes, 0, NULL);
    if (!EFI_ERROR (Status)) {
      Status = SCT_STATUS_DEVICE_DELETED;
    }
  }
  SafeFreePool (VariableValue);
  return Status;
}

//
// FUNCTION NAME.
//      VerifyAllConsoleVariable - Verify all Consoles variables.
//
// FUNCTIONAL DESCRIPTION.
//      This function will verify all Console Variables, if variables are invalid,
//      it would delete this variable.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN
//                        TRUE  - Console variables are correct or not exist.
//                        FALSE - Console variables are invalid.
//
UINT8
VerifyAllConsoleVariable (
  VOID
  )
{
  UINT8 ValidValue;
  SCT_STATUS Status;

  DPRINTF_CON ("{\n");

  ValidValue = 0;

  Status = VerifyConsoleVariable (EFI_CON_OUT_VARIABLE_NAME);
  DPRINTF_CON ("ConOut:%r\n", Status);
  if (Status == SCT_STATUS_DEVICE_DELETED) {
    ValidValue |= BIT0;
  }

  Status = VerifyConsoleVariable (EFI_CON_IN_VARIABLE_NAME);
  DPRINTF_CON ("ConIn:%r\n", Status);
  if (Status == SCT_STATUS_DEVICE_DELETED) {
    ValidValue |= BIT1;
  }

  Status = VerifyConsoleVariable (EFI_ERR_OUT_VARIABLE_NAME);
  DPRINTF_CON ("ErrOut:%r\n", Status);
  if (Status == SCT_STATUS_DEVICE_DELETED) {
    ValidValue |= BIT2;
  }

  DPRINTF_CON ("} ValidValue [0x%x]\n", ValidValue);
  return ValidValue;
}

//
// FUNCTION NAME.
//      IsManagedByThunk - Is the device path managed by thunk driver.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check if the device path managed by thunk driver.
//
// ENTRY PARAMETERS.
//      DeviceHandle    - Device Handle.
//
// EXIT PARAMETERS.
//      BOOLEAN         - TRUE is managed by thunk driver.
//

BOOLEAN
IsManagedByThunk (
  IN EFI_HANDLE DeviceHandle
  )
{
  UINTN i;
  BOOLEAN Flag;
  VOID *Interface;
  UINTN EntryCount;
  EFI_STATUS Status;
  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *OpenInfoBuffer;

  DPRINTF_CON (":\n");

  Flag = FALSE;
  if (DeviceHandle == NULL) {
    return FALSE;
  }

  //
  // Check if this handle is managed by legacy THUNK driver.
  //

  Status = gBS->OpenProtocolInformation (
                  DeviceHandle,
                  &gEfiPciIoProtocolGuid,
                  &OpenInfoBuffer,
                  &EntryCount);
  DPRINTF_CON ("Open:%r, EntryCount:%d\n", Status, EntryCount);

  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  for (i = 0; i < EntryCount; i++) {
    DPRINTF_CON ("Index:%d, Attr:0x%x\n", i, OpenInfoBuffer [i].Attributes);

    if ((OpenInfoBuffer [i].Attributes & EFI_OPEN_PROTOCOL_BY_DRIVER) != 0) {
      Status = gBS->HandleProtocol (
                      OpenInfoBuffer [i].AgentHandle,
                      &gEfiLegacyBiosGuid,
                      (VOID **)&Interface);
      DPRINTF_CON ("HandleProtocol:%r.\n", Status);

      if (!EFI_ERROR (Status)) {
        DPRINTF_CON ("  Thunk driver has already managed this PCI VGA.\n");
        Flag = TRUE;
      }
    }
  }
  DPRINTF_CON ("Flag:%d.\n", Flag);

  return Flag;
}

//
// FUNCTION NAME.
//      MsTaskDetermineDeferredImage - Default task for DetermineDeferredImage Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task to fo for DetermineDeferredImage.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskDetermineDeferredImage (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UINTN i;
  SCT_BDS_MILESTONE_DETERMINE_DEFERRED_IMAGE *DetermineImage;

  DetermineImage = (SCT_BDS_MILESTONE_DETERMINE_DEFERRED_IMAGE *) MilestoneData;
  DPRINTF_BM (":DeferredImage Vid:0x%x, Did=0x%x\n", DetermineImage->Cardvid, DetermineImage->Carddid);
  DPRINTF_BM (":DeferredImage Reconnect:%d\n", DetermineImage->Reconnect);

  i = 0;
  while (TRUE) {
    if (mIgnoreDeferredVgaImageList [i].IdVendor == 0xFFFF) {
      DPRINTF_BM (":loop:define ignore i=%d Vid:0x%x, Did=0x%x\n", i, mIgnoreDeferredVgaImageList [i].IdVendor, mIgnoreDeferredVgaImageList [i].IdDevice);

      break;
    }
    DPRINTF_BM (":define ignore i=%d Vid:0x%x, Did=0x%x\n", i, mIgnoreDeferredVgaImageList [i].IdVendor, mIgnoreDeferredVgaImageList [i].IdDevice);

    if (mIgnoreDeferredVgaImageList [i].IdDevice == 0xFFFF) {
      if (mIgnoreDeferredVgaImageList [i].IdVendor == DetermineImage->Cardvid) {
        DetermineImage->Reconnect = FALSE;
        DPRINTF_BM (":define ignore i=%d Vid:0x%x, Def:vid=0x%x\n", i, mIgnoreDeferredVgaImageList [i].IdVendor, DetermineImage->Cardvid);

        break;
      }
    } else {
      if ((mIgnoreDeferredVgaImageList [i].IdVendor == DetermineImage->Cardvid) &&
        (mIgnoreDeferredVgaImageList [i].IdDevice == DetermineImage->Carddid)) {
        DetermineImage->Reconnect = FALSE;
        DPRINTF_BM (":define ignore i=%d Vid:0x%x, Def:vid=0x%x\n", i, mIgnoreDeferredVgaImageList [i].IdVendor, DetermineImage->Cardvid);
        DPRINTF_BM (":define ignore i=%d did:0x%x, Def:did=0x%x\n", i, mIgnoreDeferredVgaImageList [i].IdDevice, DetermineImage->Carddid);

        break;
      }

    }
    i++;
  }
  DPRINTF_BM (":DeferredImage Reconnect:%d\n", DetermineImage->Reconnect);

  DPRINTF_BM (":Exit, i=%d\n", i);

  return SCT_STATUS_SUCCESS;
} // MsTaskDetermineDeferredImage
