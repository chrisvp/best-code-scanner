//
// FILENAME.
//      BdsMisc.c - SecureCore Technology(TM) Additional Funtions Supporting in the Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      Provides miscellaneous functions for BDS phase.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//
// Include standard header files.
//

#include "Meta.h"
#include <Protocol/SctUsbHcLatchProtocol.h>
#include <Protocol/Dhcp4.h>
#include <Protocol/Dhcp6.h>

//
// Private datatypes used by this module are defined here and any static
// items are declared here.
//

#if OPTION_CSM_OPTION_OUT
EFI_HII_HANDLE mUiStringHiiHandle;                // String Hii Data Base Handle.
#endif

#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND


//
// Below private data is used for USB Initialization On Demand.
//

#define KEYBOARD_TIMEOUT        655360 // 0.7s
#define KBC_COMMAND_PORT        0x64
#define KBC_DATA_PORT           0x60
#define KBC_OUTPUT_BUFFER_BIT   1
#define KBC_INPUT_BUFFER_BIT    2
#define NON_KBC_COMMAND         0xFE

static BOOLEAN mIsInPostBootPhase = FALSE;
static EFI_INPUT_READ_KEY_EX mOriginalReadKeyExFun = NULL;
static EFI_INPUT_READ_KEY mOriginalReadKeyFun = NULL;
static EFI_SIMPLE_TEXT_INPUT_PROTOCOL *SavedConIn = NULL;
static UINT8 mTriggerThreadHole = 0;

extern
BOOLEAN
EFIAPI
LegacyBootEnabled (OUT PBOOLEAN LegacyBeforeUefi OPTIONAL);

#endif

#if OPTION_CSM_OPTION_OUT
GLOBAL_REMOVE_IF_UNREFERENCED CHAR16 *MessageBoxBtnStr [] = {
  L"Yes",
  L"No"
};

EFI_GUID mUiStringPackageListGuid = SYSTEM_BOOT_MANAGER_UI_STRING_PACKAGELIST_GUID;
#endif

#if (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)

static BOOLEAN mSmmCodeAccessCheckFlag = FALSE;

#if OPTION_SUPPORT_SMM_CODE_ACCESS_CHK
extern EFI_GUID gSmmEnableCodeAccessCheckSignal;
#endif // OPTION_SUPPORT_SMM_CODE_ACCESS_CHK

#if OPTION_SMM_CODE_ACCESS_CHK_NX
extern EFI_GUID gSmmSecureBiosSignal;
#endif // OPTION_SMM_CODE_ACCESS_CHK_NX

#endif //(OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)


EFI_GUID mPs2DeviceModuleFvFile [] = {
#ifdef CONFIG_Ps2DeviceModuleFvFileGuidList
  CONFIG_Ps2DeviceModuleFvFileGuidList
#else
  ZERO_GUID
#endif
};

BOOLEAN mIsPs2DriverLoaded = FALSE;

#if OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND

static BOOT_MANAGER_CONNECTION_DEVICE mPs2DeviceConnectList [] = {
  CONFIG_BmPs2DeviceConnectList
};

BOOLEAN mIsPs2DeviceConnected = FALSE;

#endif //OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND


//
// Prototypes for functions in other modules that are a part of this component.
//

extern
EFI_STATUS
DecompressOptionalFirmwareVolume (IN UINTN Type);

extern
EFI_STATUS
FindOptionalFvHandle (
  IN EFI_GUID *FileName,
  OUT EFI_HANDLE *TargetHandle
  );

BOOLEAN
IsFvFileExist (
  IN EFI_HANDLE FvHandle,
  IN EFI_GUID *FileName
  );

extern
SCT_STATUS
EFIAPI
ConnectDevices (IN PBOOT_MANAGER_CONNECTION_DEVICE  DeviceList);

//
// Data defined in other modules and used by this module.
//

extern EFI_BOOT_MODE mBootMode;
extern EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *mTextInEx;
extern EFI_HANDLE mFvHandle;

extern EFI_SMM_COMMUNICATE_HEADER *mSmmCommunicateHeader;

//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

//
// Public API functions implemented by this component.
//

EFI_EVENT BmDispatchEvent = NULL;

//
// FUNCTION NAME.
//      ResetSystemFlagFlagMilestoneTask -
//
// FUNCTIONAL DESCRIPTION.
//      Reset System milestone task of MILESTONE_TASK_RESET_SYSTEM_FLAG.
//
// ENTRY PARAMETERS.
//      Data            - Pointer to SCT_MILESTONE_TASK_RESET_SYSTEM_FLAG.
//      DataSize        - Not used.
//
// EXIT PARAMETERS.
//      EFI_SUCCESS     - Operation successful, allowing after phase of OEM hook
//                        to be executed.
//

EFI_STATUS
ResetSystemFlagMilestoneTask (VOID* Data, UINT32 DataSize)
{
  SCT_MILESTONE_TASK_RESET_SYSTEM_FLAG *ResetSystemFlag;

  ResetSystemFlag = (SCT_MILESTONE_TASK_RESET_SYSTEM_FLAG *)Data;
  ResetSystemFlag->ResetSystemFlag = 1;
  return EFI_SUCCESS;
} // ResetSystemFlagMilestoneTask

#if (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)
//
// FUNCTION NAME.
//      BdsEnableSmmCodeAccessCheck - Enable SMM code access protection.
//
// FUNCTIONAL DESCRIPTION.
//      This function delivers an SMI to notify the SMM Code Access Check SMM
//      driver to enable SMM Code Access Checking.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
BdsEnableSmmCodeAccessCheck (VOID)
{
  UINTN CommSize;
  EFI_STATUS Status;
  EFI_SMM_COMMUNICATION_PROTOCOL *mSmmCommunication = NULL;

  DPRINTF_BM ("  BdsEnableSmmCodeAccessCheck Entry!\n");

  if (mSmmCodeAccessCheckFlag == TRUE) {
    Status = EFI_ALREADY_STARTED;
    DPRINTF_ERROR (" BdsEnableSmmCodeAccessCheck Status= [%r], (%d)\n", Status, __LINE__);
    return Status;
  }

  Status = gBS->LocateProtocol (&gEfiSmmCommunicationProtocolGuid, NULL, (VOID **) &mSmmCommunication);
  ASSERT_EFI_ERROR(Status);

  mSmmCommunicateHeader->MessageLength = 1;
  mSmmCommunicateHeader->Data [0] = 0;
  CommSize = sizeof (EFI_SMM_COMMUNICATE_HEADER);

#if (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK)
  if (mSmmCodeAccessCheckFlag != TRUE) {
    Status = EFI_UNSUPPORTED;
    CopyGuid (&(mSmmCommunicateHeader->HeaderGuid), &gSmmEnableCodeAccessCheckSignal);
    Status = mSmmCommunication->Communicate (mSmmCommunication, mSmmCommunicateHeader, &CommSize);
    if (EFI_ERROR(Status)) {
      DPRINTF_ERROR ("[gSmmEnableCodeAccessCheckSignal] - Communicate Status= [%r], mSmmCodeAccessCheckFlag=%x\n", Status, mSmmCodeAccessCheckFlag);
    } else {
      mSmmCodeAccessCheckFlag = TRUE;
    }
  }
#endif //(OPTION_SUPPORT_SMM_CODE_ACCESS_CHK)

#if (OPTION_SMM_CODE_ACCESS_CHK_NX)
  if (mSmmCodeAccessCheckFlag != TRUE) {
    CopyGuid (&(mSmmCommunicateHeader->HeaderGuid), &gSmmSecureBiosSignal);
    Status = mSmmCommunication->Communicate (mSmmCommunication, mSmmCommunicateHeader, &CommSize);
    if (EFI_ERROR(Status)) {
      DPRINTF_ERROR ("[gSmmSecureBiosSignal]            - Communicate Status= [%r], mSmmCodeAccessCheckFlag=%x\n", Status, mSmmCodeAccessCheckFlag);
    } else {
      mSmmCodeAccessCheckFlag = TRUE;
    }
  }
#endif //(OPTION_SMM_CODE_ACCESS_CHK_NX)

  if (mSmmCodeAccessCheckFlag != TRUE) {
    Status = EFI_UNSUPPORTED;
    ASSERT_EFI_ERROR(Status);
  }

  DPRINTF_BM ("BdsEnableSmmCodeAccessCheck, Communicate Status=%r, mSmmCodeAccessCheckFlag=%x\n", Status, mSmmCodeAccessCheckFlag);

  return Status;
} // BdsEnableSmmCodeAccessCheck
#endif // (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)
//
// FUNCTION NAME.
//      RequestPs2Drivers - Request PS2 Drivers for Fast Boot.
//
// FUNCTIONAL DESCRIPTION.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
EFIAPI
RequestPs2Drivers (VOID)
{

  if (!mIsPs2DriverLoaded) {
    RequestDrivers (mFvHandle, mPs2DeviceModuleFvFile, SCT_FIRMWAREVOLUME_TYPE_MAIN, FALSE);
    mIsPs2DriverLoaded = TRUE;
  }
  return;
} // RequestPs2Drivers
#if OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND
//
// FUNCTION NAME.
//     ConnectPs2Devices - Connect PS2 Devices. for Fast Boot
//
// FUNCTIONAL DESCRIPTION.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
EFIAPI
ConnectPs2Devices (VOID)
{

  EFI_STATUS Status;
  EFI_TPL Tpl;

  if (!mIsPs2DeviceConnected) {
    Tpl = SetTpl (TPL_APPLICATION);
    Status = ConnectDevices (mPs2DeviceConnectList);
    if (EFI_ERROR (Status)) {
      BmDispatch (FALSE);
      Status = ConnectDevices (mPs2DeviceConnectList);
    }
    SetTpl (Tpl);
    if (EFI_ERROR (Status)) {
      return;
    }
    mIsPs2DeviceConnected = TRUE;
  }
  return;
} // ConnectPs2Devices


#endif // OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND


#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND


//
// FUNCTION NAME.
//      ReleaseAllUsbHc - Close the occupied EFI_USB2_HC_PROTOCOL by BootManager.
//
// FUNCTIONAL DESCRIPTION.
//      This function will close the occupied EFI_USB2_HC_PROTOCOL by BootManager
//      so that other drivers can manage them.
//
// ENTRY PARAMETERS.
//      Event           - the event raised by caller.
//      Context         - the context transferred by caller.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN value.
//

EFI_STATUS
EFIAPI
ReleaseAllUsbHc (VOID)
{
  EFI_STATUS                 Status;
  SCT_LATCH_USB_HC_PROTOCOL *SctLatchUsbHcProtocol;

  DPRINTF_BM_MISC ("  Entry\n");
#if OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND

    //
    // Request PS2 Drivers.
    //

    RequestPs2Drivers ();

#endif  // OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND

  Status = gBS->LocateProtocol (
                  &gSctUsbHcLatchProtocolGuid,
                  NULL,
                  (VOID **) &SctLatchUsbHcProtocol
                  );
  DPRINTF_BM_MISC ("Locate SctLatchUsbHcProtocol Status = %r\n", Status);

  if (Status == EFI_SUCCESS){
    Status = SctLatchUsbHcProtocol->ReleaseUsbHc (SctLatchUsbHcProtocol, FALSE);
    DPRINTF_BM_MISC ("SctLatchUsbHcProtocol->ReleaseUsbHc, Status = %r\n",
                      Status);
  }

  return Status;

} // ReleaseAllUsbHc

//
// FUNCTION NAME.
//      BmGeneralCallbackForReadyToBoot - General handler when ReadyToBoot event is signaled.
//
// FUNCTIONAL DESCRIPTION.
//      General callback routine for BootManager when ReadyToBoot event is signaled.
//
// ENTRY PARAMETERS.
//      Event           - the event raised by caller.
//      Context         - the context transferred by caller.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

VOID
EFIAPI
BmGeneralCallbackForReadyToBoot (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  ReleaseAllUsbHc ();
  mIsInPostBootPhase = TRUE;

  gBS->CloseEvent (Event);

} // BmGeneralCallbackForReadyToBoot


//
// FUNCTION NAME.
//      BmCallbackForEnteringSetup - Notification when entering Setup.
//
// FUNCTIONAL DESCRIPTION.
//      Callback routine for BootManager when entering Setup.
//
// ENTRY PARAMETERS.
//      Event           - the event raised by caller.
//      Context         - the context transferred by caller.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

VOID
EFIAPI
BmCallbackForEnteringSetup (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  ReleaseAllUsbHc ();
  gBS->CloseEvent (Event);

} // BmCallbackForEnteringSetup


//
// FUNCTION NAME.
//      RegisterUsbHcNotifyAndLock - Registration for EFI_USB2_HC_PROTOCOL.
//
// FUNCTIONAL DESCRIPTION.
//      This function will register a callback function to receive the notification
//      when any EFI_USB2_HC_PROTOCOL instance has been installed on specific handle.
//
//      The callback function will proceed to occupy the control right of the
//      protocol so that the other drivers can not manage them.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
RegisterUsbHcNotifyAndLock (VOID)
{
  EFI_EVENT                  Event;
  EFI_STATUS                 Status;
  SCT_LATCH_USB_HC_PROTOCOL *SctLatchUsbHcProtocol;

  DPRINTF_BM_MISC ("  Entry\n");

  Status = gBS->LocateProtocol (
                  &gSctUsbHcLatchProtocolGuid,
                  NULL,
                  (VOID **) &SctLatchUsbHcProtocol
                  );
  DPRINTF_BM_MISC ("Locate SctLatchUsbHcProtocol Status = %r\n", Status);

  if (Status == EFI_SUCCESS){
    Status = SctLatchUsbHcProtocol->LatchUsbHc (SctLatchUsbHcProtocol);
    DPRINTF_BM_MISC ("SctLatchUsbHcProtocol->LatchUsbHc, "
                      "Status = %r\n", Status);
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Register ReadyToBoot event to release the USB HC.
  //

  Status = EfiCreateEventReadyToBootEx (
             TPL_CALLBACK,
             BmGeneralCallbackForReadyToBoot,
             NULL,
             &Event);

  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Register for notification during Setup initialization. During Setup
  // initialization, we will be able to release the control right of USB HCs.
  //

  Status = EfiNamedEventListen (
             &gEfiHiiPlatformSetupFormsetGuid,
             TPL_CALLBACK,
             BmCallbackForEnteringSetup,
             NULL,
             NULL);

  return Status;

} // RegisterUsbHcNotifyAndLock

//
// FUNCTION NAME.
//      MsTaskIsPS2KeyboaredNoExist - Detect PS2 Keyboard exist or not.
//
// FUNCTIONAL DESCRIPTION.
//      This function will detect PS2 keyboard exist or not.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN value.
//                        TRUE  - PS2 Keyboard not exist.
//                        FALSE - PS2 Keyboard exist.
//

EFI_STATUS
MsTaskIsPS2KeyboardNoExist (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{

  UINT32 TimeOut;
  UINT32 RegFilled;
  UINT8  Data;
  SCT_MILESTONE_TASK_PS2_KEYBOARD_DETECT *Ps2KeyboardDetect;
  Ps2KeyboardDetect = (SCT_MILESTONE_TASK_PS2_KEYBOARD_DETECT*)MilestoneData;

  TimeOut = 0;
  RegFilled = 0;

  //
  // 1. Always enable USB if KBC not exist.
  //

  if (IoRead8 (KBC_COMMAND_PORT) == 0xFF) {
    DPRINTF_BM_MISC ("KBC not exist.\n");
    Ps2KeyboardDetect->Ps2KeyboardNoExist = TRUE;
    return EFI_SUCCESS;
  }

  //
  // 2. Always enable USB if PS2 Keyboard not exist.
  //

  //
  // Wait till Input buffer empty.
  //

  for (TimeOut = 0; TimeOut < KEYBOARD_TIMEOUT; TimeOut += 30) {
    if (!(IoRead8 (KBC_COMMAND_PORT) & KBC_INPUT_BUFFER_BIT)) {
      RegFilled = 1;
      break;
    }

    gBS->Stall (30);
  }

  if (!RegFilled) {
    Ps2KeyboardDetect->Ps2KeyboardNoExist = TRUE;
    return EFI_SUCCESS;
  }

  //
  // Wait till Output buffer empty.
  //

  RegFilled = 0;
  for (TimeOut = 0; TimeOut < KEYBOARD_TIMEOUT; TimeOut += 30) {
    if (!(IoRead8 (KBC_COMMAND_PORT) & KBC_OUTPUT_BUFFER_BIT)) {
      RegFilled = 1;
      break;
    }

    gBS->Stall (30);
  }

  if (!RegFilled) {
    Ps2KeyboardDetect->Ps2KeyboardNoExist = TRUE;
    return EFI_SUCCESS;
  }

  //
  // Send a Invalid command to Keyboard.
  //

  IoWrite8 (KBC_DATA_PORT, 0xF1);

  //
  // Wait till Input buffer empty.
  //

  RegFilled = 0;

  for (TimeOut = 0; TimeOut < KEYBOARD_TIMEOUT; TimeOut += 30) {
    if (!(IoRead8 (KBC_COMMAND_PORT) & KBC_INPUT_BUFFER_BIT)) {
      RegFilled = 1;
      break;
    }

    gBS->Stall (30);
  }

  if (!RegFilled) {
    Ps2KeyboardDetect->Ps2KeyboardNoExist = TRUE;
    return EFI_SUCCESS;
  }

  //
  // Wait till Output buffer full.
  //

  RegFilled = 0;

  for (TimeOut = 0; TimeOut < KEYBOARD_TIMEOUT; TimeOut += 30) {
    if (IoRead8 (KBC_COMMAND_PORT) & KBC_OUTPUT_BUFFER_BIT) {
      RegFilled = 1;
      break;
    }
    gBS->Stall (30);
  }

  if (!RegFilled) {
    Ps2KeyboardDetect->Ps2KeyboardNoExist = TRUE;
    return EFI_SUCCESS;
  }

  //
  // if return 0xFE = it is return from PS2 Keyboard.
  //

  Data = IoRead8 (KBC_DATA_PORT);
  if (Data != NON_KBC_COMMAND) {
    Ps2KeyboardDetect->Ps2KeyboardNoExist = TRUE;
    return EFI_SUCCESS;
  }

  Ps2KeyboardDetect->Ps2KeyboardNoExist = FALSE;
  return EFI_SUCCESS;

} // MsTaskIsPS2KeyboardNoExist


//
// FUNCTION NAME.
//      IsUsbFullInitializationNeeded - Determine if USB full initialization is necessary.
//
// FUNCTIONAL DESCRIPTION.
//      This function will follow below criteria do determine if USB should be full
//      initialized or not.
//
//      1. Always enable USB if KBC not exist.
//      2. Always enable USB if PS2 Keyboard not exist.
//      3. Always enable USB if UEFI boot is disabled.
//      4. If legacy and UEFI boot are enabled but boot priority is set as "legacy boot first"
//      5. If BootNext is set to BIOS UI (via OSIndicator)
//      6. The first entry in BootOrder is *NOT* Windows Boot Manager.
//      7. The BootNext variable is set to boot to something other than the
//         Windows Boot Manager.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - BOOLEAN value.
//

BOOLEAN
IsUsbFullInitializationNeeded (VOID)
{
  UINTN i;
  SCT_STATUS Status;
  PUINT16 OptionOrder;
  UINTN OptionOrderSize;
  PUINT16 BootNextValue;
  PUINT64 OsIndications;
  PLOAD_OPTION_OBJECT Option;

  BOOLEAN LegacyBootEnable;   SUPPRESS_WARNING_IF_UNUSED(LegacyBootEnable);
  BOOLEAN LegacyBeforeUefi;

#if OPTION_SYSTEM_BOOT_MANAGER_CHECK_PS2_KB
  BOOLEAN Ps2KeyboardNoExist;
  SCT_MILESTONE_TASK_PS2_KEYBOARD_DETECT Ps2KeyboardDetect;
#endif

  DPRINTF_BM_MISC ("  Entry\n");

  if (PcdGetBool (PcdForceUsbFullInitialization)) {
    //
    // Force Usb Full Init.
    //
    return TRUE;
  }

  //
  // if imitate Usb On Demand is enable. Return False.
  //

  if (mSystemConfiguration.InitializeUsbOnDemand == 1) {
    return FALSE;
  }

  //
  // 1. Always enable USB if KBC not exist.
  //

  //
  // 2. Always enable USB if PS2 Keyboard not exist.
  //


#if OPTION_SYSTEM_BOOT_MANAGER_CHECK_PS2_KB
  PERF_START (0, "MsTaskIsPS2KeyboardNoExist", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_PS2KB_CHECK, MsTaskIsPS2KeyboardNoExist, &Ps2KeyboardDetect, 0);
  Ps2KeyboardNoExist = Ps2KeyboardDetect.Ps2KeyboardNoExist;
  if (Ps2KeyboardNoExist) {
    DPRINTF_BM_MISC ("KBC or PS2 Keyboard not exist \n");
    PERF_END (0, "MsTaskIsPS2KeyboardNoExist", "BootManager", 0);
    return TRUE;
  }
  PERF_END (0, "MsTaskIsPS2KeyboardNoExist", "BootManager", 0);

#endif


  //
  // 3. Always enable USB if UEFI boot is disabled.
  //

  if (mSystemConfiguration.UefiBoot == 0) {
    return TRUE;
  }

  //
  // 4. Check if both UEFI/Legacy boot enabled but boot priority is "legacy boot first".
  //
    if (mSystemConfiguration.UefiBoot == 1 &&
      mSystemConfiguration.LegacyBoot == 1) {

      LegacyBootEnable = LegacyBootEnabled (&LegacyBeforeUefi);

      if (LegacyBeforeUefi) {
        return TRUE;
      }
    }

  //
  // 5. Check if the OS request the BIOS UI interface.
  //

  OsIndications = NULL;
  Status = SctLibGetEfiGlobalVariable (
             EFI_OS_INDICATIONS_VARIABLE_NAME,
             NULL,
             NULL,
             (VOID **) &OsIndications);

  if (!EFI_ERROR (Status)) {

    if (*OsIndications & EFI_OS_INDICATIONS_BOOT_TO_FW_UI) {
      SafeFreePool (OsIndications);
      return TRUE;
    }
  }

  SafeFreePool (OsIndications);

  //
  // 6. If BootNext is set to boot to something other than "Windows Boot Manager".
  //

  BootNextValue = NULL;
  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_NEXT_VARIABLE_NAME,
             NULL,
             NULL,
             (VOID **) &BootNextValue);
  DPRINTF_BM_MISC ("  Get Efi Global Variable BootNext returned %r.\n", Status);
  if (!EFI_ERROR (Status)) {

    DPRINTF_BM_MISC ("  BootNext = %d\n", *BootNextValue);
    Option = NULL;
    Status = GetBootOption (*BootNextValue, &Option);
    if (!EFI_ERROR (Status) &&
      StrCmp (WINDOWS_BOOTMGR_DESCRIPTION, Option->Description) == 0) {
      SafeFreePool (BootNextValue);
      return FALSE;
    }
    SafeFreePool (BootNextValue);
    return TRUE;
  }

  //
  // 7. If the first BootOption in BootOrder is not "Windows Boot Manager".
  //

  OptionOrder = NULL;
  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,
             &OptionOrderSize,
             (VOID **) &OptionOrder);
  DPRINTF_BM_MISC ("  Get Efi Global Variable BootOrder returned %r.\n", Status);

  if (!EFI_ERROR (Status)) {
    for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {
      Status = GetBootOption (OptionOrder [i], &Option);
      if (!EFI_ERROR (Status)) {
        if (StrCmp (WINDOWS_BOOTMGR_DESCRIPTION, Option->Description) == 0) {
          DPRINTF_BM_MISC ("  First BootOption (No.%d) is Windows Boot Manager\n", OptionOrder [i]);
          SafeFreePool (OptionOrder);
          return FALSE;
        }
        break;
      }
    }
  }
  SafeFreePool (OptionOrder);

  return TRUE;
} // IsUsbFullInitializationNeeded


//
// FUNCTION NAME.
//      StartAllUsbHc - Connect all USB Host Controller.
//
// FUNCTIONAL DESCRIPTION.
//      This function will connect all USB Host Controller.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
EFIAPI
StartAllUsbHc (VOID)
{
  UINTN i;
  SCT_STATUS Status;
  EFI_HANDLE *UsbHcHandles;
  UINTN UsbHcHandlesCount;

  UsbHcHandles = NULL;
  UsbHcHandlesCount = 0;

#if OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND
    //
    // Connect PS2 devices.
    //

    ConnectPs2Devices ();

#endif  // OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiUsb2HcProtocolGuid,
                  NULL,
                  &UsbHcHandlesCount,
                  &UsbHcHandles);
  if (!EFI_ERROR (Status)) {
    for (i = 0; i < UsbHcHandlesCount; i++) {
      gBS->ConnectController (UsbHcHandles [i], NULL, NULL, TRUE);
    }

    FreePool (UsbHcHandles);
  } else {

    //
    // Decompress USB package and connect all USB devices.
    //

    DecompressOptionalFirmwareVolume (SCT_FIRMWAREVOLUME_TYPE_USB);
    Status = ConnectAllUsbHostController ();
  }

  return Status;

} // StartAllUsbHc


//
// FUNCTION NAME.
//      BmReadKeyStrokeEx - BootManager ReadKeyStrokeEx.
//
// FUNCTIONAL DESCRIPTION.
//      This function is a chain function for default ReadKeyStrokeEx.
//
// ENTRY PARAMETERS.
//      This            - pointer points to EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL.
//      KeyData         - pointer points to EFI_KEY_DATA.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
EFIAPI
BmReadKeyStrokeEx (
  IN EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *This,
  OUT EFI_KEY_DATA *KeyData
  )
{
  DPRINTF_BM_MISC ("Entry\n");

  if (!IsDetectingHotkey) {

    //
    // Restore the original ReadKeyStrokeEx function.
    //

    mTextInEx->ReadKeyStrokeEx = mOriginalReadKeyExFun;

    DPRINTF_BM_MISC (" Start all USB HC by ReadKeyStrokeEx\n");
    ReleaseAllUsbHc ();
    StartAllUsbHc ();

  }
  return (mOriginalReadKeyExFun)(This, KeyData);

} // BmReadKeyStrokeEx


//
// FUNCTION NAME.
//      BmReadKeyStroke - BootManager ReadKeyStroke.
//
// FUNCTIONAL DESCRIPTION.
//      This function is a chain function for default ReadKeyStroke.
//
// ENTRY PARAMETERS.
//      This            - pointer points to EFI_SIMPLE_TEXT_INPUT_PROTOCOL.
//      Key             - pointer points to EFI_INPUT_KEY.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
EFIAPI
BmReadKeyStroke (
  IN EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
  OUT EFI_INPUT_KEY *Key
  )
{
  DPRINTF_BM_MISC ("Entry\n");

  if ((mIsInPostBootPhase && ++mTriggerThreadHole == 2) ||
    (!IsDetectingHotkey && !mIsInPostBootPhase)) {

    //
    // Restore the original ReadKeyStroke function.
    //

    SavedConIn->ReadKeyStroke = mOriginalReadKeyFun;

    DPRINTF_BM_MISC (" Start all USB HC by ReadKeyStroke\n");
    ReleaseAllUsbHc ();
    StartAllUsbHc ();

  }
  return (mOriginalReadKeyFun)(This, Key);

} // BmReadKeyStroke


//
// FUNCTION NAME.
//      InitializeUsbFullInitOnDemand - Initialize the steps for USB Initialization On-demand.
//
// FUNCTIONAL DESCRIPTION.
//      This function will initialize the essential data or perform the pre-process for
//      USB Initialization On-demand feature.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
EFIAPI
InitializeUsbFullInitOnDemand (VOID)
{

  //
  // Check the current condition and determine whether doing full USB
  // initialization or not.
  //
  // BootManager will chain the default ReadKeyStrokeEx so that it can be
  // aware that ReadKeyStrokeEx is sent by others.
  //

  if (IsUsbFullInitializationNeeded () == FALSE) {

    RegisterUsbHcNotifyAndLock ();

    //
    // Chain the default ReadKeyStrokeEx function of gST->ConsoleInHandle.
    //

    mOriginalReadKeyExFun = mTextInEx->ReadKeyStrokeEx;
    mTextInEx->ReadKeyStrokeEx = BmReadKeyStrokeEx;

    //
    // Chain the default ReadKeyStroke function of gST->ConIn.
    //

    SavedConIn = gST->ConIn;
    mOriginalReadKeyFun = SavedConIn->ReadKeyStroke;
    SavedConIn->ReadKeyStroke = BmReadKeyStroke;
    return EFI_SUCCESS;
  }

  return EFI_ABORTED;
} // InitializeUsbFullInitOnDemand

#endif

#if (OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)

//
// FUNCTION NAME.
//      InitializeUiString - Initialize UI strings.
//
// FUNCTIONAL DESCRIPTION.
//      This function will collect all hotkey strings and install them into Hii
//      database for display.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
InitializeUiString (VOID)
{
  DPRINTF_BM_MISC ("InitializeUiString:\n");

  mUiStringHiiHandle = HiiAddPackages (
                       &mUiStringPackageListGuid,
                       NULL,
                       MODULE_STRING_ARRAY,
                       NULL);

  return (mUiStringHiiHandle != NULL) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;

} // InitializeUiString


//
// FUNCTION NAME.
//      PromptForLoadingCsm - Display a dialog to ask the user to load CSM module.
//
// FUNCTIONAL DESCRIPTION.
//      This function will display a dialog to query the user about whether loading
//      CSM related module or not.
//
//      If the user decides to load CSM, the system will warm-boot and load the
//      CSM at next P.O.S.T.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
PromptForLoadingCsm (VOID)
{
  UINT8 LoadCsm;
  SCT_STATUS Status;
  UINT32 SelectedOption;
  SCT_TEXT_SETUP_BROWSER2_PROTOCOL *TSB;
  EFI_STRING Title;
  EFI_STRING Prompt;

  DPRINTF_BM_MISC ("PromptForLoadingCsm\n");
  Status = gBS->LocateProtocol (
                  &gTextSetupBrowser2ProtocolGuid,
                  NULL,
                  (VOID **) &TSB);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Initialized string package for UI.
  //

  Status = InitializeUiString ();

  if (!EFI_ERROR (Status)) {
    gST->ConOut->ClearScreen (gST->ConOut);
    Title = NULL;
    Title = HiiGetString (mUiStringHiiHandle, STRING_TOKEN (SYSTEM_BOOT_MANAGER_TITLE_STR), NULL);

    Prompt = NULL;
    Prompt = HiiGetString (mUiStringHiiHandle, STRING_TOKEN (SYSTEM_BOOT_MANAGER_CSM_SUPPORT_QUERY_STR), NULL);

    if (Title == NULL || Prompt == NULL) {
      return EFI_NOT_FOUND;
    }

    SelectedOption = TSB->ShowMessageBoxEx (
                            Title,
                            Prompt,
                            NULL,
                            EFI_TEXT_ATTR (EFI_LIGHTGRAY, EFI_BLUE),
                            2,
                            0,
                            (EFI_STRING *)MessageBoxBtnStr,
                            0);
    gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_WHITE, EFI_BLACK));

    if (SelectedOption == 0) {

      //
      // Set LoadCsm variable for next boot.
      //

      LoadCsm = 1;
      Status = gRT->SetVariable (
                      L"LoadCsmNextBoot",
                      &gSctBdsServicesProtocolGuid,
                      EFI_VARIABLE_NON_VOLATILE |
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS,
                      sizeof (LoadCsm),
                      &LoadCsm);

      gRT->ResetSystem ((EFI_RESET_TYPE)EfiResetWarm, EFI_SUCCESS, 0, (CHAR16 *)NULL);
      Status = EFI_SUCCESS;

    } else {
      gST->ConOut->ClearScreen (gST->ConOut);
      Status = EFI_UNSUPPORTED;

    }
  }
  return Status;
} // PromptForLoadingCsm
#endif

//
// FUNCTION NAME.
//      RequestDrivers - Request for drivers.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to clear the SOR flag and let the drivers leave
//      un-requested state.
//
// ENTRY PARAMETERS.
//      FirmwareVolumeHandle  - The handle of the firmware volume that contains the
//                              file specified by FileName.
//      FvFileName      - FV File name list.
//      FirmwareVolumeType - Type of firmware volume which the driver resides in.
//      Dispatch        - Dispatch after the SOR flag have been cleared.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
RequestDrivers (
  IN EFI_HANDLE FirmwareVolumeHandle,
  IN EFI_GUID FvFileName [],
  IN UINTN FirmwareVolumeType,
  IN BOOLEAN Dispatch
  )
{
  UINT8 i;
  SCT_STATUS Status;
  EFI_STATUS RetStatus;
  EFI_HANDLE OptionalFvHandle;

  DPRINTF ("RequestDrivers\n");

  if (FirmwareVolumeHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Decompress optional firmware volume.
  //

  if (FirmwareVolumeType != SCT_FIRMWAREVOLUME_TYPE_MAIN) {
    DecompressOptionalFirmwareVolume (FirmwareVolumeType);
  }
  OptionalFvHandle = NULL;

  RetStatus = EFI_NOT_FOUND;
  i = 0;
  while (TRUE) {

    if (FvFileName [i].Data1 == 0) {
      break;
    }

    if (IsFvFileExist (FirmwareVolumeHandle, &FvFileName [i]) == FALSE) {

      Status = FindOptionalFvHandle (&FvFileName [i], &OptionalFvHandle);
      if (!EFI_ERROR (Status)) {

        //
        // Found it! Update handle to new one.
        //

        FirmwareVolumeHandle = OptionalFvHandle;
      }
    }

    //
    // Try to clear SOR flag.
    //

    DPRINTF (" Schedule %g ", &FvFileName [i]);
    Status = gDS->Schedule (FirmwareVolumeHandle, &FvFileName [i]);
    DPRINTF ("Returned %r\n", Status);
    RetStatus = (!EFI_ERROR (Status)) ? EFI_SUCCESS : RetStatus;
    i++;
  }

  if (!EFI_ERROR (RetStatus) && Dispatch) {
    RetStatus = BmDispatch (FALSE);
  }

  return RetStatus;
} // RequestDrivers

//
// FUNCTION NAME.
//      MsTaskTpmCheck - Default task for the TPM Operation Check Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function does nothing. Instead, it allows an external component
//      (the TCG Services driver) to implement the TPM Operation check.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskTpmCheck (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
#if OPTION_SUPPORT_TCG
  SCT_MILESTONE_TASK_TPM_PP_CHECK *TpmPpCheckData;

  TpmPpCheckData = (SCT_MILESTONE_TASK_TPM_PP_CHECK *)MilestoneData;

  if (TpmPpCheckData->PPRequireUIConfirm) {

    //
    // Don't execute the TPM request if vga does not connected.
    //

    if (TpmPpCheckData->IsVgaConnected == FALSE) {
      return SCT_STATUS_SUCCESS;
    }
  }

  //
  // Process TCG Physical Presence request
  //

  TcgPhysicalPresenceLibProcessRequest ();
  Tcg2PhysicalPresenceLibProcessRequest (NULL);
  TpmPpCheckData->IsPpExecuted = TRUE;

  return SCT_STATUS_SUCCESS;
#else
  return EFI_UNSUPPORTED;
#endif //OPTION_SUPPORT_TCG

} // MSTaskTpmCheck

//
// FUNCTION NAME.
//      MsTaskCapsuleFlashUpdate - Default task for the Capsule Flash Update Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Flash update task.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

#if OPTION_SUPPORT_CAPSULE_UPDATE
SCT_STATUS
MsTaskCapsuleFlashUpdate (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  return UpdateCapsuleService (MilestoneData, MilestoneDataSize);
} //MsTaskCapsuleFlashUpdate
#endif // OPTION_SUPPORT_CAPSULE_UPDATE

// FUNCTION NAME.
//      MsTaskBiosSelfHealing - Default task for the Bios Self Healing Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Bios Self Healing task.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

#if OPTION_SUPPORT_BIOS_SELF_HEALING
SCT_STATUS
MsTaskBiosSelfHealing (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  ProcessBiosSelfHealing (MilestoneData, MilestoneDataSize);

  return EFI_SUCCESS;
} //MsTaskBiosSelfHealing
#endif // OPTION_SUPPORT_BIOS_SELF_HEALING


//
// FUNCTION NAME.
//      LaunchFvFile - Start an EFI image from firmware volume.
//
// FUNCTIONAL DESCRIPTION.
//      This function will load specific EFI image from firmware volume into
//      memory and start it.
//
// ENTRY PARAMETERS.
//      ParentHandle    - The caller's image handle.
//      FvFile          - DevicePath for FV file.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      ExitDataSize    - pointer to the size in bytes.
//      ExitData        - pointer to a pointer to a data buffer that includes a Null-
//                        terminated string.
//

EFI_STATUS
EFIAPI
LaunchFvFile (
  IN EFI_HANDLE ParentHandle,
  IN EFI_DEVICE_PATH_PROTOCOL *FvFile,
  OUT UINTN *ExitDataSize,
  OUT PCHAR16 *ExitData
  )
{
  EFI_TPL Tpl;
  EFI_HANDLE FvHandle;
  EFI_STATUS Status;
  EFI_GUID *FileName;
  EFI_HANDLE FileImageHandle;
  EFI_DEVICE_PATH_PROTOCOL *FullDevicePath;

  FullDevicePath = NULL;

  //
  // Verify FV DevicePath first.
  //

  if (FvFile == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (FvFile->Type != MEDIA_DEVICE_PATH ||
    FvFile->SubType != MEDIA_PIWG_FW_FILE_DP) {

    return EFI_UNSUPPORTED;
  }

  FileName = &((MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)FvFile)->FvFileName;

  FvHandle = NULL;
  if (IsFvFileExist (mFvHandle, FileName)) {
    FvHandle = mFvHandle;
  } else {
    FindOptionalFvHandle (FileName, &FvHandle);
  }

  if (FvHandle == NULL) {
    DPRINTF_BM_MISC ("  Can not find target FvFile %g\n", FileName);
    return EFI_NOT_FOUND;
  }

  FullDevicePath = AppendDevicePath (
                     DevicePathFromHandle (FvHandle),
                     FvFile);
  if (FullDevicePath == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->LoadImage (
                  TRUE,
                  ParentHandle,
                  FullDevicePath,
                  NULL,
                  0,
                  &FileImageHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

#if OPTION_SUPPORT_SURE_BOOT
  Status = DisableSureBootTimerReset ();
#endif

  //
  // Force the TPL to TPL_APPLICATION.
  //

  Tpl = SetTpl (TPL_APPLICATION);

  //
  // Start the image.
  //

  Status = gBS->StartImage (
                  FileImageHandle,
                  ExitDataSize,
                  ExitData);

  //
  // The image returned, cleanup.
  //

  SetTpl (Tpl);
  return Status;

} // LaunchFvFile


//
// FUNCTION NAME.
//      GetDevicePathSizeEx - Returns the size of a device path in bytes.
//
// FUNCTIONAL DESCRIPTION.
//
//      This function returns the size, in bytes, of the device path data structure
//      specified by DevicePath including the end of device path node. If DevicePath
//      is NULL, then 0 is returned. If the length of the device path is bigger than
//      MaxSize, also return 0 to indicate this is an invalidate device path.
//
// ENTRY PARAMETERS.
//      DevicePath      - A pointer to a device path data structure.
//      MaxSize         - Max valid device path size. If big than this size,
//                        return error.
//
// EXIT PARAMETERS.
//      Function Return - 0, An invalid device path.
//                        Others, The size of a device path in bytes.
//

UINTN
GetDevicePathSizeEx (
  IN CONST EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  IN UINTN MaxSize
  )
{
  UINTN Size;
  UINTN NodeSize;

  if (DevicePath == NULL) {
    return 0;
  }

  //
  // Search for the end of the device path structure.
  //

  Size = 0;
  while (!IsDevicePathEnd (DevicePath)) {
    NodeSize = DevicePathNodeLength (DevicePath);
    if (NodeSize < END_DEVICE_PATH_LENGTH) {
      return 0;
    }
    Size += NodeSize;
    if (Size > MaxSize) {
      return 0;
    }
    DevicePath = NextDevicePathNode (DevicePath);
  }
  Size += DevicePathNodeLength (DevicePath);
  if (Size > MaxSize) {
    return 0;
  }

  return Size;
} // GetDevicePathSizeEx


//
// FUNCTION NAME.
//      StrSizeEx - Returns the size of a Null-terminated Unicode string.
//
// FUNCTIONAL DESCRIPTION.
//
//      This function returns the byte length of Unicode characters in the Null-terminated
//      Unicode string specified by String.
//
//      If the length is bigger than MaxStringLen, return length 0 to indicate that this is
//      an invalidate string.
//
// ENTRY PARAMETERS.
//      String          - A pointer to a Null-terminated Unicode string.
//      MaxSize         - Maximum string length in this string.
//
// EXIT PARAMETERS.
//      Function Return - 0, An invalid string.
//                        Others, The length of String.
//

UINTN
StrSizeEx (
  IN CONST CHAR16 *String,
  IN UINTN MaxStringLen
  )
{
  UINTN Length;

  //
  // If String is NULL or MaxStringLen is zero, return 0.
  // Also, String should be aligned in 16 bits.
  //

  if (String == NULL || MaxStringLen == 0 || ((UINTN)String & BIT0) != 0) {
    return 0;
  }

  for (Length = 0; *String != L'\0' && MaxStringLen != Length; String++, Length += 2);

  if (*String != L'\0' && MaxStringLen == Length) {
    return 0;
  }

  return (Length + 2);
} // StrSizeEx


//
// FUNCTION NAME.
//      ValidateOptionVariable - Validate the EFI Boot#### variable.
//
// FUNCTIONAL DESCRIPTION.
//
//      This function check if the content of specific Boot#### variable is valid.
//
// ENTRY PARAMETERS.
//      Variable        - Boot#### variable data.
//      VariableSize    - Returns the size of the EFI variable that was read.
//
// EXIT PARAMETERS.
//      Function Return - TRUE, The variable data is correct.
//                        FALSE, The variable data is corrupted.
//

BOOLEAN
EFIAPI
ValidateOptionVariable (
  UINT8 *Variable,
  UINTN VariableSize
  )
{
  UINT8 *TempPtr;
  UINTN StrSize;
  UINT16 FilePathSize;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;

  if (VariableSize <= sizeof (UINT16) + sizeof (UINT32)) {
    return FALSE;
  }

  //
  // Skip the option attribute.
  //

  TempPtr = Variable;
  TempPtr += sizeof (UINT32);

  //
  // Get the option's device path size.
  //

  FilePathSize = *(UINT16 *)TempPtr;
  TempPtr += sizeof (UINT16);

  //
  // Get the option's description string size.
  //

  StrSize = StrSizeEx (
              (CHAR16 *)TempPtr,
              VariableSize - sizeof (UINT16) - sizeof (UINT32));
  TempPtr += StrSize;

  //
  // Get the option's device path.
  //

  DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)TempPtr;
  TempPtr += FilePathSize;

  //
  // Validate boot option variable.
  //

  if ((FilePathSize == 0) || (StrSize == 0)) {
    return FALSE;
  }

  if (StrSize + FilePathSize + sizeof (UINT16) + sizeof (UINT32) > VariableSize) {
    return FALSE;
  }

  return (BOOLEAN)(GetDevicePathSizeEx (DevicePath, FilePathSize) != 0);
} // ValidateOptionVariable


//
// FUNCTION NAME.
//      GetRemovableBlockIo - Find all handles with a removable media device.
//
// FUNCTIONAL DESCRIPTION.
//      This function finds all handles that have the BlockIo protocol where
//      the protocol corresponds to a removable media device, e.g. CD-ROM.
//
//      BlockIo handles with removable media are treated separately from
//      BlockIo handles with fixed media. For fixed media the handle with
//      Simple File System protocol is used for the boot load option, but
//      this cannot be done for removable media because the handle with
//      Simple File System corresponds to the media in the device and not
//      to the device itself.
//
//      The LoadOption function will enumerate the child handles of the BlockIo
//      handle on each attempt to boot the option.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      NumberOfHandles - the address of a UINTN, the number of handles in the
//                        HandleBuffer.
//      HandleBuffer    - the address of an array of EFI_HANDLE's.
//

SCT_STATUS
GetRemovableBlockIo (
  OUT PUINTN NumberOfHandles,
  OUT EFI_HANDLE **HandleBuffer
  )
{
  UINTN i,j;
  SCT_STATUS Status;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath, *LastNode;

  if ((NumberOfHandles == NULL) || (HandleBuffer == NULL)) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  *NumberOfHandles = 0;
  *HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  NumberOfHandles,
                  HandleBuffer);
  if (EFI_ERROR (Status) || *NumberOfHandles == 0) {
    return SCT_STATUS_NOT_FOUND;
  }

  //
  // Remove each device that is not removable-media.
  // We do this by moving all the good entries to the front of the array, then
  // we report the size of the array to be the number of good entries. When the
  // caller frees the array the address is still correct so the extra memory is
  // recovered at that time.
  //

  j = 0;
  for (i = 0; i < *NumberOfHandles; i++) {
    Status = gBS->OpenProtocol (
                    (*HandleBuffer) [i], // the handle being tested.
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlockIo,           // interface.
                    mImageHandle,       // the handle who is testing.
                    NULL,               // no controller handle.
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status)) {
      continue;
    }
    if (!BlockIo->Media->RemovableMedia) {
      continue;
    }

    //
    // We know at this point that this handle is associated with a removable
    // media BlockIo device, but we need to determine if the handle is for the
    // device itself or for the media in the device. We check the device path
    // on this handle and look at the last node. If the node is not media then
    // this handle is the device itself.
    //

    Status = gBS->OpenProtocol (
                    (*HandleBuffer) [i], // the handle being tested.
                    &gEfiDevicePathProtocolGuid,
                    (VOID **) &DevicePath,        // interface.
                    mImageHandle,       // the handle who is testing.
                    NULL,               // no controller handle.
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status)) {
      continue;
    }

    LastNode = GetLastDeviceNode (DevicePath);
    if (LastNode == NULL) {
      continue;
    }

    if  (LastNode->Type == MEDIA_DEVICE_PATH) {
      continue;
    }

    (*HandleBuffer) [j++] = (*HandleBuffer) [i];
  }

  //
  // Update the count from the total number of BlockIo handles to the number of
  // handles that correspond to a removable media device.
  //

  *NumberOfHandles = j;

  return SCT_STATUS_SUCCESS;
} // GetRemovableBlockIo


//
// FUNCTION NAME.
//      GetNonRemovableMediaBootableDevices - Get an array of bootable handles.
//
// FUNCTIONAL DESCRIPTION.
//      This function gets all the bootable handles that do not have an
//      instance of BlockIo installed that corresponds to a removable media
//      device.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//      NumberOfHandles - the address of a UINTN, the number of handles in the
//                        HandleBuffer.
//      HandleBuffer    - the address of an array of EFI_HANDLE's.
//

SCT_STATUS
GetNonRemovableMediaBootableDevices (
  OUT PUINTN NumberOfHandles,
  OUT EFI_HANDLE **HandleBuffer
  )
{
  UINTN i,j;
  SCT_STATUS Status;
  EFI_BLOCK_IO_PROTOCOL *BlockIo;
  UINTN NumberOfSimpleFileSystemHandles;
  EFI_HANDLE *SimpleFileSystemHandleBuffer;
  UINTN NumberOfLoadFileHandles;
  EFI_HANDLE *LoadFileHandleBuffer;

  if ((NumberOfHandles == NULL) || (HandleBuffer == NULL)) {
    return SCT_STATUS_INVALID_PARAMETER;
  }


  //
  // Get the handles for Simple File System.
  //

  NumberOfSimpleFileSystemHandles = 0;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiSimpleFileSystemProtocolGuid,
                  NULL,
                  &NumberOfSimpleFileSystemHandles,
                  &SimpleFileSystemHandleBuffer);
  if (EFI_ERROR (Status) || NumberOfSimpleFileSystemHandles == 0) {
    DPRINTF ("  WARN: No SimpleFileSystem devices found.\n");
  }

  //
  // Get the handles for Load File.
  //

  NumberOfLoadFileHandles = 0;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiLoadFileProtocolGuid,
                  NULL,
                  &NumberOfLoadFileHandles,
                  &LoadFileHandleBuffer);
  if (EFI_ERROR (Status) || NumberOfLoadFileHandles == 0) {
    DPRINTF ("  WARN: No LoadFile devices found.\n");
  }

  if (NumberOfSimpleFileSystemHandles + NumberOfLoadFileHandles == 0) {
    DPRINTF ("  No devices found.\n");
    return SCT_STATUS_NOT_FOUND;
  }

  //
  // Merge the buffers into one buffer.
  //

  *HandleBuffer = AllocatePool (
                    (sizeof (EFI_HANDLE) * NumberOfSimpleFileSystemHandles) +
                    (sizeof (EFI_HANDLE) * NumberOfLoadFileHandles));
  if (*HandleBuffer == NULL) {
    return SCT_STATUS_OUT_OF_RESOURCES;
  }
  j = 0;
  for (i = 0; i < NumberOfSimpleFileSystemHandles; i++) {
    (*HandleBuffer) [j++] = SimpleFileSystemHandleBuffer [i];
  }
  for (i = 0; i < NumberOfLoadFileHandles; i++) {
    (*HandleBuffer) [j++] = LoadFileHandleBuffer [i];
  }
  *NumberOfHandles = j;
  SafeFreePool (SimpleFileSystemHandleBuffer);
  SafeFreePool (LoadFileHandleBuffer);

  //
  // Remove each device that is removable-media.
  // We do this by moving all the good entries to the front of the array, then
  // we report the size of the array to be the number of good entries. When the
  // caller frees the array the address is still correct so the extra memory is
  // recovered at that time.
  //

  j = 0;
  for (i = 0; i < *NumberOfHandles; i++) {
    Status = gBS->OpenProtocol (
                    (*HandleBuffer) [i], // the handle being tested.
                    &gEfiBlockIoProtocolGuid,
                    (VOID **) &BlockIo,           // interface.
                    mImageHandle,       // the handle who is testing.
                    NULL,               // no controller handle.
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (!EFI_ERROR (Status)) {
      if (BlockIo->Media->RemovableMedia) {
        continue;
      }
    }

    DPRINTF ("  Found non-removable-media device 0x%x.\n", (*HandleBuffer) [i]);
    (*HandleBuffer) [j++] = (*HandleBuffer) [i];
  }

  //
  // Update the count from the total number of BlockIo handles to the number of
  // handles that correspond to a removable media device.
  //

  *NumberOfHandles = j;

  return SCT_STATUS_SUCCESS;
} // GetNonRemovableMediaBootableDevices

#if (OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)

//
// FUNCTION NAME.
//      IsPureUefiOs - Check if the OS loader is CSM independent.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check the PE-COFF format to see if the image can be
//      launched without legacy BIOS support.
//
//      This check is only applicable for Windows OS loader so far.
//
// ENTRY PARAMETERS.
//      ImageBase       - The buffer of loaded image.
//
// EXIT PARAMETERS.
//      Function Return - TRUE, pure UEFI OS. Otherwise, need CSM support.
//

BOOLEAN
IsPureUefiOs (IN VOID *ImageBase)
{
  EFI_IMAGE_DOS_HEADER *DosHdr;
  EFI_IMAGE_OPTIONAL_HEADER_UNION *PeHdr;
  UINT16 DllCharacteristics;

  DllCharacteristics = 0;
  DPRINTF_LO ("  ImageBase = 0x%x\n", ImageBase);

  if (ImageBase == NULL) {
    return FALSE;
  }

  DosHdr = (EFI_IMAGE_DOS_HEADER *)ImageBase;

  if (DosHdr->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
    return FALSE;
  }

  PeHdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION *)((UINT8*)ImageBase + DosHdr->e_lfanew);

  if (PeHdr->Pe32.Signature != EFI_IMAGE_NT_SIGNATURE) {
    return FALSE;
  }

  if (PeHdr->Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    DllCharacteristics = PeHdr->Pe32.OptionalHeader.DllCharacteristics;
    DPRINTF_LO ("  DLL = 0x%x\n", DllCharacteristics);

  } else if (PeHdr->Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    DllCharacteristics = PeHdr->Pe32Plus.OptionalHeader.DllCharacteristics;
    DPRINTF_LO ("  DLL = 0x%x\n", DllCharacteristics);

  } else {
    return FALSE;
  }

  return (DllCharacteristics == 0x2000) ? TRUE : FALSE;

} // IsPureUefiOs
#endif

//
// FUNCTION NAME.
//      SetBootLogoInvalid - Inform BGRT table of boot logo invalid.
//
// FUNCTIONAL DESCRIPTION.
//      Notify BGRT that the boot logo is invalid due to some screen operations.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

#if OPTION_SYSTEM_SCT_ACPI_BGRT

EFI_STATUS
EFIAPI
SetBootLogoInvalid (VOID)
{
  return InvalidBGRTLogo ();
} // SetBootLogoInvalid

#endif


//
// FUNCTION NAME.
//      ReportBootManagerError - Report BootManager error log via error manager.
//
// FUNCTIONAL DESCRIPTION.
//      Log an error when BootManager is malfunction.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

EFI_STATUS
ReportBootManagerError (VOID)
{
  EFI_STATUS Status;
  SCT_ERROR_PROTOCOL *ErrorLog;

  Status = gBS->LocateProtocol (&gSctErrorProtocolGuid, NULL, (VOID **) &ErrorLog);
  if (!EFI_ERROR (Status)) {

    if (mIsBootOptionDamaged) {
      Status = ErrorLog->Log ( CONFIG_REPORT_BOOT_MANAGER_BOOT_OPTION_ERROR );
    }
    if (mIsHotkeyListDamaged) {
      Status = ErrorLog->Log ( CONFIG_REPORT_BOOT_MANAGER_KEY_OPTION_ERROR );
    }
  }

  return Status;
} // ReportBootManagerError


//
// FUNCTION NAME.
//      LaunchFileGuidDriver - Launch a built-in Driver(application).
//
// FUNCTIONAL DESCRIPTION.
//      This function will launch a built-in Driver(applications) which is within
//      firmware volume.
//
// ENTRY PARAMETERS.
//      FilePath        - The string for FV file path.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
LaunchFileGuidDriver (IN CHAR16 *FileGuid)
{
  PCHAR16 ExitData;
  EFI_STATUS Status;
  UINTN ExitDataSize;
  EFI_DEVICE_PATH_PROTOCOL* FvFileDp;

  DPRINTF_BM_MISC ("LaunchFileGuidDriver:\n");

  if (FileGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  FvFileDp = NULL;
  ExitData = NULL;
  ExitDataSize = 0;

  FvFileDp = BM_CONVERT_TEXT_TO_DEVICE_PATH (FileGuid);

  if (FvFileDp == NULL) {
    return EFI_NOT_FOUND;
  }

  Status = LaunchFvFile (mImageHandle, FvFileDp, &ExitDataSize, &ExitData);
  SafeFreePool (FvFileDp);
  return Status;

} // LaunchFileGuidDriver


//
// FUNCTION NAME.
//      ReadFileToBuffer - Read the content of one file to a data buffer.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to read the specific file from the file system.
//      If it is successful to find the file, the file size and data buffer will be
//      allocated.
//
//      The caller has the responsibility to free the resources.
//
// ENTRY PARAMETERS.
//      FilePath        - the full device path (FILEPATH_DEVICE_PATH).
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//      BufferSize      - the file size.
//      Buffer          - the allocated buffer for whole file content.
//

EFI_STATUS
EFIAPI
ReadFileToBuffer (
  IN EFI_DEVICE_PATH_PROTOCOL *FilePath,
  OUT UINTN *BufferSize,
  OUT VOID **Buffer
  )
{
  EFI_STATUS Status;
  EFI_HANDLE FsHandle;
  CHAR16 *FileName;
  UINTN scratchBufferSize;
  EFI_FILE_PROTOCOL *RootFh;
  EFI_GUID gFileInfo = EFI_FILE_INFO_ID;
  EFI_FILE_INFO *FileInfo;
  EFI_FILE_PROTOCOL *FileHandle;
  EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;

  if (FilePath == NULL || BufferSize == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  RootFh = NULL;
  *BufferSize = 0;
  FsHandle = NULL;
  RemainingDevicePath = FilePath;

  Status = gBS->LocateDevicePath (
                  &gEfiSimpleFileSystemProtocolGuid,
                  &RemainingDevicePath,
                  &FsHandle);

  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->HandleProtocol (
                  FsHandle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&SimpleFileSystem);

  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  //
  // The remaining device path should be FILEPATH_DEVICE_PATH.
  //

  if (RemainingDevicePath->Type == MEDIA_DEVICE_PATH &&
    RemainingDevicePath->SubType == MEDIA_FILEPATH_DP) {
    FileName = ((FILEPATH_DEVICE_PATH *)RemainingDevicePath)->PathName;
    DPRINTF_BM_MISC ("  File Name = %s\n", FileName);
  } else {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Open Root Volume.
  //

  RootFh = NULL;
  Status = SimpleFileSystem->OpenVolume (SimpleFileSystem, &RootFh);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = RootFh->Open (RootFh, &FileHandle, FileName, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  scratchBufferSize = 0;
  Status = FileHandle->GetInfo (FileHandle, &gFileInfo, &scratchBufferSize, NULL);

  if (!EFI_ERROR (Status ) || Status == EFI_BUFFER_TOO_SMALL) {
    FileInfo = (EFI_FILE_INFO *)AllocatePool (scratchBufferSize);
    if (FileInfo == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Status = FileHandle->GetInfo (
                           FileHandle,
                           &gFileInfo,
                           &scratchBufferSize,
                           FileInfo);
    if (!EFI_ERROR (Status) &&
      (FileInfo->Attribute & EFI_FILE_DIRECTORY) != EFI_FILE_DIRECTORY) {

      *BufferSize = (UINTN)FileInfo->FileSize;

      DPRINTF_BM_MISC ("  File BufferSize = 0x%x\n", *BufferSize);

      //
      // Read file content to buffer.
      //

      *Buffer = AllocatePool (*BufferSize);
      if (*Buffer != NULL) {
        Status = FileHandle->SetPosition (FileHandle, 0);
        if (!EFI_ERROR (Status)) {
          scratchBufferSize = *BufferSize;
          Status = FileHandle->Read (FileHandle, &scratchBufferSize, *Buffer);
          DPRINTF_BM_MISC ("  Read File to buffer %r total read 0x%x\n",
            Status,
            scratchBufferSize);
        }
      } else {
        Status = EFI_OUT_OF_RESOURCES;
      }
    }
    SafeFreePool (FileInfo);
  }

  return Status;
} // ReadFileToBuffer

//
// FUNCTION NAME.
//      BmUnloadImages - Unload started images.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to unload started images.
//      This function returns EFI_SUCCESS if there is anyone image unloaded successfully.
//
// ENTRY PARAMETERS.
//      FvFileName      - FV File Name List.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
BmUnloadImages (IN EFI_GUID FvFileName [])
{
  UINT8 i;
  UINTN Index;
  EFI_STATUS Status;
  EFI_STATUS ReStatus;
  EFI_GUID *NameGuid;
  UINTN DriverImageHandleCount;
  EFI_HANDLE *DriverImageHandleBuffer;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;
  EFI_DEVICE_PATH_PROTOCOL *LastDeviceNode;

  DriverImageHandleCount = 0;
  DriverImageHandleBuffer = NULL;
  ReStatus = EFI_NOT_FOUND;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiLoadedImageProtocolGuid,
                  NULL,
                  &DriverImageHandleCount,
                  &DriverImageHandleBuffer);

  if (EFI_ERROR (Status)) {
    return Status;
  }
  i = 0;
  while (TRUE) {

    if (FvFileName [i].Data1 == 0) {
      break;
    }

    //
    // Find the target image handle and unload it.
    //

    for (Index = 0; Index < DriverImageHandleCount; Index++) {

      LoadedImage = NULL;
      Status = gBS->HandleProtocol (
                      DriverImageHandleBuffer [Index],
                      &gEfiLoadedImageProtocolGuid,
                      (VOID *)&LoadedImage);

      if (EFI_ERROR (Status) || LoadedImage == NULL || LoadedImage->FilePath == NULL) {
        continue;
      }

      TempDevicePath = LoadedImage->FilePath;
      LastDeviceNode = TempDevicePath;
      while (!IsDevicePathEnd (TempDevicePath)) {
        LastDeviceNode = TempDevicePath;
        TempDevicePath = NextDevicePathNode (TempDevicePath);
      }
      NameGuid = EfiGetNameGuidFromFwVolDevicePathNode (
                   (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)LastDeviceNode);
      if ((NameGuid != NULL) && (CompareGuid (NameGuid, &FvFileName [i]))) {
        Status = gBS->UnloadImage (DriverImageHandleBuffer [Index]);
        ReStatus = (!EFI_ERROR (Status)) ? EFI_SUCCESS : ReStatus;
        break;
      }
    }
    i++;
  }

  gBS->FreePool (DriverImageHandleBuffer);
  return ReStatus;
} // BmUnloadImages

//
// FUNCTION NAME.
//      BmReconnectImagesBinding - Reconnect image's binding by calling DisconnectController & ConnectControler.
//
// FUNCTIONAL DESCRIPTION.
//      This function will call the DisconnectController to disconnect all the associated binding driver
//      per the pass-in image handle, and then perform the ConnectControler from the pass-in ControllerHandle
//      if necessary.
//
// ENTRY PARAMETERS.
//      ControllerHandle - Handle of the controller to be re-connected.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
BmReconnectImagesBinding (
  IN EFI_HANDLE ControllerHandle
  )
{
  EFI_STATUS                Status = EFI_NOT_FOUND;

  UINTN                     BindingHandleCount;
  EFI_HANDLE                *BindingHandleBuffer;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  EFI_GUID                  *NameGuid;
  EFI_GUID                  HttpBootFileGuid = {0xecebcb00, 0xd9c8, 0x11e4, {0xaf, 0x3d, 0x8c, 0xdc, 0xd4, 0x26, 0xc9, 0x73}};
  EFI_HANDLE                HttpBootDxeHandle = NULL;

  UINTN                     Dhcp4HandleCount;
  EFI_HANDLE                *Dhcp4HandleBuffer;
  UINTN                     Dhcp6HandleCount;
  EFI_HANDLE                *Dhcp6HandleBuffer;
  UINTN                     DhcpHandleCount = 0;
  EFI_HANDLE                *DhcpHandleBuffer = NULL;

  UINTN                     DeviceHandleCount;
  EFI_HANDLE                *DeviceHandleBuffer;
  EFI_DRIVER_BINDING_PROTOCOL *DriverBinding;

  UINTN                     DeviceBindingCount = 0;

  //
  // Found the driver image handle by guid, try to find related DriverBindingProtocol based
  // on the matched image handle.
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDriverBindingProtocolGuid,
                  NULL,
                  &BindingHandleCount,
                  &BindingHandleBuffer);
  DPRINTF_BM_MISC ("Ret = [%r], BindingHandleCount = [%d]!!\n", Status, BindingHandleCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  for (UINTN Index = 0; Index < BindingHandleCount; Index++) {
    //
    // Try to find the driver image handle by pass-in FV file name guid.
    //
    LoadedImage = NULL;
    Status = gBS->HandleProtocol (
                    BindingHandleBuffer[Index],
                    &gEfiLoadedImageProtocolGuid,
                    (VOID *)&LoadedImage);
    if (EFI_ERROR (Status) || LoadedImage == NULL || LoadedImage->FilePath == NULL) {
      continue;
    }

    NameGuid = EfiGetNameGuidFromFwVolDevicePathNode (
      (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)LoadedImage->FilePath);
    if ((NameGuid == NULL) || !(CompareGuid (NameGuid, &HttpBootFileGuid))) {
      continue;
    }

    HttpBootDxeHandle = BindingHandleBuffer [Index];
    DPRINTF_BM_MISC ("BindingHandleBuffer[%d] == [0x%x]!!\n", Index, BindingHandleBuffer[Index]);
    break;
  }
  if (BindingHandleBuffer != NULL) {
    FreePool (BindingHandleBuffer);
  }

  //
  // Found the device handle by DhcpXProtocolGuid guid, these Protocols was installed by HttpBootDxe Binding Driver
  // try to find related DhcpXProtocol based on the matched device handle.
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDhcp4ProtocolGuid,
                  NULL,
                  &Dhcp4HandleCount,
                  &Dhcp4HandleBuffer);
  DPRINTF_BM_MISC ("Ret = [%r], Dhcp4HandleCount = [%d]!!\n", Status, Dhcp4HandleCount);
  if (EFI_ERROR (Status)) {
    Dhcp4HandleCount = 0;
    Dhcp4HandleBuffer = NULL;
  }

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiDhcp6ProtocolGuid,
                  NULL,
                  &Dhcp6HandleCount,
                  &Dhcp6HandleBuffer);
  DPRINTF_BM_MISC ("Ret = [%r], Dhcp6HandleCount = [%d]!!\n", Status, Dhcp6HandleCount);
  if (EFI_ERROR (Status)) {
    Dhcp6HandleCount = 0;
    Dhcp6HandleBuffer = NULL;
  }

  if ((Dhcp4HandleCount + Dhcp6HandleCount) > 0) {
    DhcpHandleBuffer = (EFI_HANDLE *) AllocatePool (sizeof (EFI_HANDLE) * (Dhcp4HandleCount + Dhcp6HandleCount));
    for (UINTN i = 0; i < Dhcp4HandleCount; i++, DhcpHandleCount++) {
      DhcpHandleBuffer[DhcpHandleCount] = Dhcp4HandleBuffer[i];
    }
    if (Dhcp4HandleBuffer != NULL) {
      FreePool (Dhcp4HandleBuffer);
    }

    for (UINTN i = 0; i < Dhcp6HandleCount; i++, DhcpHandleCount++) {
      DhcpHandleBuffer[DhcpHandleCount] = Dhcp6HandleBuffer[i];
    }
    if (Dhcp6HandleBuffer != NULL) {
      FreePool (Dhcp6HandleBuffer);
    }
  }

  DPRINTF_BM_MISC ("DhcpHandleCount = [%d]!!\n", DhcpHandleCount);
  for (UINTN Index2 = 0; Index2 < DhcpHandleCount; Index2++) {
    DPRINTF_BM_MISC ("DhcpHandleBuffer[%d] == [0x%x]!!\n", Index2, DhcpHandleBuffer[Index2]);
  }

  //
  // Found the driver image handle by guid, try to find related DriverBindingProtocol based
  // on the matched image handle.
  //
  Status = gBS->LocateHandleBuffer (
                  AllHandles,
                  NULL,
                  NULL,
                  &DeviceHandleCount,
                  &DeviceHandleBuffer);
  DPRINTF_BM_MISC ("Ret = [%r], DeviceHandleCount = [%d]!!\n", Status, DeviceHandleCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  for (UINTN Index = 0; Index < DeviceHandleCount; Index++) {
    //
    // Get the DriverBindingProtocol from the handle to check if DriverBinding's ImageHandle
    // match to the found ImageHandle.
    //
    Status = gBS->HandleProtocol (
                    DeviceHandleBuffer[Index],
                    &gEfiDriverBindingProtocolGuid,
                    (VOID **)&DriverBinding);
    if (EFI_ERROR (Status)) {
      continue;
    }
    //
    // Use the ImageHandle instead of DriverBindingHandle from the DriverBindingProtocol since
    // it is possible that the binding protocol such as network drivers need to support IPV4 or
    // IPV6 maybe install onto different DriverBindingHandle.  But the ImageHandle normally
    // should be the same.
    //
    if (DriverBinding->ImageHandle != HttpBootDxeHandle) {
      continue;
    }

    DeviceBindingCount++;

    //
    // Try to disconnect the binding driver specified by ImageHandle for every installed handles.
    // The Binding driver may not necessary have relationship with pass in controller Handler.
    // Instead, the related binding driver's image handle maybe associated to other controller
    // handles which was opened by EFI_OPEN_PROTOCOL_BY_DRIVER, so the found binding could be
    // called into BindingStop when calling DisconnectController.
    //
    for (UINTN Index2 = 0; Index2 < DhcpHandleCount; Index2++) {
      DPRINTF_BM_MISC ("DhcpHandleBuffer[%d] = [0x%x]!!\n", Index2, DhcpHandleBuffer[Index2]);
      Status = gBS->DisconnectController (
                      DhcpHandleBuffer[Index2],
                      DriverBinding->DriverBindingHandle,
                      NULL);
      DPRINTF_BM_MISC ("gBS->DisconnectController ret = [%r]!!\n", Status);
    }
  }
  if (DeviceHandleBuffer != NULL) {
    FreePool (DeviceHandleBuffer);
  }
  if (DhcpHandleBuffer != NULL) {
    FreePool (DhcpHandleBuffer);
  }

  //
  // It could not find any matched image per guid.
  //
  DPRINTF_BM_MISC ("DeviceBindingCount = [%d]!!\n", DeviceBindingCount);
  if (DeviceBindingCount > 0) {
    //
    // ReConnect the drivers specified from ControllerHandle.
    //
    if (ControllerHandle != NULL) {
      ConnectAllHandles ();
      DPRINTF_BM_MISC ("ConnectAllHandles!!\n");
    }
  } else {
    Status = EFI_NOT_FOUND;
  }

  return Status;
}


#if OPTION_SYSTEM_BOOT_MANAGER_LOCK_SMRAM_IN_BDS_ENTRY

//
// FUNCTION NAME.
//      BdsLockSmram - Lock each region of SMRAM.
//
// FUNCTIONAL DESCRIPTION.
//      This function will try to use EFI_SMM_ACCESS_PROTOCOL to lock each region of SMRAM.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
BdsLockSmram (VOID)
{
  EFI_STATUS Status;
  UINTN SmramMapSize;
  EFI_SMM_ACCESS2_PROTOCOL *SmmAccess;

  DPRINTF_FUNCTION_ENTRY();

  Status = EFI_SUCCESS;

  //
  // Get EFI_SMM_ACCESS_PROTOCOL protocol instance.
  //

  Status = gBS->LocateProtocol (
                  &gEfiSmmAccess2ProtocolGuid,
                  NULL,
                  (VOID **)&SmmAccess);

  DPRINTF_BM ("  Locate EFI_SMM_ACCESS2_PROTOCOL returned %r\n", Status);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Get total size of SMRAM Map information.
  //

  SmramMapSize = 0;
  Status = SmmAccess->GetCapabilities (SmmAccess, &SmramMapSize, NULL);
  DPRINTF_BM ("  SmmAccess->GetCapabilities returned %r\n", Status);

  if (Status != EFI_BUFFER_TOO_SMALL) {
    return EFI_DEVICE_ERROR;
  }

  //
  // Get number of region.
  //

  if (Status != EFI_BUFFER_TOO_SMALL) {
    Status = SmmAccess->Lock (SmmAccess);
    DPRINTF_BM ("  SmmAccess->Lock %r\n", Status);
  }

  return Status;

} // BdsLockSmram

#endif

//
// FUNCTION NAME.
//      InternalBmEmptyCallbackFunction - Dummy function needed by the creation of EVT_NOTIFY_SIGNAL event.
//
// FUNCTIONAL DESCRIPTION.
//      This function is a dummy function in order to pass the check in CreateEventEx.
//
// ENTRY PARAMETERS.
//      Event           - Event whose notification function is being invoked.
//      Context         - The pointer to the notification function's context.
//
// EXIT PARAMETERS.
//      None.
//

VOID
EFIAPI
InternalBmEmptyCallbackFunction (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  return;
} // InternalBmEmptyCallbackFunction

//
// FUNCTION NAME.
//      BmDispatch - This function will call gDS->Dispatch and invoke SMM dispatcher.
//
// FUNCTIONAL DESCRIPTION.
//      This function will call gDS->Dispatch, and if there is no DXE driver is dispatched,
//      Boot Manager is responsible for evoking SMM dispatcher.
//
// ENTRY PARAMETERS.
//      BOOLEAN         - Signal flag.
//
// EXIT PARAMETERS.
//      Return EFI status code.
//        EFI_NOT_STARTED     Function was called within a non-TPL_APPLICATION.
//        EFI_SUCCESS         One or more DXE driver were dispatched.
//        EFI_NOT_FOUND       No DXE drivers were dispatched.
//        EFI_ALREADY_STARTED An attempt is being made to start the DXE Dispatcher recursively.
//                            Thus, no action was taken.
//

EFI_STATUS
EFIAPI
BmDispatch (
  IN BOOLEAN Signal
  )
{
  EFI_STATUS Status;
  EFI_TPL CurrentTpl = EfiGetCurrentTpl ();

  if ( CurrentTpl != TPL_APPLICATION) {
    DPRINTF_BM_MISC ("CurrentTpl = [0x%x]\n", CurrentTpl);
    return EFI_NOT_STARTED;
  }

  if (BmDispatchEvent == NULL) {
    Status = gBS->CreateEventEx (
                    EVT_NOTIFY_SIGNAL,
                    TPL_NOTIFY,
                    InternalBmEmptyCallbackFunction,
                    NULL,
                    &gEfiEventDxeDispatchGuid,
                    &BmDispatchEvent);
  }

  Status = gDS->Dispatch ();
  //   EFI_SUCCESS         One or more DXE driver were dispatched.
  //   EFI_NOT_FOUND       No DXE drivers were dispatched.
  //   EFI_ALREADY_STARTED An attempt is being made to start the DXE Dispatcher recursively.
  //                       Thus, no action was taken.
  DPRINTF_BM_MISC ("gDS->Dispatch Status = [%r]:\n", Status);
  if (Status == EFI_NOT_FOUND && Signal) {
    //
    // If there is no any DXE driver be dispatched, boot manager
    // is responsible for evoking Smm dispatcher.
    //
    gBS->SignalEvent (BmDispatchEvent);
  }

  return Status;
} // BmDispatch


//
// FUNCTION NAME.
//      SaveMemoryMap - Save memory type information.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called when the ReadyToBoot event occurs.
//
//      This function updates the memory information type variable if the
//      memory used on this boot was greater than what was reserved through
//      the variable. The variable serves as a high-water marker, such that
//      the initial memory reservations will be for the largest amount of
//      memory ever used for each type of memory.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      None.
//

VOID
EFIAPI
SaveMemoryMap (VOID)
{
  EFI_STATUS Status;
  EFI_MEMORY_TYPE_INFORMATION *PreviousMemoryTypeInformation;
  EFI_MEMORY_TYPE_INFORMATION *CurrentMemoryTypeInformation;
  UINTN VariableSize;
  BOOLEAN UpdateRequired;
  UINTN Index;
  UINTN Index1;
  UINT32 Previous;
  UINT32 Current;
  UINT32 Next;
  VOID *HobList;
  UINT32 MemoryType;    SUPPRESS_WARNING_IF_UNUSED (MemoryType);
  VOID *BackupMemoryTypeInformation;
  UINTN BackupMemoryTypeInformationSize;
  EFI_PEI_HOB_POINTERS Hob;
  UINT32 Attributes;

  UpdateRequired = FALSE;
  Attributes = 0;

  //
  // Retrieve the current memory usage statistics.  If they are not found, then
  // no adjustments can be made to the Memory Type Information variable.
  //

  Status = EfiGetSystemConfigurationTable (
             &gEfiMemoryTypeInformationGuid,
             (VOID **) &CurrentMemoryTypeInformation);
  if (EFI_ERROR (Status) || CurrentMemoryTypeInformation == NULL) {
    return;
  }

  //
  // Get the Memory Type Information settings from the HOB, if it exists. PEI
  // is responsible for getting them from variable and build a HOB to save them.
  // If the previous Memory Type Information is not available, then it sets.
  // defaults.
  //

  EfiGetSystemConfigurationTable (&gEfiHobListGuid, &HobList);

  Hob.Raw = GetNextGuidHob (&gEfiMemoryTypeInformationGuid, HobList);
  if ((Hob.Raw == NULL) || ((PreviousMemoryTypeInformation = GET_GUID_HOB_DATA (Hob.Guid)) == NULL)) {
    DPRINTF_BM ("  GetNextGuidHob returned : Failed\n");
    return;
  }

  VariableSize = GET_GUID_HOB_DATA_SIZE (Hob.Guid);
  DPRINTF_BM ("  GetNextGuidHob returned : Success\n");

  //
  // Use a heuristic to adjust the Memory Type Information for the next boot.
  // Find the amount of memory used during this boot and compare it to the
  // amount originally set aside by the PEI memory controller driver. If there
  // is a mismatch, update the amount to set aside so that, the next time we
  // boot, the larger amount is used. This causes the pools of memory to stay
  // about the same size from boot to boot.
  //

  for (Index = 0; PreviousMemoryTypeInformation [Index].Type != EfiMaxMemoryType; Index++) {

    Current = 0;
    for (Index1 = 0; CurrentMemoryTypeInformation [Index1].Type != EfiMaxMemoryType; Index1++) {
      if (PreviousMemoryTypeInformation [Index].Type == CurrentMemoryTypeInformation [Index1].Type) {
        Current = CurrentMemoryTypeInformation [Index1].NumberOfPages;
        break;
      }
    }

    if (CurrentMemoryTypeInformation [Index1].Type == EfiMaxMemoryType) {
      continue;
    }

    MemoryType = PreviousMemoryTypeInformation [Index].Type;
    Previous = PreviousMemoryTypeInformation [Index].NumberOfPages;
    Next = Previous;

#if !OPTION_SYSTEM_BOOT_MANAGER_REDUCE_MEMORY_USAGE
    //
    // Write next variable to 125% * current and Inconsistent Memory Reserved
    // across bootings may lead to S4 fail
    //

    if (Current > Previous) {
      Next = Current + ((Current * CONFIG_SYSTEM_BOOT_MANAGER_MEMORY_REGION_PAD_PCT)/100);
    }
    DPRINTF_BM (" Type [%08x] | Previous = %08x, Current = %08x, Next = %08x (page)\n",
      MemoryType,
      Previous,
      Current,
      Next);
#else

    //
    // Inconsistent Memory Reserved across bootings may lead to S4 fail
    // Write next variable to configuration * current when the pre-allocated memory is:
    //  1. More than 150% of needed memory.
    //  2. Less than the needed memory.
    //

    if ((Current + (Current >> 1)) < Previous) {
      Next = Current + ((Current * CONFIG_SYSTEM_BOOT_MANAGER_MEMORY_REGION_PAD_PCT)/100);
    } else if (Current > Previous) {
      Next = Current + ((Current * CONFIG_SYSTEM_BOOT_MANAGER_MEMORY_REGION_PAD_PCT)/100);
    }

    DPRINTF_BM (" Type %s [MinRequired %d] | Previous = %d, Current = %d, Next = %d (page)\n",
      MEMORY_TYPE_STR [MemoryType],
      mMemoryMapMinimumSize [MemoryType],
      Previous,
      Current,
      Next);
    Next = (mMemoryMapMinimumSize [MemoryType] > Next) ? mMemoryMapMinimumSize [MemoryType] : Next;
#endif

    if (Next > 0 && Next < 4) {         // round up to at least 4 pages.
      Next = 4;
    }

    if (Next != Previous) {
      PreviousMemoryTypeInformation [Index].NumberOfPages = Next;
      UpdateRequired = TRUE;
    }
  }

  //
  // If any changes were made to the Memory Type Information settings, then set
  // the new variable value.
  //

  if (UpdateRequired) {

    //
    // Backup any previous version of the memory type information. The backup is
    // used during an S4 resume so that we don't change the memory map if, after
    // this update, the user does a hibernate immediately. If they did a
    // hibernate immediately, the memory map that the OS saw during this boot
    // would not yet reflect the changes we are making here, and would cause a
    // failure during resume.
    //

    Status = SctLibGetVariable (
               EFI_MEMORY_TYPE_INFORMATION_VARIABLE_NAME,
               &gEfiMemoryTypeInformationGuid,
               &Attributes,
               &BackupMemoryTypeInformationSize,
               &BackupMemoryTypeInformation);
    if (!EFI_ERROR (Status)) {

      //
      // For the sake to change different variable attribute implemented in previous version,
      // We need to make the additional variable delete to make sure the new attribute and value
      // can be set as expected and no variable store clean up is required.
      //

      if (Attributes == (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)) {
        gRT->SetVariable (
               EFI_MEMORY_TYPE_INFORMATION_VARIABLE_NAME,
               &gEfiMemoryTypeInformationGuid,
               Attributes,
               0,
               NULL);
        gRT->SetVariable (
               L"MemoryTypeInformationBackup",
               &gEfiMemoryTypeInformationGuid,
               Attributes,
               0,
               NULL);
      }

      gRT->SetVariable (
             L"MemoryTypeInformationBackup",
             &gEfiMemoryTypeInformationGuid,
             EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
             BackupMemoryTypeInformationSize,
             BackupMemoryTypeInformation);

      SafeFreePool (BackupMemoryTypeInformation);
    }

    //
    // The GUID used for the variable is the same GUID that is used for the HOB
    // and for the configuration table.
    //

    gRT->SetVariable (
           EFI_MEMORY_TYPE_INFORMATION_VARIABLE_NAME,
           &gEfiMemoryTypeInformationGuid,
           EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
           VariableSize,
           PreviousMemoryTypeInformation);
  }

#if OPTION_SYSTEM_BOOT_MANAGER_MEMORY_REGION_PAD_RESET
  if (UpdateRequired) {
    SCT_MILESTONE_TASK_RESET_SYSTEM_FLAG ResetSystemFlag;
    //
    // Memory utilization changed, force a system reset to make memory map
    // reporting in consistency.
    //
    SCT_MILESTONE_TASK (
      MILESTONE_TASK_RESET_SYSTEM_FLAG,
      ResetSystemFlagMilestoneTask,
      &ResetSystemFlag,
      sizeof (ResetSystemFlag));

    if (ResetSystemFlag.ResetSystemFlag) {
      SctSetResetFlagFirstBoot();

    }
  }
#endif

} // SaveMemoryMap


//
// FUNCTION NAME.
//      IsBmDevicePathValid - Check if the DevicePath is correct?
//
// FUNCTIONAL DESCRIPTION.
//      This function will check the DevicePaths correct or not.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - TRUE, if correct. Otherwise, not correct.
//

BOOLEAN
EFIAPI
IsBmDevicePathValid (
  IN CONST EFI_DEVICE_PATH_PROTOCOL *DevicePath,
  IN UINTN MaxSize
  )
{

  if ((DevicePathType (DevicePath) != HARDWARE_DEVICE_PATH) && (DevicePathType (DevicePath) != ACPI_DEVICE_PATH) &&
       (DevicePathType (DevicePath) != MESSAGING_DEVICE_PATH) && (DevicePathType (DevicePath) != MEDIA_DEVICE_PATH) &&
       (DevicePathType (DevicePath) != BBS_DEVICE_PATH) && (DevicePathType (DevicePath) != END_DEVICE_PATH_TYPE)) {
    DPRINTF_BM_MISC ("Is not DevicePath, Type= 0x%x.\n", DevicePathType (DevicePath));
    return FALSE;
  }

  return IsDevicePathValid (DevicePath, MaxSize);
}


//
// FUNCTION NAME.
//      MsTaskLaunchFileGuidDriver - Default Milestone task for:
//      BDS_MILESTONE_TASK_LAUNCH_FILE_GUID_DRIVER
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone of
//      LaunchFileGuidDriver ().
//
// ENTRY PARAMETERS.
//      MilestoneData     - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
//
SCT_STATUS
MsTaskLaunchFileGuidDriver (
  IN VOID   *MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_STATUS Status;
  SCT_BDS_LAUNCH_FILE_GUID_DRIVER_DATA *MSDataFileGuidDriver = MilestoneData;
  CHAR16 *FileGuid= MSDataFileGuidDriver->FvFileGuid;

  Status = LaunchFileGuidDriver (FileGuid);
  MSDataFileGuidDriver->ReturnStatus = Status;
  return Status;
}


//
// FUNCTION NAME.
//      LaunchBuiltInApplication - Launch a built-in application by MILESTONE_TASK.
//
// FUNCTIONAL DESCRIPTION.
//      This function will launch a built-in Driver(Application) which is within fV.
//
// ENTRY PARAMETERS.
//      FilePath        - The string for FV file path.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
LaunchBuiltInApplication (IN CHAR16 *FileGuid)
{
  EFI_STATUS Status;
  SCT_BDS_LAUNCH_FILE_GUID_DRIVER_DATA MilestoneData;
  UINT32 MilestoneDataSize = sizeof (MilestoneData);

  MilestoneData.FvFileGuid = FileGuid;
  MilestoneData.ReturnStatus = EFI_SUCCESS;

  Status = SCT_MILESTONE_TASK (
             BDS_MILESTONE_TASK_LAUNCH_FILE_GUID_DRIVER,
             MsTaskLaunchFileGuidDriver,
             &MilestoneData,
             MilestoneDataSize);
  DPRINTF_LO ("BDS_MILESTONE_TASK_LAUNCH_FILE_GUID_DRIVER Ret_Status = [%r]\n", MilestoneData.ReturnStatus);
  Status = MilestoneData.ReturnStatus;
  return Status;
} // LaunchBuiltInApplication


