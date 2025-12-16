//
// FILENAME.
//      BootManager.c - SecureCore Technology(TM) System Boot Manager Object.
//
// FUNCTIONAL DESCRIPTION.
//      This module implements the Boot Manager object, which represents an
//      open instance of the EFI_BDS_ARCH_PROTOCOL protocol.
//
// NOTICE.
//      Copyright (C) 2013-2025 Phoenix Technologies Inc.  All Rights Reserved.
//

//
// Include standard header files.
//

#include "Meta.h"

//
// Private data types used by this module are defined here and any
// static items are declared here.
//

static CHAR16 mFirmwareVendor [] = PROJECT_FIRMWARE_VENDOR;

static CHAR8 mPlatformLangCodes [] = {
  SCT_BM_PLATFORM_LANG_CODES
};

static UINTN mPlatformLangCodesSize = sizeof (mPlatformLangCodes);

static CHAR8 mPlatformLang [] = {
  SCT_BM_PLATFORM_LANG
};

static UINTN mPlatformLangSize = sizeof (mPlatformLang);

EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *mTextInEx = NULL;

static BOOT_MANAGER_CONNECTION_DEVICE QuickConnectList [] = {
  CONFIG_BmQuickConnectList
};

static BOOT_MANAGER_CONNECTION_POLICY mConnectionPolicy [] = {
  {BOOT_WITH_MINIMAL_CONFIGURATION, QuickConnectList},
  {BOOT_ASSUMING_NO_CONFIGURATION_CHANGES, QuickConnectList},
  {BOOT_ON_S4_RESUME, QuickConnectList}
};

static BOOT_MANAGER_CONNECTION_DEVICE SecurityConnectList [] = {
  CONFIG_BmSecurityConnectList
};

static BOOT_MANAGER_CONNECTION_DEVICE mPreemptiveConnectList [] = {
  CONFIG_BmPreemptiveConnectList
};

static BOOT_MANAGER_CONNECTION_DEVICE mEssentialConnectList [] = {
  CONFIG_BmEssentialConnectList
};

static BOOT_MANAGER_CONNECTION_DEVICE mTouchDeviceConnectList [] = {
  CONFIG_BmTouchDevices
};

#if OPTION_SUPPORT_TCG
static BOOT_MANAGER_CONNECTION_DEVICE mMORDeviceResetConnectList [] = {
  CONFIG_BmMORDeviceResetConnectList
};
#endif //if OPTION_SUPPORT_TCG

#if OPTION_SYSTEM_BOOT_MANAGER_REDUCE_MEMORY_USAGE
static UINT32 mMemoryMapMinimumSize [] = {CONFIG_SYSTEM_MEMORY_MINIMUM_SIZE};
#endif

static BOOLEAN mEnableProgress = FALSE;
static UINT64 mProgress = 0;
static BOOT_MANAGER_PHASE_TABLE_ENTRY mPhaseTable [] = {
    {                                   // Video available.
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_VIDEO_START,
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_VIDEO_END
    },
    {                                   // Each time a connection is made.
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_CONNECTION_START,
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_CONNECTION_END
    },
    {                                   // Each time the memory test pauses for input.
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_MEMORY_START,
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_MEMORY_END
    },
    {                                   // Time intervals during a wait for keypress.
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_KEYPRESS_START,
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_KEYPRESS_END
    },
    {                                   // When checking for recovery.
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_RECOVERY_START,
      CONFIG_SYSTEM_BOOT_MANAGER_PHASE_RECOVERY_END
    }
  };

static SCT_STATUS InitializeSecurity (VOID);

#if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT
static EFI_DEVICE_PATH_PROTOCOL *OpromDevicePaths = NULL;
#endif // #if OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

static BOOLEAN mConsoleInInitialized = FALSE;

static EFI_GUID mCsmModuleFvFile [] = {
  CONFIG_CSM_MODULE_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mOnDemandFvFile [] = {
  CONFIG_ON_DEMAND_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mSeamLessBootFvFile [] = {
  CONFIG_SEAMLESS_BOOT_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mNetworkEssentialFvFile [] = {
  CONFIG_NETWORK_ESSENTIAL_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mNetworkIpV4FvFile [] = {
  CONFIG_NETWORK_IPV4_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mNetworkIpV6FvFile [] = {
#ifdef CONFIG_NETWORK_IPV6_FV_FILE_GUID_LIST
  CONFIG_NETWORK_IPV6_FV_FILE_GUID_LIST,
#else // #ifdef CONFIG_NETWORK_IPV6_FV_FILE_GUID_LIST
  {0x5BEDB5CC, 0xD830, 0x4eb2, {0x87, 0x42, 0x2D, 0x4C, 0xC9, 0xB5, 0x4F, 0x2C}}, // IPv6 Module.
  {0x99F03B99, 0x98D8, 0x49dd, {0xA8, 0xD3, 0x32, 0x19, 0xd0, 0xff, 0xe4, 0x1e}}, // MTFTP6 Module.
  {0x95E3669D, 0x34BE, 0x4775, {0xA6, 0x51, 0x7e, 0xa4, 0x1b, 0x69, 0xd8, 0x9e}}, // DHCP6 Module.
  {0xD912C7BC, 0xF098, 0x4367, {0x92, 0xba, 0xe9, 0x11, 0x08, 0x3c, 0x7b, 0x0e}}, // UDP6 Module.
#if !OPTION_SYSTEM_BOOT_MANAGER_BOP_HTTP
  {0x1A7E4468, 0x2F55, 0x4a56, {0x90, 0x3c, 0x01, 0x26, 0x5e, 0xb7, 0x62, 0x2b}}, // TCP Module for Ipv4 and Ipv6.
#endif // !OPTION_SYSTEM_BOOT_MANAGER_BOP_HTTP
#endif // #ifdef CONFIG_NETWORK_IPV6_FV_FILE_GUID_LIST
  ZERO_GUID
};

static EFI_GUID mScsiModuleFvFile [] = {
  CONFIG_SCSI_MODULE_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mTerminalDriverFileName [] = {
  CONFIG_TERMINAL_DRIVER_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mTextViewFvFile [] = {
  CONFIG_TEXT_VIEW_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mGraphicViewFvFile [] = {
  CONFIG_GRAPHIC_VIEW_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_GUID mGuiViewFvFile [] = {
  CONFIG_GUI_VIEW_FV_FILE_GUID_LIST,
  ZERO_GUID
};

static EFI_TEXT_CLEAR_SCREEN mOriginalClearScreenFun = NULL;
static BOOLEAN mShowSplashScreen = TRUE;
static BOOLEAN gPPRequireUIConfirm = FALSE;

//
// Prototypes for functions in other modules that are a part of this component.
//

//
// Data shared with other modules *within* this component.
//
BOOLEAN mIsBootOptionDamaged = FALSE;
BOOLEAN mIsBootFailConnectUSB = FALSE;
BOOLEAN mBmEndOfDxeEventSignaled = FALSE;

EFI_HANDLE mImageHandle = (VOID *) NULL;
EFI_HANDLE mFvHandle = (VOID *) NULL;
UINT16 mTimeoutValue = 0;

GLOBAL_REMOVE_IF_UNREFERENCED  BOOLEAN mS3Saved = FALSE;
BOOLEAN mDxeSmmReadyToLockProtocol = FALSE;

BOOLEAN mCsmSupported = TRUE;           // CSM module supported during P.O.S.T.
BOOLEAN mCapsuleEspDelivery = FALSE;
EFI_EVENT mBootManagerWaitEvent = NULL;
SCT_ERROR_SCREEN_TEXT_PROTOCOL *ErrorInfoScreen = NULL;

//
// This Boot Manager treats the Boot Mode strictly as an enumerated value.
// Therefore all mask-type values will be ignored.
// Here are the values recognized.
//
// BOOT_WITH_FULL_CONFIGURATION                  0x00
// BOOT_WITH_MINIMAL_CONFIGURATION               0x01
// BOOT_ASSUMING_NO_CONFIGURATION_CHANGES        0x02
// BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS 0x03
// BOOT_WITH_DEFAULT_SETTINGS                    0x04
// BOOT_ON_S4_RESUME                             0x05
// BOOT_ON_S5_RESUME                             0x06
// BOOT_ON_S2_RESUME                             0x10
// BOOT_ON_S3_RESUME                             0x11
// BOOT_ON_FLASH_UPDATE                          0x12
// BOOT_IN_RECOVERY_MODE                         0x20
//
// Due to the existence of the masked modes the boot manager will truncate the
// values by AND-ing the Boot Mode with 0x3F. This will discard all masks.
//
// BOOT_IN_RECOVERY_MODE_MASK                    0x40
// BOOT_SPECIAL_MASK                             0x80
//

#define BOOT_MODE_MASK 0x3F

EFI_BOOT_MODE mBootMode = 0;
BOOLEAN LegacyDevicesConnected = FALSE;

UINT8 *mSetupMenuEntryContext = NULL;
UINT8 *mSetupMenuExitContext = NULL;
UINT8 *mBootMenuEntryContext = NULL;
UINT8 *mBootMenuExitContext = NULL;
extern BOOLEAN IsInSetupOrBootMenu;

//
// Data defined in other modules and used by this module.
//


//
// Private functions implemented by this component.  Note these functions
// do not take the API prefix implemented by the module, or they might be
// confused with the API itself.
//

SCT_STATUS
EFIAPI
ProcessDriverOrderVariable (VOID);

SCT_STATUS
EFIAPI
ProcessSysPrepOrderVariable (VOID);

SCT_STATUS
EndDisplaySplashScreen (VOID);

SCT_STATUS
EFIAPI
UpdateSystemTable (VOID);

SCT_STATUS
EFIAPI
ConnectControllersPerPolicy (VOID);

SCT_STATUS
EFIAPI
RunDiagnostics (VOID);

SCT_STATUS
EFIAPI
ProcessBootNextVariable (VOID);

SCT_STATUS
EFIAPI
ProcessBootList (VOID);

SCT_STATUS
EFIAPI
LaunchBootMenuApplication (VOID);

//SCT_STATUS
//UpdateCheckHotkey (VOID);

SCT_STATUS
CheckRecoveryBoot (VOID);

static
SCT_STATUS
ConfigUefiNetworkStackDriver (VOID);

EFI_STATUS
EFIAPI
BmClearScreen (IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Sto);

EFI_STATUS
LoadSetupModules (VOID);

VOID
RegisterEventNotifications (VOID);

//
// Public API functions implemented by this component.
//

//
// FUNCTION NAME.
//      InitializeBootManager - Initialize Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      This routine is called during driver initialization to perform
//      any initialization associated with the Boot Manager module.
//
//      In the current implementation this function performs no work.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
InitializeBootManager (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImageInterface;
  SCT_STATUS Status;

  UINTN VariableSize;
  PUINT16 VariableValue;

  UINT32 BootOptionSupportValue;

  DPRINTF_INIT ("InitializeBootManager:\n");

  //
  // Save the Boot Manager's Image Handle.
  //

  mImageHandle = ImageHandle;
  DPRINTF_INIT ("  mImageHandle = 0x%x.\n", mImageHandle);

  //
  // Save the Handle of the Device from which the Boot Manager was loaded.
  // This is the handle of the device that has our FV.
  //

  gBS->OpenProtocol (
        ImageHandle,
        &gEfiLoadedImageProtocolGuid,
        (VOID **) &LoadedImageInterface,
        NULL,
        NULL,
        EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  DUMP_IMAGE_INFO (LoadedImageInterface);

  mFvHandle = LoadedImageInterface->DeviceHandle;
  DPRINTF_INIT ("  mFvHandle = 0x%x.\n", mFvHandle);

  //
  // Check for global variables that are defined in the UEFI Specification,
  // Chapter 3. Initialize those that do not yet exist, per the settings from
  // the project.
  //

  Status = SctLibGetEfiGlobalVariable (
             EFI_TIME_OUT_VARIABLE_NAME,
             NULL,
             &VariableSize,
             (VOID **) &VariableValue);

  if ((EFI_ERROR (Status)) || (VariableSize != sizeof (UINT16))) {
    DPRINTF_INIT ("  Initializing Timeout.\n");
    mTimeoutValue = CONFIG_SYSTEM_BOOT_MANAGER_KEYPRESS_WAIT_TIME;
    SetEfiGlobalVariable (
      EFI_TIME_OUT_VARIABLE_NAME,
      EFI_VARIABLE_NON_VOLATILE|
      EFI_VARIABLE_BOOTSERVICE_ACCESS|
      EFI_VARIABLE_RUNTIME_ACCESS,
      sizeof (UINT16),
      &mTimeoutValue);
  } else {
    mTimeoutValue = *VariableValue;
    SafeFreePool (VariableValue);
  }
  DPRINTF_INIT ("  mTimeoutValue = 0x%x.\n", mTimeoutValue);

  //
  // The the BootOptionSupport variable to indicate to the OS the level of
  // support this Boot Manager provides.
  // The Boot Manager owns this variable. We will make certain that it does
  // not exist with wrong attributes (like non-volatile) by deleting it first.
  // This should be a no-op, since it should not exist.
  //
  BootOptionSupportValue = SCT_BM_BOOT_OPTION_SUPPORT;
  SetEfiGlobalVariable (
    EFI_BOOT_OPTION_SUPPORT_VARIABLE_NAME,
    EFI_VARIABLE_BOOTSERVICE_ACCESS|
    EFI_VARIABLE_RUNTIME_ACCESS,
    sizeof (UINT32),
    &BootOptionSupportValue);

  //
  // Initialize the Boot Manager's private copy of the Boot Mode.
  //

  mBootMode = GetBootModeHob ();
  mBootMode &= BOOT_MODE_MASK;

  //
  // NEWREL: cc 10/05/27, the 2 variables could be initialized as soon as
  // possible? I cannot read them at the first time power on after flashing BIOS.
  //

  Status = SctLibGetEfiGlobalVariable (
             EFI_PLATFORM_LANG_CODES_VARIABLE_NAME,
             NULL,
             &VariableSize,
             (VOID **) &VariableValue);

  if (EFI_ERROR (Status)) {
    DPRINTF_INIT (
      "  Initializing PlatformLangCodes, 0x%x bytes, %a.\n",
      mPlatformLangCodesSize,
      mPlatformLangCodes);
    SetEfiGlobalVariable (
      EFI_PLATFORM_LANG_CODES_VARIABLE_NAME,
      EFI_VARIABLE_BOOTSERVICE_ACCESS|
      EFI_VARIABLE_RUNTIME_ACCESS,
      mPlatformLangCodesSize,
      mPlatformLangCodes);
  } else {
    DPRINTF_INIT (
      "  Found PlatformLangCodes, 0x%x bytes, %a.\n",
      VariableSize,
      VariableValue);
  }

  Status = SctLibGetEfiGlobalVariable (
             EFI_PLATFORM_LANG_VARIABLE_NAME,
             NULL,
             &VariableSize,
             (VOID **) &VariableValue);

  if (EFI_ERROR (Status)) {
    DPRINTF_INIT (
      "  Initializing PlatformLang, 0x%x bytes, %a.\n",
      mPlatformLangSize,
      mPlatformLang);
    SetEfiGlobalVariable (
      EFI_PLATFORM_LANG_VARIABLE_NAME,
      EFI_VARIABLE_NON_VOLATILE|
      EFI_VARIABLE_BOOTSERVICE_ACCESS|
      EFI_VARIABLE_RUNTIME_ACCESS,
      mPlatformLangSize,
      mPlatformLang);
  } else {
    DPRINTF_INIT (
      "  Found PlatformLang, 0x%x bytes, %a.\n",
      VariableSize,
      VariableValue);
  }

  EfiNamedEventListen (
    &gEfiHiiPlatformSetupFormsetGuid,
    TPL_CALLBACK,
    BmRegisterContextMenu,
    NULL,
    NULL);

  return SCT_STATUS_SUCCESS;
} // InitializeBootManager

//
// FUNCTION NAME.
//      MsTaskNotifyPasswordUnlockError - Check if there are Password Unlock Error or not.
//
// FUNCTIONAL DESCRIPTION.
//      Show an message for the form browser.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Codes.
//

SCT_STATUS
MsTaskNotifyPasswordUnlockError (
   IN VOID* MilestoneData,
   IN UINT32 MilestoneDataSize
  )
{
#if OPTION_PASSWORD_UNLOCK_ERROR_WARNING_DIALOG_SUPPORT
  EFI_STATUS Status;
  UINTN DataSize;
  CHAR16 String1[55];
  CHAR16 String2[40];
  CHAR16 String3[30];
  EFI_STRING Buffer[3];
  SCT_MSGBOX_BUTTON_ID ClickedBtn;
  UINT32 Attributes = 0;
  SCT_PWD_UNLOCK_ERROR_INFO SctPwdUnlockErrorInfo;
  SCT_TEXT_SETUP_BROWSER2_PROTOCOL *mTSB = NULL;

  DPRINTF_INFO ("Entry.\n");

  DataSize = sizeof (SctPwdUnlockErrorInfo);

  Status = gRT->GetVariable (
                  SCT_PWD_UNLOCK_ERROR_VARIABLE,
                  &gSctPwdUnlockErrVariableStoreGuid,
                  &Attributes,
                  &DataSize,
                  &SctPwdUnlockErrorInfo);

  if (!EFI_ERROR (Status) && SctPwdUnlockErrorInfo.WarningDialog != 0) {

    //
    // Locate gTextSetupBrowser2ProtocolGuid for showing warning dialog.
    //

    Status = gBS->LocateProtocol (&gTextSetupBrowser2ProtocolGuid, NULL, (VOID **) &mTSB);
    if (EFI_ERROR (Status)) {
      DPRINTF_ERROR ("Can't locate gTextSetupBrowser2ProtocolGuid. Status (%r)\n", Status);
      return Status;
    }

    //
    // Show warning dialog if Password Unlock Error exist.
    //

    if (SctPwdUnlockErrorInfo.Count > 0) {
      UnicodeSPrint (String1, sizeof (String1), L"Found password unlock error log in Error Manager.");
      Buffer [0] = String1;

      UnicodeSPrint (String2, sizeof (String2), L"Password unlock error log count : %d", SctPwdUnlockErrorInfo.Count);
      Buffer [1] = String2;

      UnicodeSPrint (String3, sizeof (String3), L"Press YES to clear the log.");
      Buffer [2] = String3;

      ClickedBtn = mTSB->ShowDialogEx (
                           L"Warning!!!",
                           SCT_MSGBOX_TYPE_WARN,
                           3,
                           Buffer,
                           SCT_MSGBOX_BUTTON_ID_YES,
                           SCT_MSGBOX_BUTTON_ID_YESNO);

      if (ClickedBtn == SCT_MSGBOX_BUTTON_ID_YES) {
        ZeroMem (String1, sizeof (String1));
        UnicodeSPrint (String1, sizeof (String1), L"Are you Sure to clear the Password Unlock Error Log?");
        Buffer [0] = String1;

        ClickedBtn = mTSB->ShowDialogEx (
                             L"Warning!!!",
                             SCT_MSGBOX_TYPE_WARN,
                             1,
                             Buffer,
                             SCT_MSGBOX_BUTTON_ID_YES,
                             SCT_MSGBOX_BUTTON_ID_YESNO);

        if (ClickedBtn == SCT_MSGBOX_BUTTON_ID_YES) {
          //
          // Clear Password Unlock Error Log.
          //

          SctPwdUnlockErrorInfo.Count = 0;
          Status = gRT->SetVariable (
                          SCT_PWD_UNLOCK_ERROR_VARIABLE,
                          &gSctPwdUnlockErrVariableStoreGuid,
                          Attributes,
                          DataSize,
                          &SctPwdUnlockErrorInfo);
        }
      }
    }
  }

  DPRINTF_INFO ("Exit.\n");
  return Status;

#else  // OPTION_PASSWORD_UNLOCK_ERROR_WARNING_DIALOG_SUPPORT
  return EFI_UNSUPPORTED;
#endif // OPTION_PASSWORD_UNLOCK_ERROR_WARNING_DIALOG_SUPPORT
}


//
// FUNCTION NAME.
//      BdsEntry - Transfer control from the DXE Foundation to the boot device.
//
// FUNCTIONAL DESCRIPTION.
//      Performs Boot Device Selection (BDS) and transfers control from the DXE
//      Foundation to the selected boot device.
//
//      The implementation of the boot policy must follow the rules outlined in
//      the Boot Manager chapter of the UEFI specification.
//
//      This function uses policy data from the platform to determine what
//      operating system or system utility should be loaded and invoked.
//
//      This function call also optionally uses the user's input to determine
//      the operating system or system utility to be loaded and invoked.
//
//      When the DXE Foundation has dispatched all the drivers on the dispatch
//      queue, this function is called.
//
//      This function will attempt to connect the boot devices required to load
//      and invoke the selected operating system or system utility. During this
//      process, additional firmware volumes may be discovered that may contain
//      addition DXE drivers that can be dispatched by the DXE Foundation.
//      If a boot device cannot be fully connected, this function calls the DXE
//      Service Dispatch() to allow the DXE drivers from any newly discovered
//      firmware volumes to be dispatched. Then the boot device connection can
//      be attempted again. If the same boot device connection operation fails
//      twice in a row that boot device has failed, and should be skipped.
//
// ENTRY PARAMETERS.
//      This            - pointer to the caller's instance of the protocol.
//
// EXIT PARAMETERS.
//      None            - this function cannot return.
//

VOID
EFIAPI
BdsEntry (IN EFI_BDS_ARCH_PROTOCOL *This)
{
  EFI_STATUS Status;

  //
  // Process with the Entry () milestone task.
  //

  PERF_END (0, DXE_TOK, NULL, 0);
  PERF_START (0, BDS_TOK, NULL, 0);

  DPRINTF_FUNCTION_ENTRY();

  Status = gBS->CreateEvent (
                  EVT_TIMER,
                  TPL_NOTIFY,
                  NULL,
                  NULL,
                  &mBootManagerWaitEvent);
  if (!EFI_ERROR (Status)) {

    Status = gBS->SetTimer (
                    mBootManagerWaitEvent,
                    TimerRelative,
                    TIMER_PERIOD_SECONDS (CONFIG_SYSTEM_BOOT_MANAGER_WAITING_TIME));
    if (EFI_ERROR (Status)) {
      mBootManagerWaitEvent = NULL;
    }
  }

  BDS_LOCK_SMRAM
  PERF_START (0, "MsTaskBdsEntry", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_ENTRY, MsTaskBdsEntry, NULL, 0);
  PERF_END (0, "MsTaskBdsEntry", "BootManager", 0);

} // BdsEntry

//
// Private (static) routines used by this component.
//

//
// FUNCTION NAME.
//      ProcessDriverOrderVariable - Install the drivers in the DriverOrder Variable.
//
// FUNCTIONAL DESCRIPTION.
//      The UEFI specification defines a list of Driver Load Options
//      that are to be installed in the BDS phase prior to processing
//      the Boot Load Options. This function performs this task.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ProcessDriverOrderVariable (VOID)
{
  UINTN i;
  SCT_STATUS Status;
  PUINT16 OptionOrder;
  UINTN OptionOrderSize;
  PLOAD_OPTION_OBJECT Option;
  BOOLEAN ReconnectAll;

  DPRINTF_BM ("ProcessDriverOrderVariable\n");

  //
  // Get the variable.
  //

  DPRINTF_BM ("  Calling SctLibGetEfiGlobalVariable.\n");
  Status = SctLibGetEfiGlobalVariable (
             EFI_DRIVER_ORDER_VARIABLE_NAME,
             NULL,                      // don't care about attributes.
             &OptionOrderSize,
             (VOID **) &OptionOrder);
  DPRINTF_BM ("  SctLibGetEfiGlobalVariable returned %r.\n", Status);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  //
  // The variable was found, so now we need to launch each active option.
  //

  ReconnectAll = FALSE;
  for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {
    Status = GetDriverOption (OptionOrder [i], &Option);
    if (EFI_ERROR(Status)) {
      DPRINTF_BM ("  GetOption Option [0x%x] = 0x%x, returned %r.\n",
        i, OptionOrder [i], Status);
      continue;
    }
    if (Option->Attributes & LOAD_OPTION_ACTIVE) {
      Status = LaunchDriverOption (Option->OptionNumber, Option->RawCrc);
      DPRINTF_BM ("  LaunchDriverOption Option [0x%x] = 0x%x, returned %r.\n",
        i, OptionOrder [i], Status);

      //
      // If a driver load option is marked as LOAD_OPTION_FORCE_RECONNECT,
      // then all of the EFI drivers in the system will be disconnected and
      // reconnected after the last driver load option is processed.
      //

      if (!EFI_ERROR (Status) && (Option->Attributes & LOAD_OPTION_FORCE_RECONNECT) != 0) {
        ReconnectAll = TRUE;
      }

    } else {
      DPRINTF_BM ("  Option [0x%x] = 0x%x, is not active.\n",
        i, OptionOrder [i]);
    }
  }

  if (ReconnectAll) {
    BmDisconnectAll ();
    BmConnectAll ();
  }

  //
  // Return with success.
  //

  DPRINTF_BM ("ProcessDriverOrderVariable End\n");
  return SCT_STATUS_SUCCESS;
} // ProcessDriverOrderVariable

//
// FUNCTION NAME.
//      ProcessSysPrepOrderVariable - Install the SysPreps in the SysPrepOrder Variable.
//
// FUNCTIONAL DESCRIPTION.
//      The UEFI specification defines a list of SysPrep Load Options
//      that are to be installed in the BDS phase prior to processing
//      the Boot Load Options. This function performs this task.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ProcessSysPrepOrderVariable (VOID)
{
  UINTN i;
  SCT_STATUS Status;
  PUINT16 OptionOrder;
  UINTN OptionOrderSize;
  PLOAD_OPTION_OBJECT Option;
  BOOLEAN ReconnectAll;         SUPPRESS_WARNING_IF_UNUSED (ReconnectAll);

  DPRINTF_BM ("ProcessSysPrepOrderVariable\n");

  //
  // Get the variable.
  //

  DPRINTF_BM ("  Calling SctLibGetEfiGlobalVariable.\n");
  Status = SctLibGetEfiGlobalVariable (
             EFI_SYS_PREP_ORDER_VARIABLE_NAME,
             NULL,                      // don't care about attributes.
             &OptionOrderSize,
             (VOID **) &OptionOrder);
  DPRINTF_BM ("  SctLibGetEfiGlobalVariable returned %r.\n", Status);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  //
  // The variable was found, so now we need to launch each active option.
  //

  ReconnectAll = FALSE;
  for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {
    Status = GetSysPrepOption (OptionOrder [i], &Option);
    if (EFI_ERROR(Status)) {
      DPRINTF_BM ("  GetOption Option [0x%x] = 0x%x, returned %r.\n",
        i, OptionOrder [i], Status);
      continue;
    }
    if (Option->Attributes & LOAD_OPTION_ACTIVE) {
      Status = LaunchSysPrepOption (Option->OptionNumber, Option->RawCrc);
      DPRINTF_BM ("  LaunchSysPrepOption Option [0x%x] = 0x%x, returned %r.\n",
        i, OptionOrder [i], Status);

    } else {
      DPRINTF_BM ("  Option [0x%x] = 0x%x, is not active.\n",
        i, OptionOrder [i]);
    }
  }

  //
  // Return with success.
  //

  DPRINTF_BM ("ProcessSysPrepOrderVariable End\n");
  return SCT_STATUS_SUCCESS;
} // ProcessSysPrepOrderVariable

//
// FUNCTION NAME.
//      UpdateSystemTable - Update the system table.
//
// FUNCTIONAL DESCRIPTION.
//      Any fields that are out of date or incomplete must be updated
//      at this time, such that the system table is ready for the OS
//      Boot Loader.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
UpdateSystemTable (VOID)
{
  DPRINTF_INIT ("UpdateSystemTable\n");

  //
  // Set firmware vendor.
  //

  gST->FirmwareVendor  = AllocateRuntimeCopyPool (
                           sizeof (mFirmwareVendor),
                           &mFirmwareVendor);
  if (gST->FirmwareVendor == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  DPRINTF_INIT ("  FirmwareVendor = %s\n", gST->FirmwareVendor);

  //
  // Set the firmware revision.
  //

  gST->FirmwareRevision = PROJECT_FIRMWARE_REVISION;
  DPRINTF_INIT ("  FirmwareRevision = 0x%x\n", gST->FirmwareRevision);

  //
  // Recalculate the 32-bit CRC value of the EFI System Table,
  // DXE Services Table, Boot Services Table.
  //

  //
  // Initialize the 32-bit CRC value to zero. Because the CRC32 field is the
  // part of the EFI System Table, the filed should be initialize to zero before
  // calculating the CRC value, otherwise the value is always changed after
  // calculating CRC.
  //

  gBS->Hdr.CRC32 = 0;                   // CRC32 of EFI_BOOT_SERVICES = 0.
  gBS->CalculateCrc32 (
        (PVOID)gBS,                     // IN Data. EFI_BOOT_SERVICES will be computed.
        sizeof (EFI_BOOT_SERVICES),     // IN DataSize. Size of the EFI_BOOT_SERVICES.
        &gBS->Hdr.CRC32);               // OUT Crc32. Return the CRC of EFI_BOOT_SERVICES.

  gDS->Hdr.CRC32 = 0;                   // CRC32 of EFI_DXE_SERVICES = 0.
  gBS->CalculateCrc32 (
        (PVOID)gDS,                     // IN Data. EFI_DXE_SERVICES will be computed.
        sizeof (EFI_DXE_SERVICES),      // IN DataSize. Size of the EFI_DXE_SERVICES.
        &gDS->Hdr.CRC32);               // OUT Crc32. Return the CRC of EFI_DXE_SERVICES.

  gRT->Hdr.CRC32 = 0;                   // CRC32 of EFI_RUNTIME_SERVICES = 0.
  gBS->CalculateCrc32 (
        (PVOID)gRT,                     // IN Data. EFI_RUNTIME_SERVICES will be computed.
        sizeof (EFI_RUNTIME_SERVICES),  // IN DataSize. Size of the EFI_RUNTIME_SERVICES.
        &gRT->Hdr.CRC32);               // OUT Crc32. Return the CRC of EFI_RUNTIME_SERVICES.

  gST->Hdr.CRC32 = 0;                   // CRC32 of EFI_SYSTEM_TABLE = 0.
  gBS->CalculateCrc32 (
        (PVOID)gST,                     // IN Data. EFI_SYSTEM_TABLE will be computed.
        sizeof (EFI_SYSTEM_TABLE),      // IN DataSize. Size of the EFI_SYSTEM_TABLE.
        &gST->Hdr.CRC32);               // OUT Crc32. Return the CRC of EFI_SYSTEM_TABLE.
  DPRINTF_INIT ("  Crc32 = 0x%x\n", gST->Hdr.CRC32);

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // UpdateSystemTable

//
// FUNCTION NAME.
//      UpdateProgress - Update all progress indicators.
//
// FUNCTIONAL DESCRIPTION.
//      This function updates all the progress indicators.
//
//      This function manages the overall progress through the BDS phase.
//      The progress is divided into sections. These sections are used to
//      calculate the overall percentage complete (expressed as a ratio).
//
//      This function locates all instances of SctProgressIndicator protocol
//      and calls the update function for each instance, passing in the
//      completion ratio.
//
//      If the total for a phase is not known this function will advance the
//      ratio by Completed units, with a max of the end of the phase.
//
//      This function uses the mProgress variable to store the total master
//      progress. This allows us to prevent moving the progress bar backwards.
//
// ENTRY PARAMETERS.
//      Phase           - UINTN value indicating sub-phase of the BDS phase.
//      Completed       - UINTN Value indicating the numerator if the ratio
//                        that is the progress percent complete.
//      Total           - UINTN Value indicating the denominator in the ratio
//                        that is the progress percent complete. If this value
//                        is zero then the total is not known.
//      String          - Pointer to a Unicode string to display in the
//                        progress indicator, if the progress indicator
//                        supports progress strings.
//
// EXIT PARAMETERS.
//      Function Return - SCT status code.
//

SCT_STATUS
UpdateProgress (
  IN UINT64 Phase,
  IN UINT64 Completed,
  IN UINT64 Total OPTIONAL,
  IN PCHAR16 String OPTIONAL)
{
  SCT_BDS_MILESTONE_PROGRESS_DATA MilestoneProgressData;

  MilestoneProgressData.Phase = Phase;
  MilestoneProgressData.Complete = Completed;
  MilestoneProgressData.Total = Total;
  MilestoneProgressData.Indicator = String;

  return SCT_MILESTONE_TASK (
           BDS_MILESTONE_TASK_PROGRESS,
           MsTaskUpdateProgress,
           &MilestoneProgressData,
           sizeof (MilestoneProgressData));
} // UpdateProgress


//
// FUNCTION NAME.
//      ConnectControllersPerPolicy - Call connect per the policy of the system.
//
// FUNCTIONAL DESCRIPTION.
//      This function walks through the mConnectionPolicy array to find an
//      entry whose Boot Mode matches the current Boot Mode.
//
//      Once a match is found the ConnectDevices function is called, passing
//      the ConnectionList to the function call.
//
//      If there was no match found this function will call ConnectAllHandles.
//
//      If either of these functions returns an error this function will
//      return that Status immediately.
//
//      Some drivers are dependent on certain connections taking place but are
//      not themselves UEFI-driver-model drivers. Instead they have dependency
//      expressions and one or more of the protocols on which they are dependant
//      is produced by a UEFI-driver-model driver. This is bad design, as these
//      drivers should instead be written to receive notification when their
//      dependency is met or (better yet) they should be rewritten to be
//      UEFI-driver-model drivers.
//
//      This function includes a call to gDS->Dispatch () as a work around to
//      support drivers that use dependency expressions that may have been
//      satisfied by previous connects.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ConnectControllersPerPolicy (VOID)
{
  SCT_BDS_MILESTONE_CONNECT_DATA MilestoneConnectData;
  UINT32 ConnectDataSize;

  DPRINTF_BM ("ConnectControllersPerPolicy:\n");

  UpdateProgress (BOOT_MANAGER_PHASE_CONNECTION, 0, 1, NULL);
  MilestoneConnectData.BootMode = mBootMode;
  MilestoneConnectData.ConnectAll = FALSE;
  ConnectDataSize = sizeof (MilestoneConnectData);

  //
  // Call the Connect Device milestone.
  //

  PERF_START (0, "ConnectDevices", "BootManager", 0);
  SCT_MILESTONE_TASK (
    BDS_MILESTONE_TASK_CONNECT_DEVICES,
    MsTaskConnectDevices,
    &MilestoneConnectData,
    ConnectDataSize);
  PERF_END (0, "ConnectDevices", "BootManager", 0);

  UpdateProgress (BOOT_MANAGER_PHASE_CONNECTION, 1, 1, NULL);

  return SCT_STATUS_SUCCESS;
} // ConnectControllersPerPolicy


//
// FUNCTION NAME.
//      PauseForInput - Check hotkeys and display test progress.
//
// FUNCTIONAL DESCRIPTION.
//      This function displays the progress of a test and checks the hotkeys.
//
//      The parameters are a ratio of done to total. The units have no meaning
//      to this function and could be displayed in several ways, most commonly
//      they are displayed as a progress bar.
//
// ENTRY PARAMETERS.
//      Tested          - a value represented the amount tested so far.
//      Total           - a value representing the total amount to test.
//
// EXIT PARAMETERS.
//      Function Return - a Boolean value, TRUE if a hotkey or ESC was pressed.
//

BOOLEAN
EFIAPI
PauseForInput (
  IN UINT64 Tested,
  IN UINT64 Total
  )
{
  DPRINTF_BM ("PauseForInput: 0x%x / 0x%x.\n", Tested, Total);

  UpdateProgress (BOOT_MANAGER_PHASE_MEMORY, Tested, Total, NULL);

  return FALSE;
} // PauseForInput


//
// FUNCTION NAME.
//      RunDiagnostics - Run diagnostics, per business logic.
//
// FUNCTIONAL DESCRIPTION.
//      This function is about making system memory available. Up to this
//      point only the memory that was specified in the platform driver as
//      required for initialization was made available in through the GCD. The
//      memory test will add memory to the GCD as it is tested.
//
//      There are several ways that memory tests can be scaled for speed. One
//      is through the selection of drivers. This function just located the
//      gEfiGenericMemTestProtocolGuid protocol, so the driver that implements
//      this protocol has final control over what each level of test means.
//
//      This protocol defines levels of tests, in ascending order they are:
//              IGNORE
//              QUICK
//              SPARSE
//              EXTENSIVE
//
//      Additional diagnostics not having anything to do with memory may be
//      added here, especially if they can be run in parallel with the memory
//      tests.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
RunDiagnostics (VOID)
{
  BOOLEAN ErrorOut;
  BOOLEAN TestAbort;
  SCT_STATUS Status;
  UINT64 TotalMemorySize;
  UINT64 TestedMemorySize;
  BOOLEAN RequireSoftECCInit;
  EXTENDMEM_COVERAGE_LEVEL Level;
  EFI_GENERIC_MEMORY_TEST_PROTOCOL *MemoryTestProtocol;

  DPRINTF_BM ("RunDiagnostics\n");

  Level = CONFIG_SYSTEM_BOOT_MANAGER_MEMORY_TEST_LEVEL;
  DPRINTF_BM ("  Level 0x%x.\n", Level);

  //
  // Initialize the memory test protocol. If it is not found or if there is no
  // new memory to test we will return immediately. If the Init function return
  // is EFI_NO_MEDIA, that means there is no additional memory to test.
  //

  Status = gBS->LocateProtocol (
                  &gEfiGenericMemTestProtocolGuid,
                  NULL,
                  (VOID **) &MemoryTestProtocol);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("  Problem locating Memory Tests, %r.\n", Status);
    return Status;
  }
  Status = MemoryTestProtocol->MemoryTestInit (
                                 MemoryTestProtocol,
                                 Level,
                                 &RequireSoftECCInit);
  if (Status == EFI_NO_MEDIA) {
    DPRINTF_BM ("  Memory Tests failed to init, %r.\n", Status);
    return SCT_STATUS_SUCCESS;
  }

  //
  // Test all the untested memory. Now that we have initialized the memory test
  // we have to keep calling the perform memory test function until it returns
  // EFI_NOT_FOUND. You are not allowed to proceed until this function returns
  // EFI_NOT_FOUND if there is ECC memory in the system because it is now in
  // test mode, and the memory test needs to walk across it all to put it back
  // into read mode. If the TestAbort flag is set the memory test will skip all
  // the actual testing and only do what is needed to restore ECC memory.
  //

  TestAbort = FALSE;
  while (TRUE) {
    Status = MemoryTestProtocol->PerformMemoryTest (
                                   MemoryTestProtocol,
                                   &TestedMemorySize,
                                   &TotalMemorySize,
                                   &ErrorOut,
                                   TestAbort);
    if (Status == EFI_NOT_FOUND) {
      DPRINTF_BM ("  Memory Tests complete.\n");
      break;
    }
    if (EFI_ERROR (Status)) {

      //
      // This is a memory error. Log the error.
      //

      DPRINTF_BM ("  Memory Error, %r.\n", Status);

      //
      // NEWREL: cu 09/11/30. Do the above.
      //

      break;
    }

    TestAbort = PauseForInput (TestedMemorySize, TotalMemorySize);
    if (TestAbort && !RequireSoftECCInit) {
      DPRINTF_BM ("  Aborting tests.\n");
      break;
    }
  }

  //
  // Done with memory tests. Shut down the memory test protocol.
  //

  Status = MemoryTestProtocol->Finished (MemoryTestProtocol);
  DPRINTF_BM ("  Memory Test Finished, %r.\n", Status);

  //
  // Before we return we need to check to see if we should now service a hotkey.
  // The test in PauseForInput only returned true if there was a hotkey pressed.
  // It did not actually service the event. We needed to stop the memory tests
  // before we could service the event. This is our first opportunity.
  //

  UPDATE_HOTKEY_STATES (mTextInEx);

  return Status; // Return the status from Finished.
} // RunDiagnostics


//
// FUNCTION NAME.
//      ProcessBootNextVariable - Attempt to launch the BootNext Load Option.
//
// FUNCTIONAL DESCRIPTION.
//      If the BootNext variable exists we attempt to launch it.
//      The BootNext variable is always deleted.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ProcessBootNextVariable (VOID)
{
  UINT32 Crc;
  SCT_STATUS Status;
  PUINT16 BootNextValue;
  PLOAD_OPTION_OBJECT Option;

  DPRINTF_BM ("ProcessBootNextVariable:\n");

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_NEXT_VARIABLE_NAME,
             NULL,                      // don't care about attributes.
             NULL,                      // don't care about size.
             (VOID **) &BootNextValue);
  DPRINTF_BM ("  SctLibGetEfiGlobalVariable returned %r.\n", Status);

  //
  // If the variable is not present we are done processing it.
  //

  if (EFI_ERROR (Status)) {
    return SCT_STATUS_SUCCESS;
  }

  //
  // Delete the variable immediately. BootNext is one-shot pass or fail.
  //

  Status = SetEfiGlobalVariable (
             EFI_BOOT_NEXT_VARIABLE_NAME,
             EFI_VARIABLE_NON_VOLATILE |
             EFI_VARIABLE_BOOTSERVICE_ACCESS |
             EFI_VARIABLE_RUNTIME_ACCESS,
             0,
             NULL);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("  Problem deleting BootNext, %r.\n", Status);
    return Status;
  }

  Option = NULL;
  Status = GetBootOption (*BootNextValue, &Option);
  if (EFI_ERROR (Status) || Option == NULL) {
    return EFI_NOT_FOUND;
  }

  DPRINTF_BM (" BootNextValue = %d\n", *BootNextValue);

  //
  // Check if the BootOption is active.
  //

  if (((Option->Attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_BOOT) &&
      ((Option->Attributes & LOAD_OPTION_ACTIVE) != LOAD_OPTION_ACTIVE)) {

    DPRINTF_BM ("  BootNext BootOption is not active \n");
    SafeFreePool (BootNextValue);
    return EFI_ACCESS_DENIED;
  }

  if ((Option->Attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_APP) {
    DecompressOptionalFirmwareVolume (SCT_FIRMWAREVOLUME_TYPE_ALL);
  }

  //
  // For the BootNext option we will ignore the active attribute and attempt
  // to launch the option no matter what.
  //

  GetLoadOptionCrc (*BootNextValue, SCT_BM_LO_BOOT, &Crc);
  Status = LaunchBootOption (*BootNextValue, Crc);

  SafeFreePool (BootNextValue);
  return Status;
} // ProcessBootNextVariable


//
// FUNCTION NAME.
//      ProcessBootList - Attempt the Load Options in the Boot List.
//
// FUNCTIONAL DESCRIPTION.
//      This function processes the Boot List. The default Boot List is provided
//      in the BootOrder variable as an array of OptionNumbers.
//
//      NEWREL: cu 09/11/19, Add support for discovering which Boot List should
//      be used and processing it, instead of always processing the Boot List
//      in the BootOrder variable.
//
// ENTRY PARAMETERS.
//      ReturnFail      - return if Boot failed.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
ProcessBootList (VOID)
{
  UINTN i;
  UINT32 Crc;
  SCT_STATUS Status;
  SCT_STATUS LaunchStatus;
  PUINT16 OptionOrder;
  UINTN OptionOrderSize;
  PLOAD_OPTION_OBJECT Option;
  BOOLEAN EnumerateFlag;
#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
  UINT32 PrevCrc;
  UINTN NewOptionOrderSize;
#endif

  DPRINTF_BM ("ProcessBootList:\n");

  EnumerateFlag = FALSE;
  LaunchStatus = EFI_SUCCESS;

  //
  // Get the variable.
  //

  Status = SctLibGetEfiGlobalVariable (
             EFI_BOOT_ORDER_VARIABLE_NAME,
             NULL,                      // don't care about attributes.
             &OptionOrderSize,
             (VOID **) &OptionOrder);
  DPRINTF_BM ("  SctLibGetEfiGlobalVariable returned %r.\n", Status);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG_BMR ({
    for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {
      DPRINTF_BM ("  BootOrder [0x%x] = 0x%x.\n", i, OptionOrder [i]);
    }
  });

  //
  // The variable was found, so now we need to launch each active option.
  //

  for (i = 0; i < OptionOrderSize / sizeof (UINT16); i++) {
    if (mBmHotkeySupport_Count != 0) {
      CHECK_HOTKEYS (mTextInEx);
    }

    Status = GetBootOption (OptionOrder [i], &Option);

    DPRINTF_BM ("  GetOption Option [0x%x] = 0x%x, returned %r.\n",
      i, OptionOrder [i], Status);

    if (EFI_ERROR (Status)) {
      continue;
    }

    DPRINTF_BM ("  Launch BootOption :%s\n", Option->Description);

    if (Option->Attributes & LOAD_OPTION_ACTIVE) {
      GetLoadOptionCrc (Option->OptionNumber, SCT_BM_LO_BOOT, &Crc);
      LaunchStatus = LaunchBootOption (Option->OptionNumber, Crc);
      DPRINTF_BM ("  LaunchBootOption Option [0x%x] = 0x%x, returned %r.\n",
        i, OptionOrder [i], LaunchStatus);

#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND

      //
      // If fail to boot from first BootOption, release the USB HC control right
      // so that other drivers can proceed to manage them.
      //
      if (!mIsBootFailConnectUSB) {
        ReleaseAllUsbHc ();
        StartAllUsbHc ();
        mIsBootFailConnectUSB = TRUE;
      }

#endif

      //
      // Try to enumerate all BootOption once if :
      // The first boot fail in each POST time, and
      // the current boot option's is pre-defined load option.
      //
      // Note: Pre-defined load option is to make sure option number would not
      //       be changed after enumeration.
      //

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS
      if (EFI_ERROR (LaunchStatus)) {

        if (IsPreDefinedLoadOption (OptionOrder [i])&& !EnumerateFlag) {
          PrevCrc = Crc;

          EnumerateAllLoadOptions ();
          EnumerateFlag = TRUE;

          GetLoadOptionCrc (OptionOrder [i], SCT_BM_LO_BOOT, &Crc);

          if (PrevCrc != Crc) {

            //
            // After enumeration, if current load option has been changed,
            // Boot Manager will try to launch it again.
            //

            LaunchStatus = LaunchBootOption (OptionOrder [i], Crc);
            DPRINTF_BM ("  LaunchBootOption Option [0x%x] = 0x%x, returned %r.\n",
            i, OptionOrder [i], LaunchStatus);
          }

        }
      }
#endif

      //
      // UEFI Specification Version 2.3 Section 3.1.1 Boot Manager Programming
      // states the following in paragraph 4: "If the boot via Boot#### returns
      // with a status of EFI_SUCCESS the boot manager will stop processing the
      // BootOrder variable and present a boot manager menu to the user."
      //

      if (LaunchStatus == EFI_SUCCESS) {
        LaunchBootMenuApplication ();
      }
    } else {
      DPRINTF_BM ("  Option [0x%x] = 0x%x, is not active.\n",
        i, OptionOrder [i]);
    }
  }

#if OPTION_SYSTEM_BOOT_MANAGER_ENUMERATE_BOOT_OPTIONS

  //
  // if the last Boot device is fail,
  // update "BootOrder" to check if new devices have been enumerated.
  //

  if (EFI_ERROR (LaunchStatus) && (i == OptionOrderSize / sizeof (UINT16))) {
    Status = SctLibGetEfiGlobalVariable (
               EFI_BOOT_ORDER_VARIABLE_NAME,
               NULL,                      // don't care about attributes.
               &NewOptionOrderSize,
               (VOID **) &OptionOrder);
    DPRINTF_BM ("  SctLibGetEfiGlobalVariable returned %r.\n", Status);
    if (EFI_ERROR(Status)) {
      return Status;
    }

    if (NewOptionOrderSize > OptionOrderSize){

      //
      // Try the new devices.
      //

      DPRINTF_BM ("Try to boot to new devices.\n");
      for (; i < NewOptionOrderSize / sizeof (UINT16); i++) {
        Status = GetBootOption (OptionOrder [i], &Option);

        DPRINTF_BM ("  GetOption Option [0x%x] = 0x%x, returned %r.\n",
          i, OptionOrder [i], Status);

        if (EFI_ERROR (Status)) {
          continue;
        }

        DPRINTF_BM ("  Launch BootOption :%s\n", Option->Description);

        if (Option->Attributes & LOAD_OPTION_ACTIVE) {
          GetLoadOptionCrc (Option->OptionNumber, SCT_BM_LO_BOOT, &Crc);
          Status = LaunchBootOption (Option->OptionNumber, Crc);
          DPRINTF_BM ("  LaunchBootOption Option [0x%x] = 0x%x, returned %r.\n",
            i, OptionOrder [i], Status);

          if (Status == EFI_SUCCESS) {
            LaunchBootMenuApplication ();
          }
        } else {
          DPRINTF_BM ("  Option [0x%x] = 0x%x, is not active.\n",
            i, OptionOrder [i]);
        }
      }
    }
  }
#endif
  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // ProcessBootList


//
// FUNCTION NAME.
//      LaunchBootMenuApplication - Display the boot menu.
//
// FUNCTIONAL DESCRIPTION.
//      If all Load Options fail to find a boot loader display the Boot Menu
//      to get guidance from the user.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EFIAPI
LaunchBootMenuApplication (VOID)
{
  UINT8 Mode;
  UINT8 *Data;
  EFI_STATUS Status;
  CURRENT_VIEW CurrentView;
  EFI_GUID SctSelectViewGuid = SCT_SELECT_VIEW_GUID;

  Mode = TEXT_VIEW;
  Data = NULL;

#if (OPTION_SYSTEM_FORM_BROWSER_METRO_VIEW + OPTION_SYSTEM_FORM_BROWSER_SIMPLE_TEXT_VIEW + OPTION_SYSTEM_FORM_BROWSER_GRAPHICAL_TEXT_VIEW) == 0
#error  NOT ANY FORM_BROWSER_VIEW Type was Defined !!!
#endif

  //
  // Force text mode if UCR is enabled.
  //

  if (IsUcrEnabled () == FALSE) {

    //
    // GUI + Text View. or GUI + Graphic View.
    //

    Data = SctLibGetVariableAndSize (
             SELECT_VIEW_VARIABLE_NAME,
             &gSctSelectViewGuid,
             NULL);

    if (Data == NULL) {
      Mode = TEXT_VIEW;
    } else {
      Mode = *Data;
      FreePool (Data);
    }

  } // IF UCR DISABLED.

  do {
    CurrentView.ViewType = Mode;
    gRT->SetVariable (
           CURRENT_VIEW_VARIABLE_NAME,
           &SctSelectViewGuid,
           EFI_VARIABLE_BOOTSERVICE_ACCESS,
           sizeof (CURRENT_VIEW),
           &CurrentView);

    Status =  LaunchBuiltInApplication ((Mode == METRO_VIEW) ? CONFIG_SYSTEM_GUI_BOOT_MENU_DEVICE_PATH : CONFIG_SYSTEM_BOOT_MENU_DEVICE_PATH);
    if (EFI_ERROR (Status) && (Mode == METRO_VIEW)) {
      Mode = TEXT_VIEW;
    } else {
      break;
    }

  } while(TRUE);

  return Status;
} // LaunchBootMenuApplication


//
// FUNCTION NAME.
//      CheckRecoveryBoot - Launch Boot option with SCT_BM_RECOVERY flag is set.
//
// FUNCTIONAL DESCRIPTION.
//      This function checks if the current boot mode is recovery and
//      try to launch the boot option with SCT_BM_RECOVERY flag is set.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
CheckRecoveryBoot (VOID)
{
  UINT32 Crc;
  SCT_STATUS Status;
  PUINT16 RecoveryOptionNumber;

  //
  // Call the update progress milestone.
  //

  UpdateProgress (BOOT_MANAGER_PHASE_RECOVERY, 0, 1, NULL);

  //
  // Check current Boot Mode.
  //

  if(mBootMode != BOOT_IN_RECOVERY_MODE) {
    UpdateProgress (BOOT_MANAGER_PHASE_RECOVERY, 1, 1, NULL);
    return SCT_STATUS_SUCCESS;
  }

  //
  // Find the Recovery entry.
  //

  RecoveryOptionNumber = NULL;
  RecoveryOptionNumber = SctLibGetVariableAndSize (
                           SCT_BOOT_OPTION_RECOVERY,
                           &gSctBdsServicesProtocolGuid,
                           NULL);

  if (RecoveryOptionNumber == NULL) {
    DPRINTF_BM ("  Couldn't find Recovery variable\n");
    return EFI_NOT_FOUND;
  }
  DPRINTF_BM ("  Find Recovery variable %x.\n", *RecoveryOptionNumber);
  GetLoadOptionCrc (*RecoveryOptionNumber, SCT_BM_LO_BOOT, &Crc);
  Status = LaunchBootOption (*RecoveryOptionNumber, Crc);

  return Status;
} // CheckRecoveryBoot.


//
// FUNCTION NAME.
//      EndDisplaySplashScreen - End the display of the diagnostic splash screen.
//
// FUNCTIONAL DESCRIPTION.
//      This function will call the Stop of the diagnostic splash screen.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
EndDisplaySplashScreen (VOID)
{
  SCT_STATUS Status;
  SCT_DIAGNOSTIC_SPLASH_PROTOCOL *DiagnosticSplash;

  Status = SCT_STATUS_SUCCESS;
  DPRINTF_BM ("EndDisplaySplashScreen: \n");

  if (mSystemConfiguration.DiagnosticSplash == 1) {

    DPRINTF_BM ("  Stop display in Splash.\n");
    Status = gBS->LocateProtocol (
                    &gSctDiagnosticSplashProtocolGuid,
                    NULL,
                    (VOID **) &DiagnosticSplash);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("  Problem finding Diagnostic Splash Protocol, status: %r.\n", Status);
      return Status;
    }

    Status = DiagnosticSplash->Stop (DiagnosticSplash);
  }

  return Status;
} // EndDisplaySplashScreen


//
// FUNCTION NAME.
//      InitializeSecurity - Initialize Security per the UEFI Specification.
//
// FUNCTIONAL DESCRIPTION.
//      This function locates the User Manager protocol and calls its Identify()
//      method to establish the Current User. The Current User profile is
//      also published in the System Table by the User Manager on ReadyToBootEvent.
//
//      Prior to the Identify call this function processes the
//      SecurityConnection list, a configurable list of device paths that must
//      be connected when security is enabled. Generally these device paths
//      describe Credential Providers which will be discovered and managed
//      by the User Manager.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//                        SCT_STATUS_SUCCESS.
//

static
SCT_STATUS
InitializeSecurity (VOID)
{
#if OPTION_SUPPORT_USER_IDENTIFICATION
  EFI_STATUS Status;
  EFI_TPL Tpl;
  EFI_USER_PROFILE_HANDLE User;         // User Profile handle returned by Identify();
  EFI_USER_MANAGER_PROTOCOL *UserManagerProtocol; // pointer to User Manager protocol.
  PBA_STATUS_VAR *PbaStatusVar;
  EFI_GUID PbaStatusVarGuid = PBA_STATUS_VAR_GUID;
  UINTN VarSize;
  UINT32 Attributes;

  DPRINTF_BM ("InitializeSecurity:\n");

  Status = ConnectDevices (SecurityConnectList);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("  ConnectDevices returned %r.\n", Status);
    return Status;
  }

  //
  // Per UEFI specification, the Boot Manager needs to call the User Manager's
  // Identify() function to establish the Current User.
  //

  //
  // Locate the User Manager protocol.
  //

  Status = gBS->LocateProtocol (
                  &gEfiUserManagerProtocolGuid,
                  NULL,
                  (VOID **) &UserManagerProtocol);

  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // If UserManagerProtocol is installed then call its Identify() method.
  //

  PbaStatusVar = NULL;
  VarSize = 0;
  Attributes = 0;
  Status = SctLibGetVariable (
             PBA_STATUS_VAR_NAME,
             &PbaStatusVarGuid,
             &Attributes,
             &VarSize,
             (VOID**)&PbaStatusVar);

  if (EFI_ERROR (Status) || VarSize == 0) {
    DPRINTF ("Failed to get PBA_STATUS_VAR_NAME variable, status: %r.\n", Status);
    return SCT_STATUS_INVALID_DATA;
  }

  if (PbaStatusVar->IdentifyOnBoot != 0) {

    if (mBmHotkeySupport_Count != 0) {
      UPDATE_HOTKEY_STATES (mTextInEx);
    }

#if OPTION_SYSTEM_VIRTUAL_KEYBOARD_SUPPORT
    CloseVirtualKeyboard ();
#endif

    Tpl = SetTpl (TPL_APPLICATION);
    UserManagerProtocol->Identify (UserManagerProtocol, &User);
    SetTpl (Tpl);

#if OPTION_SYSTEM_VIRTUAL_KEYBOARD_SUPPORT
    OpenVirtualKeyboard ();
#endif

    //
    // Extend the timeout value of HOTKEY detection.
    //

    mTimeoutValue = (mTimeoutValue == 0) ? CONFIG_SYSTEM_BOOT_MANAGER_WAIT_TIME_AFTER_PASSWORD_PROMPT : mTimeoutValue;
  }

#endif // OPTION_SUPPORT_USER_IDENTIFICATION

  return SCT_STATUS_SUCCESS;
} // InitializeSecurity

//
// FUNCTION NAME.
//      EndOfDxeEventGroupGuidCallback - Dummy function needed by the creation of EVT_NOTIFY_SIGNAL event.
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
EndOfDxeEventGroupGuidCallback (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  mBmEndOfDxeEventSignaled = TRUE;
  return;
} // EndOfDxeEventGroupGuidCallback

//
// FUNCTION NAME.
//      MsTaskBdsEntry - Default task for the Bds Entry Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task for the BDS Entry.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      None.
//

SCT_STATUS
MsTaskBdsEntry (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_STATUS Status;
  UINTN DataSize;
  PUINT64 OsIndications;
  UINT64 OsIndicationsSupported;
  EFI_EVENT EndOfDxeEvent;
  EFI_HANDLE Handle;
  SCT_MILESTONE_TASK_TPM_PP_CHECK TpmPPMilstoreData;
#if OPTION_SUPPORT_TCG
  EFI_INPUT_KEY Key;
#endif

#if (OPTION_CSM_OPTION_OUT && OPTION_CSM_AUTO_OPTION)
  UINT8 *LoadCsm;
#endif

#if OPTION_SYSTEM_BOOT_MANAGER_BOOT_FROM_LAST_BOOT_OPTION_AT_S4
  PUINT16 LastBootCurrentValue;
#endif

  SCT_BDS_MILESTONE_BOOT_FAIL_CONFIG_DATA BootFailConfigData;
#if OPTION_SUPPORT_CAPSULE_UPDATE
  SCT_BDS_MILESTONE_CAPSULE_UPDATE_DATA CapsuleUpdateData;
#endif

#if OPTION_SYSTEM_BOOT_MANAGER_VARIABLE_ROBUST_CHECK
  EFI_STATUS VarCheckStatus;
#endif

#if OPTION_SYSTEM_BOOT_MANAGER_BOOT_STATE
  BOOLEAN IsFirstBoot;
#endif

#if OPTION_SUPPORT_BIOS_SELF_HEALING
  SCT_BDS_MILESTONE_BIOS_SELF_HEALING_DATA BiosSelfHealingData;
  EFI_HOB_GUID_TYPE *GuidHob;
#endif

  DPRINTF_FUNCTION_ENTRY();

  Status = gBS->HandleProtocol (
                  gST->ConsoleInHandle,
                  &gEfiSimpleTextInputExProtocolGuid,
                  (VOID **) &mTextInEx);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Failed to find the SimpleTextInputEx Protocol.\n");
  }

  Status = PrepareDeferred ();
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Failed to PrepareDeferred.\n");
  }

  //
  // Report Status Code(0x30).
  // BDS Entry Point Report Status Code.
  //

  REPORT_STATUS_CODE (
    EFI_PROGRESS_CODE,
    EFI_SOFTWARE_BDS | EFI_SW_BDS_ENTRY_POINT);

  //
  // Initialize the system configuration.
  //

  Status = InitializeConfiguration ();
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Failed to initialize System variable.\n");;
  }

  LoadSetupModules ();

#if OPTION_SYSTEM_BOOT_MANAGER_HIDE_SPLASH_SCREEN_UCR

  //
  //Hide Splash Screen and Hotkey if Console Redirection is enabled
  //

  if (mSystemConRedirect.UcrStatus != SCT_CONSOLE_REDIRECTION_STATUS_DISABLED) {
    mShowSplashScreen = FALSE;
    mDisplayHotkeysDuringPost = FALSE;
  }
#endif

  //
  // Check the OsIndication and clear the bits.
  //

  DataSize = 0;
  Status = SctLibGetVariable (
             EFI_OS_INDICATIONS_VARIABLE_NAME,
             &gEfiGlobalVariableGuid,
             NULL,
             &DataSize,
             (VOID **) &OsIndications);

  if (!EFI_ERROR (Status)) {

    //
    // Always clear EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED bit if it has
    // been set.  It indicate the capsule is delivered through ESP.
    //

    if (*OsIndications & EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED) {
      mCapsuleEspDelivery = TRUE;
      *OsIndications &= ~EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED;
    }

    //
    // Always clear EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED bit if it has been set.
    //

    if (*OsIndications & EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED) {
      *OsIndications &= ~EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED;
    }

    Status = gRT->SetVariable (
                    EFI_OS_INDICATIONS_VARIABLE_NAME,
                    &gEfiGlobalVariableGuid,
                    EFI_VARIABLE_BOOTSERVICE_ACCESS |
                    EFI_VARIABLE_RUNTIME_ACCESS |
                    EFI_VARIABLE_NON_VOLATILE,
                    sizeof (UINT64),
                    OsIndications);

    FreePool (OsIndications);
  }

#if OPTION_SUPPORT_SECURE_BIOS

  //
  // Lock SPI ROM regions and freeze SPI controller settings.
  //

  SecureBiosFreeze ();
#endif // OPTION_SUPPORT_SECURE_BIOS

  DPRINTF_BM ("  mSystemConfiguration.CsmSupport = %d\n", mSystemConfiguration.CsmSupport);
  switch (mSystemConfiguration.CsmSupport) {

    case CSM_SUPPORT_NO: {              // NO, without CSM during P.O.S.T.
      DPRINTF_BM ("  No CSM during P.O.S.T.\n");
      if (SeamLessBootFlag()) {
        RequestDrivers (mFvHandle, mSeamLessBootFvFile, SCT_FIRMWAREVOLUME_TYPE_MAIN, FALSE);
      }
      mCsmSupported = FALSE;
      mDisplayHotkeysDuringPost = OPTION_SYSTEM_BOOT_MANAGER_DISPLAY_HOTKEY_PROMPT;
    } break;

    case CSM_SUPPORT_YES: {             // YES, load CSM modules always.
      DPRINTF_BM ("  Loading CSM during P.O.S.T.\n");
      mCsmSupported = TRUE;
      RequestDrivers (mFvHandle, mCsmModuleFvFile, SCT_FIRMWAREVOLUME_TYPE_CSM, FALSE);
      RequestDrivers (mFvHandle, mOnDemandFvFile, SCT_FIRMWAREVOLUME_TYPE_MAIN, FALSE);
      PrepareContextOverrideDriver ();
    } break;

  #if OPTION_CSM_AUTO_OPTION
    case CSM_SUPPORT_AUTO: {            // according to saved variable.
      DPRINTF_BM ("  Auto-detection for loading CSM during P.O.S.T.\n");
      //
      // Check if the CSM module is necessary for this boot.
      //
      DataSize = 0;
      Status = SctLibGetVariable (
                 L"LoadCsmNextBoot",
                 &gSctBdsServicesProtocolGuid,
                 NULL,
                 &DataSize,
                 &LoadCsm);
      if (!EFI_ERROR (Status) && *LoadCsm == 1) {
        //
        // With CSM.
        //
        mCsmSupported = TRUE;
        DPRINTF_BM ("  Load CSM module is necessary\n");
        RequestDrivers (mFvHandle, mCsmModuleFvFile, SCT_FIRMWAREVOLUME_TYPE_CSM, FALSE);
        RequestDrivers (mFvHandle, mOnDemandFvFile, SCT_FIRMWAREVOLUME_TYPE_MAIN, FALSE);
        PrepareContextOverrideDriver ();
      } else {
        //
        // Without CSM.
        //
        mCsmSupported = FALSE;
        mDisplayHotkeysDuringPost = OPTION_SYSTEM_BOOT_MANAGER_DISPLAY_HOTKEY_PROMPT;
      }
    } break;
  #endif
  } // switch (mSystemConfiguration.CsmSupport)


  DPRINTF_BM ("mSystemConRedirect.UcrStatus %d\n", mSystemConRedirect.UcrStatus);

  if (mSystemConRedirect.UcrStatus != SCT_CONSOLE_REDIRECTION_STATUS_DISABLED) {
    DPRINTF_BM ("Load terminal driver\n");
    RequestDrivers (mFvHandle, mTerminalDriverFileName, SCT_FIRMWAREVOLUME_TYPE_MAIN, FALSE);
    DPRINTF_BM ("Load terminal driver returned %r\n", Status);
  }
#if OPTION_SUPPORT_TCG
  gPPRequireUIConfirm = TcgPhysicalPresenceLibNeedUserConfirm ();
  gPPRequireUIConfirm |= Tcg2PhysicalPresenceLibNeedUserConfirm ();
#endif

  PERF_START (0, "ConfigUefiNetwork", "BootManager", 0);
  ConfigUefiNetworkStackDriver ();
  PERF_END (0, "ConfigUefiNetwork", "BootManager", 0);

  //
  // Initialize the Device services.
  //

  InitializeDevice ();

  //
  // Finalize the System Table in preparation for an OS Boot Loader.
  //

  UpdateSystemTable ();

  PERF_START (0, "DiscoverBmEssentialVariable", "BootManager", 0);

  //
  // Discover and allocate resources for those variables needed by BootManager.
  //

  DiscoverBmEssentialVariable (FALSE);

  PERF_END (0, "DiscoverBmEssentialVariable", "BootManager", 0);

  //
  // The hotkey services are dependent on the load option services, so we must
  // initialize load options first.
  //

  PERF_START (0, "InitializeLoadOptions", "BootManager", 0);
  InitializeLoadOptions ();
  PERF_END (0, "InitializeLoadOptions", "BootManager", 0);

#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND
  Status = InitializeUsbFullInitOnDemand ();
  if (Status == EFI_ABORTED) {

    //
    // Decompress USB package if Boot Manager requires USB full initialization.
    //

    DecompressOptionalFirmwareVolume (SCT_FIRMWAREVOLUME_TYPE_USB);

#if OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND
    RequestPs2Drivers ();
#endif  // OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND

  }

#if !OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND
    RequestPs2Drivers ();
#endif  // OPTION_SYSTEM_BOOT_MANAGER_PS2_DEVICE_INIT_ON_DEMAND

#else
  DecompressOptionalFirmwareVolume (SCT_FIRMWAREVOLUME_TYPE_USB);

  RequestPs2Drivers ();

#endif

  //
  // Update if we should check Hotkey for current boot mode.
  //
  //UpdateCheckHotkey ();
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_UPDATE_HOTKEY_SUPPORT_COUNT, MsTaskUpdateHotkeySupportCount,  NULL, 0);

  //
  // Create an event for each hotkey. Note that we create the hotkey events
  // before we connect consoles. This will prevent race conditions.
  // Disable Hotkeys if resuming from S4.
  //
  INITIALIZE_HOTKEY (mTextInEx);

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)

  if (BOOT_ON_S4_RESUME == mBootMode) {

    //
    // Store the OPROM devicePath first for S4 resume.
    //

    Status = SctLibGetVariable (
               L"OpromDevicePath",
               &gSctBdsServicesProtocolGuid,
               NULL,
               NULL,
               &OpromDevicePaths);
    if (EFI_ERROR (Status)) {
      OpromDevicePaths = NULL;
    }
  }
#endif

  //
  // Always clear "OpromDevicePath" variable.
  //

  Status = gRT->SetVariable (
                  L"OpromDevicePath",
                  &gSctBdsServicesProtocolGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  0,
                  (VOID *)NULL);

  //
  // Chain the default ClearScreen Function.
  //

  mOriginalClearScreenFun = gST->ConOut->ClearScreen;
  gST->ConOut->ClearScreen = BmClearScreen;

  //
  // Free the resources allocated for those variables needed by BootManager.
  //

  FreeBmEssentialVariable ();

  //
  // Check if all essential variables in BootManager are robust.
  //

#if OPTION_SYSTEM_BOOT_MANAGER_VARIABLE_ROBUST_CHECK
  PERF_START (0, "CheckBmVariable", "BootManager", 0);
  VarCheckStatus = CheckBootManagerVariable (FALSE, &gSctBdsServicesProtocolGuid);
  if (EFI_ERROR (VarCheckStatus)) {
    mIsBootOptionDamaged = TRUE;
  }

  DPRINTF_HK ("mIsBootOptionDamaged:%d, %r.\n", mIsBootOptionDamaged, Status);
  DPRINTF_HK ("mIsHotkeyListDamaged:%d, %r.\n", mIsHotkeyListDamaged, Status);

  if (mIsHotkeyListDamaged || mIsBootOptionDamaged) {

    ReportBootManagerError ();
    RemoveAllBootManagerVariable ();
    InitializeLoadOptions ();
    INITIALIZE_HOTKEY (mTextInEx);
    mIsHotkeyListDamaged = FALSE;
    mIsBootOptionDamaged = FALSE;
  }
  PERF_END (0, "CheckBmVariable", "BootManager", 0);
#endif

  //
  // Dispatch all drivers that are pendding to load.
  //

  BmDispatch (FALSE);

  //
  // Call Connect Drivers milestone.
  //

  PERF_START (0, "ConnectDrivers", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_CONNECT_DRIVERS, MsTaskConnectDrivers, NULL, 0);
  PERF_END (0, "ConnectDrivers", "BootManager", 0);

  //
  // Connect Consoles per the platform policy and the variables ConIn, ConOut
  // and ErrOut.
  //

  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_CONSOLE, MsTaskConnectConsoles, NULL, 0);

  //
  // Displays a UI screen to notify the user that TPM state change operation
  // has been requested.
  //

  PERF_START (0, "TpmCheck", "BootManager", 0);
  TpmPPMilstoreData.IsVgaConnected = (mDeferredVgaHandle == 0) ? TRUE : FALSE;
  TpmPPMilstoreData.PPRequireUIConfirm = gPPRequireUIConfirm;
  TpmPPMilstoreData.IsPpExecuted = FALSE;
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_TPM_OP_CHECK, MsTaskTpmCheck, &TpmPPMilstoreData, sizeof (TpmPPMilstoreData));
  PERF_END (0, "TpmCheck", "BootManager", 0);

  //
  // Connect all PCI devices before signaling EndOfDxe events.
  //

  ConnectAllPciDevices ();
  BmDispatch (TRUE);

#if OPTION_SUPPORT_CSM
  //
  // Prepare S3 information, this MUST be done before gEfiDxeSmmReadyToLockProtocolGuid (ExitPmAuth/EndOfDxe)
  //

  if (!mS3Saved) {
    EFI_ACPI_S3_SAVE_PROTOCOL *AcpiS3Save;
    EFI_PHYSICAL_ADDRESS S3ReservedLowMemoryBase;

    Status = gBS->LocateProtocol (&gEfiAcpiS3SaveProtocolGuid, NULL, (VOID **) &AcpiS3Save);
    if (!EFI_ERROR (Status)) {
      S3ReservedLowMemoryBase = 0;
      if (mCsmSupported == FALSE) {

        //
        // Allocate buffer under 1MB for the real mode ACPI wake vector.
        // There are no legacy BIOS so any location should be O.K.
        //

        S3ReservedLowMemoryBase = 0xFFFFF;
        Status = (gBS->AllocatePages) (
                         AllocateMaxAddress,
                         EfiReservedMemoryType,
                         EFI_SIZE_TO_PAGES (CONFIG_SYSTEM_ACPI_S3_SAVE_SIZE_CSM),
                         &S3ReservedLowMemoryBase);
        if (EFI_ERROR(Status)) {
          return Status;
        }
      }
      AcpiS3Save->S3Save (AcpiS3Save, NULL);
      mS3Saved = TRUE;
    }
  }
#endif // OPTION_SUPPORT_CSM

    DPRINTF_BM ("Bootmanager signaling EndOfDxe event.\n");

#if OPTION_SUPPORT_TCG

  //
  // MemoryOverwriteControl.
  //

  PERF_START (0, "MemoryOverwriteControl", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_MEMORY_OVERWRITE_CONTROL, MsTaskMemoryOverwriteControl, NULL, 0);
  PERF_END (0, "MemoryOverwriteControl", "BootManager", 0);
#endif // OPTION_SUPPORT_TCG

#if OPTION_SUPPORT_BIOS_DATA_SELF_HEALING && OPTION_SYSTEM_BIOS_DATA_SELF_HEALING_BDS_BACKUP

  //
  // Call the bios data backup before end of dxe event, so the SMM driver could access the memory
  // outside of the SMM.
  //

  DPRINTF_BM ("Call ProcessBiosDataBackup!\n");
  ProcessBiosDataBackup ();
#endif // OPTION_SUPPORT_BIOS_DATA_SELF_HEALING && OPTION_SYSTEM_BIOS_DATA_SELF_HEALING_BDS_BACKUP

#if OPTION_SUPPORT_CSM
  //
  // Signal EndOfDxe events before connecting console devices.
  // Since PI1.2.1, we need signal EndOfDxe as ExitPmAuth.
  //

  Handle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &Handle,
                  &gExitPmAuthProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  NULL);
#endif // OPTION_SUPPORT_CSM

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  EndOfDxeEventGroupGuidCallback,
                  NULL,
                  &gEfiEndOfDxeEventGroupGuid,
                  &EndOfDxeEvent);
  gBS->SignalEvent (EndOfDxeEvent);
  gBS->CloseEvent (EndOfDxeEvent);

  if (mDxeSmmReadyToLockProtocol == FALSE) {
    //
    // NOTE: We need install DxeSmmReadyToLock directly here because many boot script is added via ExitPmAuth/EndOfDxe callback.
    // If we install them at same callback, these boot script will be rejected because BootScript Driver runs first to lock them done.
    // So we separate them to be 2 different events, ExitPmAuth is last chance to let platform add boot script. DxeSmmReadyToLock will
    // make boot script save driver lock down the interface.
    //

    Handle = NULL;
    Status = gBS->InstallProtocolInterface (
                    &Handle,
                    &gEfiDxeSmmReadyToLockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    NULL);
    ASSERT_EFI_ERROR (Status);
    mDxeSmmReadyToLockProtocol = TRUE;
  }

#if (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)

  BdsEnableSmmCodeAccessCheck();

#endif // (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)

  //
  // Connect those devices that have touch functionality.
  //

  //
  // Dispatch the deferred 3rd party images.
  //

  PERF_START (0, "DeferredImage", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_LOAD_DEFERRED_IMAGE, MsTaskLoadDeferredImage, NULL, 0);
  PERF_END (0, "DeferredImage", "BootManager", 0);

  ConnectDevices (mTouchDeviceConnectList);

#if OPTION_SYSTEM_BOOT_MANAGER_BOOT_STATE
  IsFirstBoot = PcdGetBool (PcdBootState);
  if (IsFirstBoot) {
    PcdSetBoolS (PcdBootState, FALSE);
  }
#endif

  RequestDrivers (mFvHandle, mScsiModuleFvFile, SCT_FIRMWAREVOLUME_TYPE_MAIN, TRUE);

#if OPTION_SYSTEM_VIRTUAL_KEYBOARD_SUPPORT

  //
  // Open virtual keyboard service.
  //

  OpenVirtualKeyboard ();
#endif

  SignalConsoleReady ();

  //
  // If PP should be executed but it did not because the un-trusted console,
  // then it should display the error message to warn the user.
  //

#if OPTION_SUPPORT_TCG
  if (((TcgPhysicalPresenceLibNeedUserConfirm () == TRUE) || (Tcg2PhysicalPresenceLibNeedUserConfirm () == TRUE)) &&
    (TpmPPMilstoreData.IsPpExecuted == FALSE)) {
    CreatePopUp (
      EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE,
      &Key,
      L"TPM Physical Presence prompt deferred due to un-trusted console.",
      L"Please check your video and keyboard hardware configuration.",
      L"Please press any key to continue.",
      NULL);
  }
#endif

  //
  // BDS Services are dependent on Load Option and Hotkey services.
  // BdsServices use the databases in the LoadOption and Hotkey modules.
  // Besides, BDS service would be available after the consoles connected.
  //

  InitializeBdsServices ();

  InitializeBootManagerPolicy ();

#if OPTION_SUPPORT_BIOS_SELF_HEALING
  DPRINTF_BM ("Call ProcessBiosSelfHealing!\n");

  GuidHob = GetFirstGuidHob (&gSctBiosSelfHealingModeHobGuid);
  if (GuidHob != NULL) {
    CopyMem ((VOID *) &BiosSelfHealingData, GET_GUID_HOB_DATA (GuidHob), sizeof (SCT_BDS_MILESTONE_BIOS_SELF_HEALING_DATA));
  } else {
    BiosSelfHealingData.BiosSelfHealingMode = 0;
    BiosSelfHealingData.Attributes = 0;
  }

  SCT_MILESTONE_TASK (
    BDS_MILESTONE_TASK_BIOS_SELF_HEALING,
    MsTaskBiosSelfHealing,
    &BiosSelfHealingData,
    sizeof (BiosSelfHealingData));
#endif

  //
  // Call the capsule flash update milestone.
  //

#if OPTION_SUPPORT_CAPSULE_UPDATE

  //
  // Make sure to clean the "CapsuleUpdateData" variable.
  // To avoid re-do capsule update.
  // "CapsuleHddUpdateData" will be deleted after UpdateCapsuleFromHdd.
  //

  Status = gRT->SetVariable (
                  EFI_CAPSULE_VARIABLE_NAME,
                  &gEfiCapsuleVendorGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  0,
                  (VOID *)NULL);

  //
  // Clean the "CapsuleGuidData" variable.
  //
  Status = gRT->SetVariable (
                  SCT_CAPSULE_GUID_VARIABLE_NAME,
                  &gSctCapsuleInfoVariableGuid,
                  EFI_VARIABLE_NON_VOLATILE |
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  0,
                  (VOID *)NULL);

  //
  // If mCapsuleEspDelivery is set, then don't need to process with it
  // at the very beginning.  Only process it after the devicepath has been
  // connected.
  //

  if (mCapsuleEspDelivery == FALSE) {

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

  //
  // Set OsIndicationsSupported variable so that OS can provide a way for the user
  // to launch BIOS UI interface/FMP Capsule update/Capsule Delivery on ESP.
  //

  OsIndicationsSupported = EFI_OS_INDICATIONS_BOOT_TO_FW_UI | EFI_BOOT_OPTION_SUPPORT_SYSPREP;
#if OPTION_SUPPORT_FMP_CAPSULE_UPDATE
  OsIndicationsSupported |= EFI_OS_INDICATIONS_FMP_CAPSULE_SUPPORTED;
#endif // OPTION_SUPPORT_FMP_CAPSULE_UPDATE
#if OPTION_SUPPORT_OS_INDICATIONS_CAPSULE_DELIVERY
  OsIndicationsSupported |= EFI_OS_INDICATIONS_FILE_CAPSULE_DELIVERY_SUPPORTED;
#endif // OPTION_SUPPORT_OS_INDICATIONS_CAPSULE_DELIVERY

  Status = gRT->SetVariable (
                  EFI_OS_INDICATIONS_SUPPORT_VARIABLE_NAME,
                  &gEfiGlobalVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  sizeof (UINT64),
                  &OsIndicationsSupported);

  if (mBmHotkeySupport_Count != 0) {
    UPDATE_HOTKEY_STATES (mTextInEx);
  }

  //
  // If the user select "DiagnosticSplash" during P.O.S.T, we don't register
  // the "PAUSE" key here and postpone to the MsTaskDisplayDiagnosticSplashScreen.
  //

  if (mSystemConfiguration.DiagnosticSplash != 1) {
    Status = RegisterPauseHotkey ();
  }

  //
  // Start the clock on the Timeout value. At this point we have initialized
  // ConIn and ConOut, so the user's opportunity to press a hotkey has started.
  //

  mTimeoutValue = (BOOT_ON_S4_RESUME == mBootMode) ? 0: mTimeoutValue;

  //
  // Process with the Connect Device milestone.
  // Depending on the Boot Mode, we may connect some drivers at this time.
  //

  ConnectControllersPerPolicy ();

  //
  // Update the hotkey state before starting any security operations.
  //

  if (mBmHotkeySupport_Count != 0) {
    UPDATE_HOTKEY_STATES (mTextInEx);
  }

  //
  // Start all Credential Providers and the User Manager.
  //

  PERF_START (0, "InitializeSecurity","BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_USER_IDENTIFY, MsTaskInitializeSecurity, NULL, 0);
  PERF_END (0, "InitializeSecurity", "BootManager", 0);

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)
  PERF_START (0, "LegacyInit", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_LEGACY_INIT, MsTaskLegacyInit, NULL, 0);
  PERF_END (0, "LegacyInit", "BootManager", 0);
#endif // OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT

  //
  // Update hot key status later.
  //
  // If updating hot key status right after displaying hot key message,
  // user must press the hot key very very very QUICK.
  // Skip Hotkey status update if resuming from S4.
  //

  if (mBmHotkeySupport_Count != 0) {
    UPDATE_HOTKEY_STATES (mTextInEx);
  }

  //
  // Run the memory tests milestone task. This makes all of memory available.
  //

  PERF_START (0, "RunDiagnostics", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_DIAGNOSTICS, MsTaskRunDiagnostics, NULL, 0);
  PERF_END (0, "RunDiagnostics", "BootManager", 0);

  //
  // BDS Service Tests are a development feature that will display information
  // about the system while exercising the BdsServices.
  //

  BDS_SERVICES_TEST ();

  //
  // Wait for a key press milestone task.
  //

  PERF_START (0, "HotkeyDetect", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_HOTKEY, MsTaskHotkeyDetect, NULL, 0);
  PERF_END (0, "HotkeyDetect", "BootManager", 0);

  //
  // Check if current boot mode is recovery
  // If YES, launch the boot option with SCT_BM_RECOVERY flag first.
  //

  CheckRecoveryBoot ();

  //
  // Disable Progress Indicators.
  //

  mEnableProgress = FALSE;

  //
  // Before entering normal booting process, retrieve all hot-plug devices with
  // SimpleTextInProtocol installed and add their corresponding device path in
  // ConIn variable.
  //

#if OPTION_SYSTEM_BOOT_MANAGER_ADD_HOTPLUG_CON_IN
  AddAllHotPlugConInDeviceToVariable ();
#endif //OPTION_SYSTEM_BOOT_MANAGER_ADD_HOTPLUG_CON_IN

  DPRINTF_BM ("ConnectDevices for Essential ConnectList\n");
  PrepareContextOverrideDriverForEssential ();
  Status = ConnectDevices (mEssentialConnectList);

#if (OPTION_SYSTEM_BOOT_MANAGER_LEGACY_BOOT)

  if (!QuickBootEnabled () &&
    LegacyBootEnabled (NULL) &&
    LoadAllOprom ()) {

    ShadowAllOproms ();
  }

  if (BOOT_ON_S4_RESUME == mBootMode) {

    //
    // Shadow the OPROM devices so that the E820 report can be identical to the
    // previous booting.
    //

    LoadOpromFromDevicePaths (OpromDevicePaths);
  }
#endif

  //
  // Perform Dispatch for those drivers that are still queued by dependencies.
  //

  BmDispatch (FALSE);

  if (mBmHotkeySupport_Count != 0) {
    UPDATE_HOTKEY_STATES (mTextInEx);
  }

  //
  // Prevent from updating HOTKEY message.
  //

  ENABLE_UPDATE_HOTKEY_MSG (FALSE);

  //
  // Restore the original ClearScreen function.
  //

  gST->ConOut->ClearScreen = mOriginalClearScreenFun;

  if (mBmHotkeySupport_Count != 0) {
    CHECK_HOTKEYS (mTextInEx);
  }

#if OPTION_SYSTEM_VIRTUAL_KEYBOARD_SUPPORT

  //
  // Close virtual keyboard service.
  //

  CloseVirtualKeyboard ();
#endif

  //
  // Call Display Splash Screen milestone.
  //

  PERF_START (0, "DisplayDiagnosticSplashScreen", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_DIAGNOSTIC_SPLASH, MsTaskDisplayDiagnosticSplashScreen, NULL, 0);
  PERF_END (0, "DisplayDiagnosticSplashScreen", "BootManager", 0);

#if OPTION_SYSTEM_BOOT_MANAGER_DISPLAY_HOTKEY_PROMPT
  ClearHotkeyPromptString ();
#endif


  //
  // Unregister the Pause Key before we try boot option
  //

  Status = UnRegisterPauseHotkey ();

  //
  // Initialize Boot Fail configuration data.
  //

  BootFailConfigData.FailCount = 0;
  BootFailConfigData.DisableHotkey = FALSE;
  BootFailConfigData.RetryAllBootOption = TRUE;
  BootFailConfigData.PromptString = NULL;
  BootFailConfigData.Reserved = 0;

  //
  // Check if the OS request the BIOS UI interface.
  //

  DataSize = 0;
  Status = SctLibGetVariable (
             EFI_OS_INDICATIONS_VARIABLE_NAME,
             &gEfiGlobalVariableGuid,
             NULL,
             &DataSize,
             (VOID **) &OsIndications);

  if (!EFI_ERROR (Status)) {

    if (*OsIndications & EFI_OS_INDICATIONS_BOOT_TO_FW_UI) {

      //
      // Clear OS_INDICATIONS_BOOT_TO_FW_UI bit and set variable again.
      //

      *OsIndications &= ~EFI_OS_INDICATIONS_BOOT_TO_FW_UI;
      Status = gRT->SetVariable (
                      EFI_OS_INDICATIONS_VARIABLE_NAME,
                      &gEfiGlobalVariableGuid,
                      EFI_VARIABLE_BOOTSERVICE_ACCESS |
                      EFI_VARIABLE_RUNTIME_ACCESS |
                      EFI_VARIABLE_NON_VOLATILE,
                      sizeof (UINT64),
                      OsIndications);


      SafeFreePool (OsIndications);

      //
      // Launch default user interface.
      //

#if OPTION_SYSTEM_BOOT_MANAGER_USB_FULL_INIT_ON_DEMAND

      //
      // Release USB HC control right here before entering UI.
      //

      ReleaseAllUsbHc ();
#endif
      LaunchBuiltInApplication (CONFIG_SYSTEM_BIOS_SETUP_DEVICE_PATH);
    }
  }

  //
  // If there are Password Unlock Error Logs in ErrorManager,
  // show the warning dialog.
  //
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_PASSWORD_UNLOCK, MsTaskNotifyPasswordUnlockError, NULL, 0);

  while (TRUE) {

    //
    // Set BootNext with LastBootCurrent if resuming from S4,
    // then clear LastBootCurrent in case of dead loop.
    //

    if (BootFailConfigData.FailCount == 0) {
#if OPTION_SYSTEM_BOOT_MANAGER_BOOT_FROM_LAST_BOOT_OPTION_AT_S4
      if (BOOT_ON_S4_RESUME == mBootMode && IsBootOrderChanged () == FALSE) {
        Status = SctLibGetVariable (
                   L"LastBootCurrent",
                   &gSctBdsServicesProtocolGuid,
                   NULL,                  // don't care about attributes.
                   NULL,                  // don't care about size.
                   (VOID **) &LastBootCurrentValue);

        if (EFI_SUCCESS == Status) {
          Status = SetEfiGlobalVariable (
                     EFI_BOOT_NEXT_VARIABLE_NAME,
                     EFI_VARIABLE_BOOTSERVICE_ACCESS|
                     EFI_VARIABLE_RUNTIME_ACCESS|
                     EFI_VARIABLE_NON_VOLATILE,
                     sizeof (UINT16),
                     LastBootCurrentValue);

          gRT->SetVariable (
                 L"LastBootCurrent",
                 &gSctBdsServicesProtocolGuid,
                 EFI_VARIABLE_BOOTSERVICE_ACCESS |
                 EFI_VARIABLE_RUNTIME_ACCESS |
                 EFI_VARIABLE_NON_VOLATILE,
                 0,
                 NULL);
        }
      }
#endif
    }

    //
    // Call Connect SysPrep#### milestone.
    //

    PERF_START (0, "ConnectSysPreps", "BootManager", 0);
    SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_CONNECT_SYSPREPS, MsTaskConnectSysPreps, NULL, 0);
    PERF_END (0, "ConnectSysPreps", "BootManager", 0);

    //
    // If the BootNext variable is set we must process it first.
    //

    SCT_MILESTONE_TASK (
      BDS_MILESTONE_TASK_PROCESS_BOOT_NEXT,
      MsTaskProcessBootNextVariable,
      NULL,
      0);

    if (!BootFailConfigData.DisableHotkey) {
      CHECK_HOTKEYS (mTextInEx);
    }

    //
    // Now process the Boot List to find and launch a Boot Device.
    //

    if (BootFailConfigData.RetryAllBootOption) {
      SCT_MILESTONE_TASK (
        BDS_MILESTONE_TASK_PROCESS_BOOT_LIST,
        MsTaskProcessBootOrderVariable,
        NULL,
        0);
    }

    if (!BootFailConfigData.DisableHotkey) {
      CHECK_HOTKEYS (mTextInEx);
    }

    //
    // If all BootOption failed to boot, we should launch the Boot Menu application.
    // But the customer can use the SCT_BDS_MILESTONE_BOOT_FAILED milestone to
    // override the default behavior.
    //

    BootFailConfigData.FailCount++;
#if OPTION_SYSTEM_BOOT_MANAGER_VARIABLE_ROBUST_CHECK

    if (BootFailConfigData.FailCount == 1) {

      VarCheckStatus = CheckBootManagerVariable (
                         TRUE,
                         &gSctBdsServicesProtocolGuid);
      if (EFI_ERROR (VarCheckStatus)) {
        mIsBootOptionDamaged = TRUE;
        ReportBootManagerError ();
        RemoveAllBootManagerVariable ();
        InitializeLoadOptions ();
        INITIALIZE_HOTKEY (mTextInEx);
        mIsBootOptionDamaged = FALSE;
      }
    }
#endif

    SCT_MILESTONE_TASK (
      BDS_MILESTONE_TASK_BOOT_FAILED,
      MsTaskAllBootOptionBootFailed,
      &BootFailConfigData,
      sizeof (BootFailConfigData));
  }

  return SCT_STATUS_SUCCESS;
} // MsTaskBdsEntry


//
// FUNCTION NAME.
//      MsTaskConnectConsoles - Connect consoles for ConIn, ConOut and ErrOut.
//
// FUNCTIONAL DESCRIPTION.
//      Process and update if necessary the ConIn, ConOut and ErrOut
//      variables.
//
//      The device drivers for console devices update the ConInDev and
//      ConOutDev variables and ErrOutDev variables. These variables represent
//      console connection options that are available but not necessarily
//      connected.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskConnectConsoles (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  BOOLEAN Flag = FALSE;         SUPPRESS_WARNING_IF_UNUSED (Flag);
  DPRINTF_BM ("ConnectConsoles:\n");

  //
  // Connect the Output Console.
  // If the output console fails to connect with ConOut try to connect the
  // default console list, per the project settings.
  //

  //
  // Call the update the progress bar milestone.
  //

  if (SeamLessBootFlag() == 0) {
    UpdateProgress (BOOT_MANAGER_PHASE_VIDEO, 0, 1, NULL);
  }

  //
  // Verify all console variables, if error delete, else it makes system hang in binding driver.
  //

  VerifyAllConsoleVariable ();

  //
  // Process with the Out Console milestone.
  //

  PERF_START (0, "ConnectConsoleOut", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_VIDEO_INIT, MsTaskConnectConsoleOut, NULL, 0);
  PERF_END (0, "ConnectConsoleOut", "BootManager", 0);

  //
  // Connect those controllers/devices which need to take long time to
  // initialize first.
  //

  ConnectDevices (mPreemptiveConnectList);

#if OPTION_SYSTEM_CONNECT_USB_HC_BY_SPEED

  //
  // EHCI host controller learns device speed. If device is low/full speed and
  // the hub is an EHCI root hub, the port will be released to its companion
  // controllers.
  //
  // For reducing the redundant time, we connect all USB Host Controller in the
  // order as EHCI first.
  //

  PERF_START (0, "ConnectAllUsbHc", "BootManager", 0);
  ConnectAllUsbHostController ();
  PERF_END (0, "ConnectAllUsbHc", "BootManager", 0);

#endif // (OPTION_SYSTEM_CONNECT_USB_HC_BY_SPEED)

#if OPTION_SUPPORT_TCG
  //
  // Check if the pending TPM request needs user input to confirm and disables showing the splash screen.
  //

  if (TcgPhysicalPresenceLibNeedUserConfirm () || Tcg2PhysicalPresenceLibNeedUserConfirm ()) {
    EFI_INPUT_KEY Key;

    mShowSplashScreen = FALSE;
    //
    // Trigger a ReadKeyStroke so that the USB devices can be initialized.
    //

    gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  }
#endif //OPTION_SUPPORT_TCG

  //
  // Call Display splash screen milestone.
  //

  DPRINTF_BM ("mShowSplashScreen Status :%x:\n", mShowSplashScreen);

  if (mShowSplashScreen) {
#if OPTION_CSM_OPTION_OUT
    if ((mCsmSupported == TRUE) || SeamLessBootFlag()) {
#endif
      PERF_START (0, "DisplaySplashScreen", "BootManager", 0);
      SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_SPLASH, MsTaskDisplaySplashScreen, NULL, 0);
      PERF_END (0, "DisplaySplashScreen", "BootManager", 0);
      Flag = TRUE;
#if OPTION_CSM_OPTION_OUT
    }
#endif
  }

  if (SeamLessBootFlag() == 0) {
#if OPTION_SYSTEM_SCT_ACPI_BGRT
    if (Flag != TRUE) {
      SetBootLogoInvalid ();
    }
#endif
  }

  //
  // Enable Progress Indicators.
  //

  if ((SeamLessBootFlag() == 0) && (mShowSplashScreen)) {
    mEnableProgress = TRUE;
  }

  //
  // Call Hot key display milestone.
  //

  PERF_START (0, "DisplayHotKey", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_HOTKEY_DISPLAY, MsTaskDisplayHotkey, NULL, 0);
  PERF_END (0, "DisplayHotKey", "BootManager", 0);

  //
  // Call the update the progress bar milestone.
  //

  if (SeamLessBootFlag() == 0) {
    UpdateProgress (BOOT_MANAGER_PHASE_VIDEO, 1, 1, NULL);
  }

  //
  // Connect the Input Console milestone.
  //

  if (mConsoleInInitialized == FALSE) {
    PERF_START (0, "ConnectConsoleIn", "BootManager", 0);
    SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_KEYBOARD_INIT, MsTaskConnectConsoleIn, NULL, 0);
    PERF_END (0, "ConnectConsoleIn", "BootManager", 0);
  }

  //
  // Connect the Standard Error Console milestone.
  //

  PERF_START (0, "ConnectErrorOut", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_ERROR_OUT_INIT, MsTaskConnectErrorOut, NULL, 0);
  PERF_END (0, "ConnectErrorOut", "BootManager", 0);

  //
  // call the collect all console milestone
  //

  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_COLLECT_CONSOLE, MsTaskCollectConsole, NULL, 0);

  if (mBmHotkeySupport_Count != 0) {
    UPDATE_HOTKEY_STATES (mTextInEx);
  }

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // ConnectConsoles


//
// FUNCTION NAME.
//      MsTaskConnectConsoleOut - Default task for the ConsoleOut Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      None.
//

SCT_STATUS
MsTaskConnectConsoleOut (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UINTN i;
  UINTN HandleCount;
  SCT_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  PSCT_CONFIGURE_CONSOLE_PROTOCOL p;

  DPRINTF_BM ("ConnectConsoleOut:\n");

  //
  // Connect all PCI devices first.
  //

  ConnectAllPciDevices ();

  //
  // Get all the Configure Console protocol instances.
  //

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctConfigureConsoleProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  //
  // Connect the Output Console. If the output console fails to connect with
  // ConOut try to connect the default console list, per the project settings.
  //

  for (i = 0; i < HandleCount; i++) {
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
    p->ConfigConOut ();
  }

  ConOutInit ();

  //
  // Clean up and return with success.
  //

  SafeFreePool (HandleBuffer);

  return SCT_STATUS_SUCCESS;
} // MSTaskConnectConsoleOut


//
// FUNCTION NAME.
//      MsTaskConnectConsoleIn - Default task for the ConsoleIn Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Keyboard/Mouse Initialization
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskConnectConsoleIn (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UINTN i;
  UINTN HandleCount;
  SCT_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  PSCT_CONFIGURE_CONSOLE_PROTOCOL p;

  DPRINTF_BM ("ConnectConsoleIn:\n");

  //
  // Get all the Configure Console protocol instances.
  //

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctConfigureConsoleProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  //
  // Connect the Input Console.
  //

  for (i = 0; i < HandleCount; i++) {
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
    p->ConfigConIn ();
  }

  ConInInit ();

  SafeFreePool (HandleBuffer);

  //
  // Return with success.
  //

  mConsoleInInitialized = TRUE;
  return SCT_STATUS_SUCCESS;
} // MSTaskConnectConsoleIn


//
// FUNCTION NAME.
//      MsTaskConnectErrorOut - Default task for the ErrOut Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Error Out Initialization
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskConnectErrorOut (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UINTN i;
  UINTN HandleCount;
  SCT_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  PSCT_CONFIGURE_CONSOLE_PROTOCOL p;

  DPRINTF_BM ("ConnectErrorOut:\n");

  //
  // Get all the Configure Console protocol instances.
  //

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctConfigureConsoleProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);

  //
  // Connect the Standard Error Console.
  //

  for (i = 0; i < HandleCount; i++) {
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
    p->ConfigErrOut ();
  }

  ErrOutInit ();

  SafeFreePool (HandleBuffer);

  //
  // Return with success.
  //

  return SCT_STATUS_SUCCESS;
} // MSTaskConnectErrorOut


//
// FUNCTION NAME.
//      MsTaskCollectConsole - Default task for the CollectConsole Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskCollectConsole (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UINTN DataSize;
  EFI_STATUS Status;      SUPPRESS_WARNING_IF_UNUSED (Status);

  DPRINTF_BM ("CollectAllConsole:\n");
  DataSize = 0;

  if (mSystemConRedirect.UcrStatus != SCT_CONSOLE_REDIRECTION_STATUS_DISABLED) {
    Status = GetConsoleByVariable (EFI_CON_OUT_VARIABLE_NAME, &DataSize);
  }

  PERF_START (0, "ConnectDefaultDevices", "BootManager", 0);
  ConnectDefaultDevices ();
  PERF_END (0, "ConnectDefaultDevices", "BootManager", 0);

  PERF_START (0, "CollectAllConsoles", "BootManager", 0);
  CollectAllConsoles ();
  PERF_END (0, "CollectAllConsoles", "BootManager", 0);

  if (mSystemConRedirect.UcrStatus != SCT_CONSOLE_REDIRECTION_STATUS_DISABLED) {
    Status = ConnectConsoleRedirectByVariable (EFI_CON_OUT_VARIABLE_NAME, DataSize);
  }

  return SCT_STATUS_SUCCESS;
} // MsTaskCollectConsole


//
// FUNCTION NAME.
//      MsTaskProcessBootNextVariable - Default task for ProcessBootNextVariable Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task to process BootNext variable.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskProcessBootNextVariable (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  DPRINTF_BM ("MsTaskProcessBootNextVariable:\n");
  ProcessBootNextVariable ();
  return SCT_STATUS_SUCCESS;
} // MsTaskProcessBootNextVariable


//
// FUNCTION NAME.
//      MsTaskProcessBootOrderVariable - Default task for ProcessBootOrderVariable Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task to process BootOrder variable.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskProcessBootOrderVariable (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  DPRINTF_BM ("MsTaskProcessBootOrderVariable:\n");

  ProcessBootList ();

  return SCT_STATUS_SUCCESS;
} // MsTaskProcessBootOrderVariable


//
// FUNCTION NAME.
//      MsTaskAllBootOptionBootFailed - Default task for BootFailed Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task when all BootOption failed to boot.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskAllBootOptionBootFailed (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_STATUS Status;

  DPRINTF_BM ("MsTaskAllBootOptionBootFailed:\n");

  //
  // Show Error Log Message Screen
  //

  Status = EFI_SUCCESS;
  if (ErrorInfoScreen == NULL) {

    Status = gBS->LocateProtocol (
               &gSctErrorScreenTextProtocolGuid,
               NULL,
               (VOID **)&ErrorInfoScreen);
  } // if (ErrorInfoScreen == NULL) {
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Locate gSctErrorScreenTextProtocolGuid Fail.\n");
  } else {
    ErrorInfoScreen->ShowAllErrorMessage (ErrorInfoScreen);
  }

  //
  // Default behavior is launching BootMenu application.
  //

  LaunchBootMenuApplication ();
  return SCT_STATUS_SUCCESS;
} // MsTaskAllBootOptionBootFailed


//
// FUNCTION NAME.
//      MsTaskDisplayHotkey - Default task for the Hotkey Display Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Hotkey display information.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskDisplayHotkey (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  //
  // Display the hotkey messages. This has to happen after we display logo
  // messages. Do not display Hotkeys if resuming from S4.
  //

  if ((!QuickBootEnabled ()) && (mBmHotkeySupport_Count != 0)) {
    DISPLAY_HOTKEY_MESSAGES ();
  }

  return SCT_STATUS_SUCCESS;
} // MSTaskDisplayHotkey


//
// FUNCTION NAME.
//      MsTaskTimeout - Default task for the Timeout Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Timeout that recovers the system in case the operating system
//      fails to boot.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskTimeout (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  PSCT_BDS_MILESTONE_TIMEOUT_DATA TimeoutData = (PSCT_BDS_MILESTONE_TIMEOUT_DATA)MilestoneData;

  if (TimeoutData == NULL)
    return SCT_STATUS_INVALID_PARAMETER;

  //
  // Set the watchdog timer in case the boot failed.
  //

  gBS->SetWatchdogTimer (TimeoutData->Timeout, 0, 0, NULL);

  return SCT_STATUS_SUCCESS;
} // MSTaskTimeout


//
// FUNCTION NAME.
//      MsTaskConnectDrivers - Default task for the Connect Drivers Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Connect Drivers.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskConnectDrivers (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  //
  // The DriverOrder variable defines a list of drivers to be launched.
  // These drivers must be processed first.
  //

  ProcessDriverOrderVariable ();

  return SCT_STATUS_SUCCESS;
} // MSTaskConnectDrivers

//
// FUNCTION NAME.
//      MsTaskSysPreps - Default task for the Connect SysPreps Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Connect SysPreps.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskConnectSysPreps (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  //
  // The SysPrepOrder variable defines a list of drivers to be launched.
  // These drivers must be processed first.
  //

  ProcessSysPrepOrderVariable ();

  return SCT_STATUS_SUCCESS;
} // MSTaskConnectSysPreps

//
// FUNCTION NAME.
//      MsTaskConnectDevices - Default task for the Connect Devices Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Connect Devices.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskConnectDevices (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UINTN i;
  SCT_STATUS Status;

  PSCT_BDS_MILESTONE_CONNECT_DATA pMilestoneConnectData = (PSCT_BDS_MILESTONE_CONNECT_DATA) MilestoneData;

  if (pMilestoneConnectData->ConnectAll) {
    Status = ConnectAllHandlesExceptPciVga ();
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("  ConnectAllHandlesExceptPciVga returned %r.\n", Status);
      return Status;
    }
  } else {

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

    for (i = 0; i < (sizeof (mConnectionPolicy) / sizeof (BOOT_MANAGER_CONNECTION_POLICY)); i++) {
      if (mConnectionPolicy [i].BootMode == pMilestoneConnectData->BootMode) {
        DPRINTF_BM (
          "  mConnectionPolicy [%d].BootMode = 0x%x, mBootMode = 0x%x.\n",
          i,
          mConnectionPolicy [i].BootMode,
          mBootMode);

        Status = ConnectDevices (mConnectionPolicy [i].ConnectionList);
        if (EFI_ERROR (Status)) {
          DPRINTF_BM ("  ConnectDevices returned %r.\n", Status);
          return Status;
        }

        break;
      }
    } // for

  }

  DPRINTF_BM ("ConnectControllersPerPolicy.gDS->Dispatch.\n");
  BmDispatch (FALSE);
  DUMP_ALL_DEVICE_PATHS;

  return SCT_STATUS_SUCCESS;
} // MsTaskConnectDevices


//
// FUNCTION NAME.
//      MsTaskInitializeSecurity - Default task for the Security Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Security Initialization.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskInitializeSecurity (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  InitializeSecurity ();

  return SCT_STATUS_SUCCESS;
} // MSTaskInitializeSecurity



//
// FUNCTION NAME.
//      MsTaskLegacyInit - Default task for the Legacy Initialization Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Legacy Initialization.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskLegacyInit (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  SCT_STATUS Status;

  Status = InitializeLegacy ();
  if (EFI_ERROR (Status)) {
    DPRINTF_BM ("Failed to initialize legacy.\n");
  }

  return SCT_STATUS_SUCCESS;
} // MsTaskLegacyInit


//
// FUNCTION NAME.
//      MsTaskHotkeyDetect - Default task for the Hotkey Detect Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Hotkey Detect.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskHotkeyDetect (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  #if OPTION_SYSTEM_BOOT_MANAGER_KEYPRESS_CHECK_ENABLE
    EFI_TPL Tpl;
    EFI_STATUS Status;
    EFI_EVENT TimeoutEvt;
    Status = EFI_SUCCESS;
    TimeoutEvt = NULL;
    DPRINTF_BM ("  Timeout value is %d\n", mTimeoutValue);

    UpdateProgress (BOOT_MANAGER_PHASE_KEYPRESS, 0, 1, NULL);
    if (mBmHotkeySupport_Count != 0) {

      UPDATE_HOTKEY_STATES (mTextInEx);
      if (mTimeoutValue > 0) {

        Status = gBS->CreateEvent (
                        EVT_TIMER,
                        TPL_CALLBACK,
                        NULL,
                        NULL,
                        &TimeoutEvt);
        if (EFI_ERROR (Status)) {
          return Status;
        }

        Status = gBS->SetTimer (
                        TimeoutEvt,
                        TimerRelative,
                        TIMER_PERIOD_SECONDS (mTimeoutValue));
        if (EFI_ERROR (Status)) {
          return Status;
        }

        //
        // Now we wait until the clock has expired on the Timeout value.
        //

        DPRINTF_BM ("BootManager timeout set to %d seconds. Waiting...\n", mTimeoutValue);
        Tpl = SetTpl (TPL_APPLICATION);
        while (EFI_ERROR (gBS->CheckEvent (TimeoutEvt))) {
          UPDATE_HOTKEY_STATES (mTextInEx);
          if (CHECK_HOTKEY_PRESSED ()) {
            break;
          }
        }
        SetTpl (Tpl);
        if (TimeoutEvt != NULL) {
          gBS->CloseEvent (TimeoutEvt);
        }
        DPRINTF_BM ("BootManager timeout wait complete.\n");
      }
    }
  #endif //OPTION_SYSTEM_BOOT_MANAGER_KEYPRESS_CHECK_ENABLE

  UpdateProgress (BOOT_MANAGER_PHASE_KEYPRESS, 1, 1, NULL);
  return SCT_STATUS_SUCCESS;
} // MSTaskHotkeyDetect


//
// FUNCTION NAME.
//      MsTaskRunDiagnostics - Default task for the Diagnostic Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Diagnostic memory test.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskRunDiagnostics (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UpdateProgress (BOOT_MANAGER_PHASE_MEMORY, 0, 1, NULL);
  RunDiagnostics ();
  UpdateProgress (BOOT_MANAGER_PHASE_MEMORY, 1, 1, NULL);

  return SCT_STATUS_SUCCESS;
} // MSTaskRunDiagnostics


//
// FUNCTION NAME.
//      MsTaskDisplaySplashScreen - Default task for the Splash Screen Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Splash Screen display.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskDisplaySplashScreen (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  UINTN i;
  UINTN j;
  INT32 Index;
  UINTN Columns;
  UINTN Rows;
  SCT_STATUS Status;
  BOOLEAN IsGopModeChanged;
  BOOLEAN IsPreferredGopModeFound = FALSE;
  SUPPRESS_WARNING_IF_UNUSED (IsGopModeChanged);
  SUPPRESS_WARNING_IF_UNUSED (IsPreferredGopModeFound);

  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  PSCT_IMAGE_PACKAGE_PROTOCOL Temp;
  PSCT_IMAGE_PACKAGE_PROTOCOL *ImagePackage; // An array of pointers, unknown size.
  SCT_DIAGNOSTIC_SPLASH_PROTOCOL *DiagnosticSplash;

  UINT32 ModeNumber;
  UINTN SizeOfInfo;
  EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;

  SCT_SYSTEM_VIDEO_RESOLUTION DefaultVideoResolutionTable [] = {
    CONFIG_VrTable                      // Default video resolution table defined in Module.def.
  };

  SCT_SYSTEM_VIDEO_RESOLUTION *VideoResolutionTable;
  SCT_SYSTEM_VIDEO_RESOLUTION *TempVideoResolutionTable;
  SCT_CONSOLE_RESOLUTION_POLICY_PROTOCOL *SctConsoleResolutionPolicy = NULL;

  //
  // Display the splash screen, per system configuration.
  //

  if (SeamLessBootFlag() == 0) {
    if (QuickBootEnabled ()) {
#if OPTION_SYSTEM_SCT_ACPI_BGRT
      SetBootLogoInvalid ();
#endif
      return SCT_STATUS_SUCCESS;
    }
  }

  //
  // Check GOP driver ready. if not ready maybe it is a extended VGA
  // the GOP driver will be installed in MsTaskLoadDeferredImage.
  //
  Status = gBS->HandleProtocol (
                  gST->ConsoleOutHandle,
                  &gEfiGraphicsOutputProtocolGuid,
                  (VOID **) &Gop);
  if (EFI_ERROR (Status)) {
    DPRINTF_BM (" Gop Driver not ready.\n");
    return EFI_NOT_READY;
  }
  DPRINTF_BM ("DisplaySplashScreen:\n");

  if (mSystemConfiguration.DiagnosticSplash == 1) {

    DPRINTF_BM ("  Do Diagnostic Splash.\n");

    Status = gBS->LocateProtocol (
                    &gSctDiagnosticSplashProtocolGuid,
                    NULL,
                    (VOID **) &DiagnosticSplash);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("  Problem finding Diagnostic Splash Protocol %r.\n", Status);
      goto NORMAL_SPLASH;
    } else {

      //
      // Since the user expects all devices can be presented in the system so
      // BootManager connects all handles before starting splash screen.
      //

      if (mConsoleInInitialized == FALSE) {
        PERF_START (0, "ConnectConsoleIn", "BootManager", 0);
        SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_KEYBOARD_INIT, MsTaskConnectConsoleIn, NULL, 0);
        PERF_END (0, "ConnectConsoleIn", "BootManager", 0);
      }

#if OPTION_SYSTEM_SCT_ACPI_BGRT
      SetBootLogoInvalid ();
#endif
      return Status;
    }
  }

NORMAL_SPLASH:
  DPRINTF_BM ("  Do Normal Splash.\n");

  //
  // Get all the Image Packages.
  // Exit immediately if there are none.
  //

  //
  // Call Dispatch again so that the dependency satisfied drivers can be loaded.
  //

  BmDispatch (FALSE);

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctImagePackageProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  if ((EFI_ERROR (Status)) || (HandleCount == 0)) {
    DPRINTF_BM ("  No Image Packages found.\n");
#if OPTION_SYSTEM_SCT_ACPI_BGRT
    SetBootLogoInvalid ();
#endif
    return SCT_STATUS_SUCCESS;
  }

  SCT_GOP_USE_BEGIN(GopContext);
  SctGetGopByHandle (gST->ConsoleOutHandle, &Gop);
  if (Gop == NULL) {
    DPRINTF_ERROR ("  Queries GOP handle Not found.\n");
#if OPTION_SYSTEM_SCT_ACPI_BGRT
    SetBootLogoInvalid ();
#endif
    SCT_GOP_USE_END(GopContext);
    return SCT_STATUS_SUCCESS;
  }

  //
  // Try to find the mode number for each of resolutions listed in the VrTable
  // until SetMode success.
  //

  VideoResolutionTable = DefaultVideoResolutionTable;

  gBS->LocateProtocol (&gSctConsoleResolutionPolicyProtocolGuid, NULL, (VOID **) &SctConsoleResolutionPolicy);
  if ((SctConsoleResolutionPolicy != NULL) &&
      (SctConsoleResolutionPolicy->SplashScreen.Valid == TRUE)) {
    TempVideoResolutionTable = AllocatePool ((sizeof (DefaultVideoResolutionTable)) + (sizeof (SCT_SYSTEM_VIDEO_RESOLUTION)));
    if (TempVideoResolutionTable != NULL) {
      TempVideoResolutionTable->XRes = SctConsoleResolutionPolicy->SplashScreen.XRes;
      TempVideoResolutionTable->YRes = SctConsoleResolutionPolicy->SplashScreen.YRes;
      CopyMem (TempVideoResolutionTable + 1, &DefaultVideoResolutionTable, sizeof(DefaultVideoResolutionTable));
      VideoResolutionTable = TempVideoResolutionTable;
    }
  }

  //
  // Do not set preferred mode when the console redirection enabled
  //

  IsGopModeChanged = FALSE;
  if (mSystemConRedirect.UcrStatus == SCT_CONSOLE_REDIRECTION_STATUS_DISABLED) {
    for (i = 0; VideoResolutionTable [i].XRes != 0; i++) {

      //
      // Find the mode number and try to set mode.
      //

      for (ModeNumber = 0; ModeNumber < Gop->Mode->MaxMode; ModeNumber++) {
        Status = Gop->QueryMode (
                        Gop,
                        ModeNumber,
                        &SizeOfInfo,
                        &Info);
        if (!EFI_ERROR (Status)) {
          if ((Info->HorizontalResolution == VideoResolutionTable [i].XRes) &&
              (Info->VerticalResolution == VideoResolutionTable [i].YRes)) {
            if ((Gop->Mode->Info->HorizontalResolution != VideoResolutionTable [i].XRes) ||
                (Gop->Mode->Info->VerticalResolution   != VideoResolutionTable [i].YRes)) {
              Status = Gop->SetMode (Gop, ModeNumber);
              if (!EFI_ERROR (Status)) {
                IsGopModeChanged = TRUE;
              }
            }
            if (!EFI_ERROR (Status)) {
              FreePool (Info);
              IsPreferredGopModeFound = TRUE;
              break;
            }
          }
          FreePool (Info);
        }
      }

      //
      // Try next resolution if SetMode is not successful.
      //

      if (ModeNumber != Gop->Mode->MaxMode) {
        break;
      }
    }

    //
    // Synchronize the text mode.
    //
#if OPTION_SYSTEM_CONSOLE_GRAPHICS_MODE0_1_RESOLUTION_COMPATIBILITY
    if (IsGopModeChanged == TRUE) {
#else
    if (IsPreferredGopModeFound == TRUE) {
#endif

      DPRINTF_BM (" GOP Mode changed to %d x %d\n",
        VideoResolutionTable [i].XRes,
        VideoResolutionTable [i].YRes);

      for (Index = 0; Index < gST->ConOut->Mode->MaxMode; Index++) {
        Status = gST->ConOut->QueryMode (gST->ConOut, Index, &Columns, &Rows);
        if (EFI_ERROR (Status)) {
          continue;
        }

        if (Columns == VideoResolutionTable [i].XRes / CONFIG_SYSTEM_CONSOLE_GRAPHICS_GLYPH_WIDTH &&
          Rows == VideoResolutionTable [i].YRes / CONFIG_SYSTEM_CONSOLE_GRAPHICS_GLYPH_HEIGHT) {
          if (Index == gST->ConOut->Mode->Mode) {
            DPRINTF_BM ("It's the same text mode, Mode=%d. Don't set mode \n", Index);
            break;
          }
          DPRINTF_BM (" Set text mode as %d\n", Index);
          gST->ConOut->SetMode (gST->ConOut, Index);
          break;
        }
      }
      if (Index == gST->ConOut->Mode->MaxMode) {
        DPRINTF_BM (" Fail to find matched text mode\n");
      }
    }
  }

  SCT_GOP_USE_END(GopContext);

  if (VideoResolutionTable != DefaultVideoResolutionTable) {
    FreePool (VideoResolutionTable);
  }

  if (EFI_ERROR (Status)) {
#if OPTION_SYSTEM_SCT_ACPI_BGRT
    SetBootLogoInvalid ();
#endif
    return Status;
  }

  //
  // Create an array for all the protocol pointers.
  // Then fill out the array with pointers to all the protocol instances.
  //

  ImagePackage = AllocateZeroPool (
                   HandleCount * sizeof (PSCT_IMAGE_PACKAGE_PROTOCOL));
  for (i = 0; i < HandleCount; i++) {
    Status = gBS->OpenProtocol (
                    HandleBuffer [i],
                    &gSctImagePackageProtocolGuid,
                    (VOID **) &(ImagePackage [i]),
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("  There was a problem with an image package.\n");
      ImagePackage [i] = NULL;
    }
  }

  //
  // Sort the Image Packages by ZValue.
  // Bubble Sort.
  //

  for (i = HandleCount - 1; i > 0; i--) {
    for (j = 0; j < i; j++) {
      if ((ImagePackage [j])->ZValue > (ImagePackage [j + 1])->ZValue) {
        Temp = ImagePackage [j];
        ImagePackage [j] = ImagePackage [j + 1];
        ImagePackage [j + 1] = Temp;
      }
    }
  }

  //
  // Hide cursor before displaying splash.
  //

  gST->ConOut->EnableCursor (gST->ConOut, FALSE);

  //
  // Display all the Image Packages.
  //

  for (i = 0; i < HandleCount; i++) {
    if (ImagePackage [i] == NULL) {
      continue;
    }
    (ImagePackage [i])->Display (ImagePackage [i]);
  }

  SafeFreePool (ImagePackage);
  SafeFreePool (HandleBuffer);
  return Status;
} // MSTaskDisplaySplashScreen


//
// FUNCTION NAME.
//      MsTaskUpdateProgress - Default task for the Progress Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//      Progress display.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskUpdateProgress (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  PSCT_BDS_MILESTONE_PROGRESS_DATA ProgressData = (PSCT_BDS_MILESTONE_PROGRESS_DATA)MilestoneData;
  SCT_STATUS Status;
  UINTN i;
  UINT64 Progress;
  UINTN HandleCount;
  EFI_HANDLE *HandleBuffer;
  PSCT_PROGRESS_INDICATOR_PROTOCOL ProgressIndicator;

  if (ProgressData == NULL) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // To determine if Diagnostic Splash is enabled,
  //

#if OPTION_SUPPORT_DIAGNOSTIC_SPLASH
  if (mSystemConfiguration.DiagnosticSplash == 1) {
    return SCT_STATUS_SUCCESS;
  }
#endif

  if (!mEnableProgress) {
    return SCT_STATUS_SUCCESS;
  }

  if (QuickBootEnabled ()) {
    return SCT_STATUS_SUCCESS;
  }

  DPRINTF_BM (
    "UpdateProgress: Phase %d: 0x%x / 0x%x: %s.\n",
    ProgressData->Phase,
    ProgressData->Complete,
    ProgressData->Total,
    ProgressData->Indicator);

  //
  // Check Phase to make sure it is not too big for mPhaseTable.
  //

  if (ProgressData->Phase >= (sizeof (mPhaseTable) / sizeof (BOOT_MANAGER_PHASE_TABLE_ENTRY))) {
    return SCT_STATUS_INVALID_PARAMETER;
  }

  //
  // Calculate the new Progress. Don't update mProgress yet.
  //

  if (ProgressData->Total == 0) {

    //
    // Advance mProgress by Completed.
    //

    if ((mProgress + ProgressData->Complete) > mPhaseTable [ProgressData->Phase].PhaseEnd) {
      Progress = mPhaseTable [ProgressData->Phase].PhaseEnd;
    } else {
      Progress = mProgress + ProgressData->Complete;
    }

  } else if (ProgressData->Complete > ProgressData->Total) {

    //
    // This is an improper use of Completed. It should never be greater than
    // Total. We will force the Progress to the end of phase.
    //

    Progress = mPhaseTable [ProgressData->Phase].PhaseEnd;

  } else {

    //
    // Scale this progress into the total progress.
    // (Completed * (End - Start) / Total) + Start.

    Progress = MultU64x32 (
                 ProgressData->Complete,
                 (mPhaseTable [ProgressData->Phase].PhaseEnd - mPhaseTable [ProgressData->Phase].PhaseStart));
    Progress = DivU64x64Remainder (Progress, ProgressData->Total, NULL);
    Progress += mPhaseTable [ProgressData->Phase].PhaseStart;
  }

  //
  // We only update the progress if it moved forward.
  //

  if (Progress > mProgress) {
    mProgress = Progress;
  } else {

    //
    // Exit early if no progress was made.
    //

    return SCT_STATUS_SUCCESS;
  }
  DPRINTF_BM ("  mProgress 0x%x.\n", mProgress);

  //
  // Get all the Progress Indicators.
  // Exit immediately if there are none.
  //

  HandleCount = 0;
  HandleBuffer = NULL;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gSctProgressIndicatorProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer);
  if ((EFI_ERROR (Status)) || (HandleCount == 0)) {
    DPRINTF_BM ("  No Progress Indicators found.\n");
    return SCT_STATUS_SUCCESS;
  }

  //
  // Update all the Progress Indicators.
  //

  for (i = 0; i < HandleCount; i++) {
    Status = gBS->OpenProtocol (
                    HandleBuffer [i],
                    &gSctProgressIndicatorProtocolGuid,
                    (VOID **) &ProgressIndicator,
                    mImageHandle,
                    NULL,
                    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM (
        "  There was a problem opening a Progress Indicator, %r.\n",
        Status);
      continue;
    }

    Status = ProgressIndicator->Update (
                                  (UINTN)mProgress,
                                  BOOT_MANAGER_PHASE_TOTAL,
                                  ProgressData->Indicator);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM (
        "  There was a problem updating Progress Indicator, %r.\n",
        Status);
      continue;
    }
  }

  return SCT_STATUS_SUCCESS;
} // MsTaskUpdateProgress


//
// FUNCTION NAME.
//      MsTaskUpdateHotkeySupportCount - Get the current boot mode.
//
// FUNCTIONAL DESCRIPTION.
//      This function will check the mBootMode and the SystemConfiguration
//      and will update mBmHotkeySupport_Count.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
MsTaskUpdateHotkeySupportCount (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_STATUS Status;

  UINT32  Attributes;
  UINTN   DataSize;
  UINT32  *DataValue = NULL;
  UINT32  BootOptionSupport;

  Status = SctLibGetEfiGlobalVariable (EFI_BOOT_OPTION_SUPPORT_VARIABLE_NAME, &Attributes, &DataSize, (VOID **) &DataValue);
  if ( (Status != EFI_SUCCESS) || (DataValue == NULL) ) {
    Status = EFI_LOAD_ERROR;
    ASSERT_EFI_ERROR (Status);
  }
  BootOptionSupport = *DataValue;
  SafeFreePool(DataValue);
  DPRINTF (" BootOptionSupport, 0x%08x.\n",  BootOptionSupport);

  if (mBootMode != BOOT_ON_S4_RESUME) {
    return EFI_SUCCESS;
  } else {
    if (CONFIG_SYSTEM_BOOT_MANAGER_HOTKEY_IN_S4_RESUME) {
      return EFI_SUCCESS;
    } else {
      BootOptionSupport &=  ~EFI_BOOT_OPTION_SUPPORT_KEY;
      Status = SetEfiGlobalVariable (EFI_BOOT_OPTION_SUPPORT_VARIABLE_NAME, Attributes, DataSize, &BootOptionSupport);
      ASSERT_EFI_ERROR (Status);
    }
  }

  if (mSystemConfiguration.CheckHotkeyS4 !=0) {
    return EFI_SUCCESS;
  } else {
    BootOptionSupport &=  ~EFI_BOOT_OPTION_SUPPORT_KEY;
    Status = SetEfiGlobalVariable (EFI_BOOT_OPTION_SUPPORT_VARIABLE_NAME, Attributes, DataSize, &BootOptionSupport);
    ASSERT_EFI_ERROR (Status);
  }

  return Status;
} // MsTaskUpdateCheckHotkey


//
// FUNCTION NAME.
//      MsTaskDisplayDiagnosticSplashScreen - Default task for the Diagnostic Splash Screen Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone of
//      displaying Diagnostic Splash Screen.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskDisplayDiagnosticSplashScreen (
  IN VOID *MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  SCT_STATUS Status;
  EFI_KEY_DATA KeyData;
  SCT_DIAGNOSTIC_SPLASH_PROTOCOL *DiagnosticSplash;

  Status = SCT_STATUS_SUCCESS;

  //
  // Display the splash screen, per system configuration.
  //

  if (QuickBootEnabled () || mSystemConfiguration.DiagnosticSplash == 0) {
    return SCT_STATUS_SUCCESS;
  }

  DPRINTF_BM ("  Do Diagnostic Splash.\n");
  mTextInEx->ReadKeyStrokeEx (mTextInEx, &KeyData);

  Status = gBS->LocateProtocol (
                  &gSctDiagnosticSplashProtocolGuid,
                  NULL,
                  (VOID **) &DiagnosticSplash);
  if (!EFI_ERROR (Status)) {

    Status = RegisterPauseHotkey ();
    ConnectAllHandlesExceptPciVga ();
    Status = DiagnosticSplash->Start (
                                 DiagnosticSplash,
                                 SCT_DIAGNOSTIC_SPLASH_FOOTERSTRING_SETUP);

#if OPTION_SYSTEM_BOOT_MANAGER_KEYPRESS_CHECK_ENABLE
    {
      EFI_EVENT TimeoutEvt;
      UINT8 DurationInSecond;

      //
      // Give another chance to allow the user to press HotKey.
      //

      Status = gBS->CreateEvent (
                      EVT_TIMER,
                      TPL_CALLBACK,
                      NULL,
                      NULL,
                      &TimeoutEvt);
      if (EFI_ERROR (Status)) {
        return Status;
      }

      DurationInSecond = CONFIG_SYSTEM_BOOT_MANAGER_DURATION_OF_DIAGNOSTIC_SPLASH;
      if (DurationInSecond <= 0) {
        DurationInSecond = 2;             // 2 seconds at least for visibility.
      }

      Status = gBS->SetTimer (
                      TimeoutEvt,
                      TimerRelative,
                      TIMER_PERIOD_SECONDS (DurationInSecond));
      if (EFI_ERROR (Status)) {
        return Status;
      }

      //
      // Now we wait until the clock has expired on the Timeout value.
      //

      while (EFI_ERROR (gBS->CheckEvent (TimeoutEvt))) {
        if (mBmHotkeySupport_Count != 0) {
          UPDATE_HOTKEY_STATES (mTextInEx);
        } else {
          mTextInEx->ReadKeyStrokeEx (mTextInEx, &KeyData);
        }
      }

      if (TimeoutEvt != NULL) {
        gBS->CloseEvent (TimeoutEvt);
      }
    }
#endif //OPTION_SYSTEM_BOOT_MANAGER_KEYPRESS_CHECK_ENABLE

    //
    // Stop display the diagnostic splash screen.
    //

    EndDisplaySplashScreen ();

    if (mBmHotkeySupport_Count != 0) {
      CHECK_HOTKEYS (mTextInEx);
    }

  }

  return Status;
} // MsTaskDisplayDiagnosticSplashScreen


//
// FUNCTION NAME.
//      ConfigUefiNetworkStackDriver - Load UEFI Network Stack according to system configuration.
//
// FUNCTIONAL DESCRIPTION.
//      This function will load the partial or all drivers related to UEFI
//      network stack according to system configuration.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

static
SCT_STATUS
ConfigUefiNetworkStackDriver (VOID)
{
  BOOLEAN EnableNetworkStack;
  EnableNetworkStack = FALSE;

  DPRINTF_FUNCTION_ENTRY();

  if (mSystemConfiguration.NetworkStack == FALSE) {
    BmUnloadImages (mNetworkEssentialFvFile);
    BmUnloadImages (mNetworkIpV4FvFile);
    BmUnloadImages (mNetworkIpV6FvFile);
    return EFI_SUCCESS;
  }

  if (mSystemConfiguration.UefiBoot == 1 &&
    mSystemConfiguration.LegacyBoot == 1) {

    if (mSystemConfiguration.BootPriority == 0) {
      EnableNetworkStack = TRUE;
    }

  } else if (mSystemConfiguration.UefiBoot == 1) {

    EnableNetworkStack = TRUE;

  }

#if OPTION_CSM_OPTION_OUT

  switch (mSystemConfiguration.CsmSupport) {

    case CSM_SUPPORT_NO:                // CSM Not Support.
#if OPTION_CSM_AUTO_OPTION
    case CSM_SUPPORT_AUTO:              // Auto-Detection.
#endif
      EnableNetworkStack = TRUE;
      break;
    case CSM_SUPPORT_YES:               // CSM Support.
      break;
  }

#endif

  if (EnableNetworkStack == FALSE) {
    BmUnloadImages (mNetworkEssentialFvFile);
    BmUnloadImages (mNetworkIpV4FvFile);
    BmUnloadImages (mNetworkIpV6FvFile);
    return EFI_SUCCESS;
  }

  //
  // If Network stack is enabled, decompress the FV which may contain the UEFI Network Drivers first.
  //

  if (EnableNetworkStack) {
    DPRINTF ("  Decompress Network firmware volume.\n");
    DecompressOptionalFirmwareVolume (SCT_FIRMWAREVOLUME_TYPE_NETWORK);
  }

  //
  // Unload IPv6 related UEFI drivers if IPv6 is disabled.
  //

  if (!mSystemConfiguration.IpV6) {
    BmUnloadImages (mNetworkIpV6FvFile);
  }

  //
  // Unload IPv4 related UEFI drivers if IPv4 is disabled.
  //

  if (!mSystemConfiguration.IpV4) {
    BmUnloadImages (mNetworkIpV4FvFile);
  }

  //
  // Unload Network related UEFI drivers if both IPv4 and IPv6 are disabled.
  //

  if (!mSystemConfiguration.IpV6 && !mSystemConfiguration.IpV4) {
    BmUnloadImages (mNetworkEssentialFvFile);
  }

  return EFI_SUCCESS;

} // ConfigUefiNetworkStackDriver

//
// FUNCTION NAME.
//      BmClearScreen - Hooked function for default ClearScreen.
//
// FUNCTIONAL DESCRIPTION.
//      This function will hook the original ClearScreen function to detect if
//      anyone has cleared the screen during P.O.S.T.
//
// ENTRY PARAMETERS.
//      Sto             - pointer points to EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

EFI_STATUS
EFIAPI
BmClearScreen (IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Sto)
{

  //
  // Restore the previous ClearScreen function.
  //

  gST->ConOut->ClearScreen = mOriginalClearScreenFun;

  //
  // Since the screen has been cleared during P.O.S.T, do not display progress
  // bar and HOTKEY message anymore.
  //

  mEnableProgress = FALSE;

  ENABLE_UPDATE_HOTKEY_MSG (FALSE);

  return gST->ConOut->ClearScreen (gST->ConOut);

} // BmClearScreen

//
// FUNCTION NAME.
//      BmConnectAll - Connect all current system handles.
//
// FUNCTIONAL DESCRIPTION.
//      This function will invoke gBS->Controller() for each handle exists in
//      system handle buffer.
//
//      This function should be ONLY invoked after BmDisconnectAll is called.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - None.
//

VOID
EFIAPI
BmConnectAll (VOID)
{
  //
  // Connect console devices first.
  //

  PERF_START (0, "ConnectConsoleOut", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_VIDEO_INIT, MsTaskConnectConsoleOut, NULL, 0);
  PERF_END (0, "ConnectConsoleOut", "BootManager", 0);

  PERF_START (0, "ConnectConsoleIn", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_KEYBOARD_INIT, MsTaskConnectConsoleIn, NULL, 0);
  PERF_END (0, "ConnectConsoleIn", "BootManager", 0);

  PERF_START (0, "ConnectErrorOut", "BootManager", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_ERROR_OUT_INIT, MsTaskConnectErrorOut, NULL, 0);
  PERF_END (0, "ConnectErrorOut", "BootManager", 0);

  ConnectAllHandlesExceptPciVga ();

} // BmConnectAll

//
// FUNCTION NAME.
//      LoadSetupModules - Load Setup related modules.
//
// FUNCTIONAL DESCRIPTION.
//      This function will load all necessary modules for setup based on current setting.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI Status Code.
//

EFI_STATUS
LoadSetupModules (VOID)
{
  UINT8 Mode;
  UINT8 *Data;
  EFI_STATUS Status;
  CURRENT_VIEW CurrentView;
  EFI_GUID *FvFileName = mTextViewFvFile;
  EFI_GUID SctSelectViewGuid = SCT_SELECT_VIEW_GUID;

  Mode = TEXT_VIEW;
  Data = NULL;

  RegisterEventNotifications ();

  //
  // Force text mode if UCR is enabled.
  //

  if (IsUcrEnabled () == FALSE) {

    //
    // GUI + Text View. or GUI + Graphic View.
    //

    Data = SctLibGetVariableAndSize (
             SELECT_VIEW_VARIABLE_NAME,
             &gSctSelectViewGuid,
             NULL);

    if (Data == NULL) {
      Mode = TEXT_VIEW;
    } else {
      Mode = *Data;
      FreePool (Data);
    }

  } // IF UCR DISABLED.

  do {
    CurrentView.ViewType = Mode;
    gRT->SetVariable (
           CURRENT_VIEW_VARIABLE_NAME,
           &SctSelectViewGuid,
           EFI_VARIABLE_BOOTSERVICE_ACCESS,
           sizeof (CURRENT_VIEW),
           &CurrentView);

    switch (Mode) {
      case TEXT_VIEW:
        FvFileName = mTextViewFvFile;
        break;

      case GRAPHIC_VIEW:
        FvFileName = mGraphicViewFvFile;
        break;

      case METRO_VIEW:
        FvFileName = mGuiViewFvFile;
        break;
    }

    Status = RequestDrivers (
               mFvHandle,
               FvFileName,
               SCT_FIRMWAREVOLUME_TYPE_MAIN,
               FALSE);
    if (EFI_ERROR (Status) && (Mode == METRO_VIEW)) {
      Mode = TEXT_VIEW;
    } else {
      break;
    }

  } while(TRUE);

  return Status;
} // LoadSetupModules

//
// FUNCTION NAME.
//      MsTaskAfterReadyToBoot - Default task for the AfterReadyToBoot  Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function will process the default task for the milestone
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskAfterReadyToBoot (
  IN VOID *MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{

  UINT8 ResetFlag;

  ResetFlag = SctGetResetFlagFirstBoot();

  while (ResetFlag) {
    SctCleanResetFlagFirstBoot();
    DPRINTF ("\n System is going to Reset........\n\n\n\n");
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0 , NULL);
  }

  //Do nothing
  return SCT_STATUS_SUCCESS;
} // MsTaskAfterReadyToBoot

//
// FUNCTION NAME.
//      MsTaskLoadDeferredImage - Default task for LoadDeferredImage Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task to Load Deferred Image.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskLoadDeferredImage (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  DPRINTF_BM ("MsTaskLoadDeferredImage:\n");
  LoadDeferredImage ();
  return SCT_STATUS_SUCCESS;
} // MsTaskLoadDeferredImage

#if OPTION_SUPPORT_TCG
//
// FUNCTION NAME.
//      MsTaskMemoryOverwriteControl - Default task for MemoryOverwriteControl Milestone.
//
// FUNCTIONAL DESCRIPTION.
//      This function is called if Boot Manager want to execute the default
//      task to fo for MemoryOverwriteControl.
//
// ENTRY PARAMETERS.
//      MilestoneData   - Additional data for the milestone task to process.
//      MilestoneDataSize - Size of the additional data.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//

SCT_STATUS
MsTaskMemoryOverwriteControl (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  )
{
  EFI_STATUS Status;

  DPRINTF_BM ("MsTaskMemoryOverwriteControl:\n");
  if (IsMorBitSet ()) {
    Status = ConnectDevices (mMORDeviceResetConnectList);
    if (EFI_ERROR (Status)) {
      DPRINTF_BM ("  ConnectDevices returned %r.\n", Status);
      return Status;
    }

  }
  return SCT_STATUS_SUCCESS;
} // MsTaskMemoryOverwriteControl
#endif //if OPTION_SUPPORT_TCG

VOID
EFIAPI
BmSetupBootMenuCallback (
  IN EFI_EVENT Event,
  IN VOID *Context
  )
{
  if (((UINTN)Context == (UINTN)mSetupMenuEntryContext) ||
      ((UINTN)Context == (UINTN)mBootMenuEntryContext)) {
    IsInSetupOrBootMenu = TRUE;
  } else {
    IsInSetupOrBootMenu = FALSE;
  }

  return;
}

//
// FUNCTION NAME.
//      RegisterEventNotifications - Create named event listeners
//
// FUNCTIONAL DESCRIPTION.
//      This function will register notification event for setup and
//      boot menu entry/exit.
//
// ENTRY PARAMETERS.
//      None
//
// EXIT PARAMETERS.
//      None
//

VOID
RegisterEventNotifications (
  VOID
  )
{
  mSetupMenuEntryContext = (UINT8 *)AllocateZeroPool (sizeof (UINT8));
  mSetupMenuExitContext = (UINT8 *)AllocateZeroPool (sizeof (UINT8));
  mBootMenuEntryContext = (UINT8 *)AllocateZeroPool (sizeof (UINT8));
  mBootMenuExitContext = (UINT8 *)AllocateZeroPool (sizeof (UINT8));

  if ((mSetupMenuEntryContext == NULL) ||
      (mSetupMenuExitContext == NULL) ||
      (mBootMenuEntryContext == NULL) ||
      (mBootMenuExitContext == NULL))
  {
    DPRINTF_BM (" Out of resource!\n");

    if (mSetupMenuEntryContext != NULL) {
      FreePool (mSetupMenuEntryContext);
      mSetupMenuEntryContext = NULL;
    }
    if (mSetupMenuExitContext != NULL) {
      FreePool (mSetupMenuExitContext);
      mSetupMenuExitContext = NULL;
    }
    if (mBootMenuEntryContext != NULL) {
      FreePool (mBootMenuEntryContext);
      mBootMenuEntryContext = NULL;
    }
    if (mBootMenuExitContext != NULL) {
      FreePool (mBootMenuExitContext);
      mBootMenuExitContext = NULL;
    }

    return;
  }

  EfiNamedEventListen (
    &gEfiHiiPlatformSetupFormsetGuid,
    TPL_CALLBACK,
    BmSetupBootMenuCallback,
    (VOID *)mSetupMenuEntryContext,
    NULL
    );

  EfiNamedEventListen (
    &gSctHiiPlatformSetupDoneGuid,
    TPL_CALLBACK,
    BmSetupBootMenuCallback,
    (VOID *)mSetupMenuExitContext,
    NULL
    );

  EfiNamedEventListen (
    &gSctBootMenuEntryGuid,
    TPL_CALLBACK,
    BmSetupBootMenuCallback,
    (VOID *)mBootMenuEntryContext,
    NULL
    );

  EfiNamedEventListen (
    &gSctBootMenuExitGuid,
    TPL_CALLBACK,
    BmSetupBootMenuCallback,
    (VOID *)mBootMenuExitContext,
    NULL
    );

  return;
}