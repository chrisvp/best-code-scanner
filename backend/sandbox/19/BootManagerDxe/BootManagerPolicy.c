//
// FILENAME.
//      BootManagerPolicy.c - SecureCore Technology(TM) BootManagerPolicy in the Boot Manager.
//
// FUNCTIONAL DESCRIPTION.
//      This module produces Boot Manager Policy protocol.
//
// NOTICE.
//      Copyright (C) 2016-2024 Phoenix Technologies.  All Rights Reserved.
//

//
// Include standard header files.
//


#include "Meta.h"

//
// Data defined in other modules and used by this module.
//

extern DRIVER_OBJECT mBootManager;

SCT_STATUS
EFIAPI
ConnectAllHandles (VOID);

EFI_STATUS
EFIAPI
ConnectAllHandlesExceptPciVga (VOID);


CHAR16 mNetworkDeviceList[] = L"_NDL";

//
// FUNCTION NAME.
//      ConnectAllAndCreateNetworkDeviceList - Connect all drivers and create the network device list.
//
// FUNCTIONAL DESCRIPTION.
//      This function Connect all the system drivers to controllers and create the
//      network device list in NV storage.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//                        EFI_SUCCESS Network devices are connected.
//                        EFI_DEVICE_ERROR No network device is connected.
//

EFI_STATUS
ConnectAllAndCreateNetworkDeviceList (
  VOID
  )
{
  UINTN HandleCount;
  EFI_STATUS Status;
  EFI_HANDLE *Handles;
  EFI_DEVICE_PATH_PROTOCOL *Devices;
  EFI_DEVICE_PATH_PROTOCOL *SingleDevice;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;

  BmConnectAll ();

  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiManagedNetworkServiceBindingProtocolGuid, NULL, &HandleCount, &Handles);
  if (EFI_ERROR (Status)) {
    Handles = NULL;
    HandleCount = 0;
  }

  Devices = NULL;
  while (HandleCount-- != 0) {
    Status = gBS->HandleProtocol (Handles[HandleCount], &gEfiDevicePathProtocolGuid, (VOID **) &SingleDevice);
    if (EFI_ERROR (Status) || (SingleDevice == NULL)) {
      continue;
    }
    TempDevicePath = Devices;
    Devices = AppendDevicePathInstance (Devices, SingleDevice);
    if (TempDevicePath != NULL) {
      SafeFreePool (TempDevicePath);
    }
  }

  if (Devices != NULL) {
    Status = gRT->SetVariable (
                    mNetworkDeviceList,
                    &gEfiCallerIdGuid,
                    EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                    GetDevicePathSize (Devices),
                    Devices
                    );
    //
    // Fails to save the network device list to NV storage is not a fatal error.
    // Only impact is performance.
    //

    SafeFreePool (Devices);
  }

  return (Devices == NULL) ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

//
// FUNCTION NAME.
//      ConnectNetwork - Connect the network devices.
//
// FUNCTIONAL DESCRIPTION.
//      This function handles to connect the network devices..
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//                        EFI_SUCCESS At least one network device was connected.
//                        EFI_DEVICE_ERROR Network devices were not connected due
//                                         to an error.
//

EFI_STATUS
ConnectNetwork (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE pHandle;
  BOOLEAN OneConnected;
  EFI_DEVICE_PATH_PROTOCOL *Devices;
  EFI_DEVICE_PATH_PROTOCOL *TempDevicePath;

  OneConnected = FALSE;
  GetVariable2 (mNetworkDeviceList, &gEfiCallerIdGuid, (VOID **) &Devices, NULL);
  TempDevicePath = Devices;
  if (TempDevicePath != NULL) {
    Status = ConnectDevicePath (TempDevicePath, &pHandle);
    if (!EFI_ERROR (Status)) {
      OneConnected = TRUE;
    }
  }
  if (Devices != NULL) {
    SafeFreePool (Devices);
  }

  if (OneConnected) {
    return EFI_SUCCESS;
  } else {

    //
    // Cached network devices list doesn't exist or is NOT valid.
    //

    return ConnectAllAndCreateNetworkDeviceList ();
  }
}

//
// FUNCTION NAME.
//      ConnectAllDefaultConsoles - Connect the network devices.
//
// FUNCTIONAL DESCRIPTION.
//      This function handles to connect the network devices..
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//                        EFI_SUCCESS At least one network device was connected.
//                        EFI_DEVICE_ERROR Network devices were not connected due
//                                         to an error.
//

EFI_STATUS
ConnectAllDefaultConsoles (
  VOID
  )
{

  //
  // Connect console devices first.
  //

  PERF_START (0, "ConnectConsoleOut", "BMPolicy", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_VIDEO_INIT, MsTaskConnectConsoleOut, NULL, 0);
  PERF_END (0, "ConnectConsoleOut", "BMPolicy", 0);

  PERF_START (0, "ConnectConsoleIn", "BMPolicy", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_KEYBOARD_INIT, MsTaskConnectConsoleIn, NULL, 0);
  PERF_END (0, "ConnectConsoleIn", "BMPolicy", 0);

  PERF_START (0, "ConnectErrorOut", "BMPolicy", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_ERROR_OUT_INIT, MsTaskConnectErrorOut, NULL, 0);
  PERF_END (0, "ConnectErrorOut", "BMPolicy", 0);

  //
  // call the collect all console milestone
  //

  PERF_START (0, "CollectConsole", "BMPolicy", 0);
  SCT_MILESTONE_TASK (BDS_MILESTONE_TASK_COLLECT_CONSOLE, MsTaskCollectConsole, NULL, 0);
  PERF_END (0, "CollectConsole", "BMPolicy", 0);

  return EFI_SUCCESS;

}

//
// FUNCTION NAME.
//      BootManagerPolicyConnectDevicePath - Connect a device path following the
//      platforms EFI Boot Manager policy.
//
// FUNCTIONAL DESCRIPTION.
//      The ConnectDevicePath() function allows the caller to connect a DevicePath
//      using the same policy as the EFI Boot Manager.
//
// ENTRY PARAMETERS.
//      This            - A pointer to the EFI_BOOT_MANAGER_POLICY_PROTOCOL instance.
//      DevicePath      - Points to the start of the EFI device path to connect. If
//                        DevicePath is NULL then all the controllers in the system
//                        will be connected using the platforms EFI Boot Manager policy.
//      Recursive       - If TRUE, then ConnectController() is called recursively
//                        until the entire tree of controllers below the controller
//                        specified by DevicePath have been created. If FALSE, then
//                        the tree of controllers is only expanded One level. If
//                        DevicePath is NULL then Recursive is ignored.
//
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//                        EFI_SUCCESS            The DevicePath was connected.
//                        EFI_NOT_FOUND          The DevicePath was not found.
//                        EFI_NOT_FOUND          No driver was connected to DevicePath.
//                        EFI_SECURITY_VIOLATION The user has no permission to start
//                                               UEFI device drivers on the DevicePath.
//                        EFI_UNSUPPORTED        The current TPL is not TPL_APPLICATION.
//

EFI_STATUS
EFIAPI
BootManagerPolicyConnectDevicePath (
  IN EFI_BOOT_MANAGER_POLICY_PROTOCOL *This,
  IN EFI_DEVICE_PATH *DevicePath,
  IN BOOLEAN Recursive
  )
{
  EFI_STATUS Status;
  EFI_HANDLE Controller;

  if (EfiGetCurrentTpl () != TPL_APPLICATION) {
    return EFI_UNSUPPORTED;
  }

  if (DevicePath == NULL) {
    BmConnectAll ();
    return EFI_SUCCESS;
  }

  if (Recursive) {
    Status = ConnectDevicePath (DevicePath, &Controller);
  } else {
    Status = gBS->LocateDevicePath (&gEfiDevicePathProtocolGuid, &DevicePath, &Controller);
    if (!EFI_ERROR (Status)) {
      Status = gBS->ConnectController (Controller, NULL, DevicePath, FALSE);
    }
  }
  return Status;
}

//
// FUNCTION NAME.
//      BootManagerPolicyConnectDeviceClass - Connect a class of devices using
//      the platform Boot Manager policy.
//
// FUNCTIONAL DESCRIPTION.
//      The ConnectDeviceClass() function allows the caller to request that the
//      Boot Manager connect a class of devices.
//
// ENTRY PARAMETERS.
//      This            - A pointer to the EFI_BOOT_MANAGER_POLICY_PROTOCOL instance.
//      Class           - A pointer to an EFI_GUID that represents a class of devices
//                        that will be connected using the Boot Managers platform policy.
//
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//                        EFI_SUCCESS            At least one devices of the Class
//                                               was connected.
//                        EFI_DEVICE_ERROR       Devices were not connected due to
//                                               an error.
//                        EFI_NOT_FOUND          The Class is not supported by the
//                                               platform.
//                        EFI_UNSUPPORTED        The current TPL is not TPL_APPLICATION.
//

EFI_STATUS
EFIAPI
BootManagerPolicyConnectDeviceClass (
  IN EFI_BOOT_MANAGER_POLICY_PROTOCOL *This,
  IN EFI_GUID *Class
  )
{
  if (EfiGetCurrentTpl () != TPL_APPLICATION) {
    return EFI_UNSUPPORTED;
  }

  if (CompareGuid (Class, &gEfiBootManagerPolicyConnectAllGuid)) {
    ConnectAllAndCreateNetworkDeviceList ();
    return EFI_SUCCESS;
  }

  if (CompareGuid (Class, &gEfiBootManagerPolicyConsoleGuid)) {
    return ConnectAllDefaultConsoles ();
  }

  if (CompareGuid (Class, &gEfiBootManagerPolicyNetworkGuid)) {
    return ConnectNetwork ();
  }

  return EFI_NOT_FOUND;
}

EFI_BOOT_MANAGER_POLICY_PROTOCOL  mBootManagerPolicy = {
  EFI_BOOT_MANAGER_POLICY_PROTOCOL_REVISION,
  BootManagerPolicyConnectDevicePath,
  BootManagerPolicyConnectDeviceClass
};

//
// FUNCTION NAME.
//      InitializeBootManagerPolicy - Initialize the BootManagerPolicy module.
//
// FUNCTIONAL DESCRIPTION.
//      This function installs  Install Boot Manager Policy Protocol.
//
// ENTRY PARAMETERS.
//      None.
//
// EXIT PARAMETERS.
//      Function Return - EFI status code.
//
// WARNINGS.
//      None.
//

EFI_STATUS
EFIAPI
InitializeBootManagerPolicy (
  VOID
  )
{
  EFI_STATUS Status;

  Status =  gBS->InstallMultipleProtocolInterfaces (
                  &mBootManager.Handle,
                  &gEfiBootManagerPolicyProtocolGuid,
                  &mBootManagerPolicy,
                  NULL
                  );

  DPRINTF_INIT ("InitializeBootManagerPolicy, Status=%r.\n", Status);
  return Status;
}
