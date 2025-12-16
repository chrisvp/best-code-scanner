//
// FILENAME.
//      Meta.h - SecureCore Technology(TM) System Boot Manager Top-Level Include File.
//
// FUNCTIONAL DESCRIPTION.
//      This include file includes all of the other include files for
//      the System Boot Manager DXE Driver.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _EDK2_H_META
#define _EDK2_H_META

#include <SysMeta.h>                    // SCT System Includes.
//
// Standard header files included by modules in this driver.
//

#include <Universal/CapsulePei/Capsule.h>
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/Scsi.h>
#include <IndustryStandard/Pci.h>

//
// The libraries used by this driver.
//

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>

#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/PerformanceLib.h>
#include <Library/HiiLib.h>
#include <Library/DevicePathLib.h>

#include <Library/PcdLib.h>

#include <Library/TcgPhysicalPresenceLib.h>
#include <Library/Tcg2PhysicalPresenceLib.h>

#include <Library/IoLib.h>
#include <Library/UefiBootManagerLib.h>
#include <Library/VariableFlashInfoLib.h>


//
// The following definitions specify the protocols used or published by this driver.
// (alphabetical order).
//

#if OPTION_SUPPORT_CSM
#include <Protocol/AcpiS3Save.h>
#include <Protocol/LegacyRegion.h>
#endif

#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/BlockIo.h>
#include <Protocol/CpuIo2.h>
#include <Protocol/DevicePathFromText.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/DiskInfo.h>
#include <Protocol/GenericMemoryTest.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/HiiString.h>
#include <Protocol/LoadFile.h>
#include <Protocol/LoadedImage.h>

#include <Protocol/PciIo.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Protocol/ScsiIo.h>

#include <Protocol/SimpleFileSystem.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextInEx.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/SmmCommunication.h>
#include <Protocol/UserManager.h>

#include <Protocol/AtaPassThru.h>

#include <Protocol/SmmAccess2.h>
#include <Protocol/HiiConfigRouting.h>
#include <Protocol/HiiConfigAccess.h>

#include <Protocol/LegacyRegion2.h>


//
// These protocols are needed for their defines only.
// (alphabetical order).
//

#include <Protocol/AbsolutePointer.h>
#include <Protocol/ComponentName.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/EdidDiscovered.h>

//#include <Protocol/SdMmcPassThru.h>
#include <Protocol/FormBrowser2.h>
#include <Protocol/IdeControllerInit.h>

#include <Protocol/PxeBaseCode.h>

#include <Protocol/SimpleNetwork.h>

#include <Protocol/UgaDraw.h>
#include <Protocol/UsbHostController.h>

#include <Protocol/FirmwareVolume2.h>

#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/BusSpecificDriverOverride.h>

#include <Protocol/ManagedNetwork.h>
#include <Protocol/BootManagerPolicy.h>
#include <Protocol/DeferredImageLoad.h>
#include <Protocol/RamDisk.h>
#include <Protocol/EfiSdHostIo.h>
#include <Protocol/SdMmcPassThru.h>

#include <Pi/PiDxeCis.h>

//
// These GUIDs are used.
// (alphabetical order).
//

#include <Guid/GlobalVariable.h>
#include <Guid/Gpt.h>
#include <Guid/ImageAuthentication.h>
#include <Guid/MemoryTypeInformation.h>
#include <Guid/FileInfo.h>
#include <Guid/FileSystemVolumeLabelInfo.h>
#include <Guid/HobList.h>
#include <Guid/MdeModuleHii.h>

#include <Guid/EventGroup.h>
#include <Guid/PcAnsi.h>
#include <Guid/ConsoleInDevice.h>

#include <Guid/MemoryOverwriteControl.h>

#include <Guid/FmpCapsule.h>
#include <Guid/SystemResourceTable.h>
#include <Guid/VariableFormat.h>

//
// These protocols are produced in this driver.
//

#include <Protocol/Bds.h>

#include <Guid/ZeroGuid.h>


#endif // _EDK2_H_META
