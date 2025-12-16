//
// FILENAME.
//      NvmeCmd.h - SecureCore Technology(TM) NVMe Command Function Head file.
//
// FUNCTIONAL DESCRIPTION.
//      This include file contains standard data type definitions for NVMe Command
//      functions for BootManager DXE Driver.
//
// NOTICE.
//      Copyright (C) 2015-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_NVMECMD
#define _SCT_H_NVMECMD

#include <IndustryStandard/Nvme.h>

#define NVME_GENERIC_TIMEOUT                 EFI_TIMER_PERIOD_SECONDS (5)
#define NVME_CONTROLLER_ID                   0

EFI_STATUS
EFIAPI
NvmeIdentifyController (
  IN EFI_HANDLE DiskHandle,
  OUT NVME_ADMIN_CONTROLLER_DATA *IdentData
  );

#endif // _SCT_H_NVMECMD
