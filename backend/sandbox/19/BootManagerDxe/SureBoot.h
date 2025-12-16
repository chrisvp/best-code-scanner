//
// FILENAME.
//      SureBoot.h - SecureCore Technology(TM) The header file for SureBoot feature.
//
// FUNCTIONAL DESCRIPTION.
//      Provides functions for SureBoot feature.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SURE_BOOT_H
#define _SURE_BOOT_H

EFI_STATUS
EFIAPI
ResetSureBootStatus (VOID* Data, UINT32 DataSize);

EFI_STATUS
EFIAPI
DisableSureBootTimerReset (VOID);

#endif // _SURE_BOOT_H.

