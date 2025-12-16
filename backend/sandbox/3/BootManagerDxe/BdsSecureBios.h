//
// FILENAME.
//      BdsSecureBios.h - SecureCore Technology(TM) The header file for SecureBios feature.
//
// FUNCTIONAL DESCRIPTION.
//      Provides funtions for SecureBios feature.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _BDS_SECURE_BIOS_H
#define _BDS_SECURE_BIOS_H

#if OPTION_SUPPORT_SECURE_BIOS

typedef struct _SECURE_BIOS_LOCK_REGION {
  UINT64 BeginFdlaOffset;
  UINT64 RegionSize;
  BOOLEAN Action;
} SECURE_BIOS_LOCK_REGION;

EFI_STATUS
EFIAPI
SecureBiosFreeze (VOID);

#endif

#endif // _BDS_SECURE_BIOS_H.

