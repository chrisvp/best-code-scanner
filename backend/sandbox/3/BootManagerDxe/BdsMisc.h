//
// FILENAME.
//      BdsMisc.h - SecureCore Technology(TM) The header file for miscellaneous functions.
//
// FUNCTIONAL DESCRIPTION.
//      This include file contains data definitions and data structures
//      associated with miscellaneous functions support in the System Boot Manager.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _BDS_MISC_H
#define _BDS_MISC_H


#if OPTION_SYSTEM_BOOT_MANAGER_LOCK_SMRAM_IN_BDS_ENTRY
EFI_STATUS
BdsLockSmram (VOID);
#define BDS_LOCK_SMRAM {BdsLockSmram ();}
#else
#define BDS_LOCK_SMRAM
#endif

#if (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)
EFI_STATUS
BdsEnableSmmCodeAccessCheck (VOID);
#endif // (OPTION_SUPPORT_SMM_CODE_ACCESS_CHK || OPTION_SMM_CODE_ACCESS_CHK_NX)

EFI_STATUS
EFIAPI
BmDispatch (
  IN BOOLEAN Signal
);

VOID
EFIAPI
SaveMemoryMap (VOID);

extern BOOLEAN mIsBootOptionDamaged;

#endif // _BDS_MISC_H.

