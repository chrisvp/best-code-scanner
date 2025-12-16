//
// FILENAME.
//      BdsCapsuleUpdate.h - SecureCore Technology(TM) The header file for CapsuleUpdate feature.
//
// FUNCTIONAL DESCRIPTION.
//      Provides functions for CapsuleUpdate feature.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _BDS_CAPSULE_UPDATE_H
#define _BDS_CAPSULE_UPDATE_H

EFI_STATUS
UpdateCapsuleService (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  );

#endif // _BDS_CAPSULE_UPDATE_H

