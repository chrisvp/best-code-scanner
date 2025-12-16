//
// FILENAME.
//      BdsBiosSelfHealing.h - SecureCore Technology(TM) The header file for BIOS Self Healing feature.
//
// FUNCTIONAL DESCRIPTION.
//      Provides functions for BIOS Self Healing feature.
//
// NOTICE.
//      Copyright (C) 2013-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _BDS_BIOS_SELF_HEALING_H
#define _BDS_BIOS_SELF_HEALING_H

#if OPTION_SUPPORT_BIOS_SELF_HEALING

VOID
ProcessBiosSelfHealing (
  IN VOID* MilestoneData,
  IN UINT32 MilestoneDataSize
  );

#endif // OPTION_SUPPORT_BIOS_SELF_HEALING.
#endif // _BDS_BIOS_SELF_HEALING_H.
