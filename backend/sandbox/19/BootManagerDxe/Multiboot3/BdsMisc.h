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

#ifndef _BDS_MB3_MISC_H
#define _BDS_MB3_MISC_H

//
// USB Interface Subclass.
//

#define USB_MASS_STORE_UFI      0x04
#define USB_MASS_STORE_8070I    0x05

//
// USB Mass PDT.
//

#define USB_PDT_DIRECT_ACCESS   0x00
#define USB_PDT_CDROM           0x05
#define USB_PDT_OPTICAL         0x07
#define USB_PDT_SIMPLE_DIRECT   0x0E

#define USB_VENDOR_ID_LEN       8
#define USB_PRODUCT_ID_LEN      16

//
// Plus one space character.
//

#define USB_MSD_DEVICE_LEN      (USB_VENDOR_ID_LEN + USB_PRODUCT_ID_LEN + 1)

#pragma pack(1)
typedef struct {
  UINT8 Pdt;                    // Peripheral Device Type (low 5 bits).
  UINT8 Removable;              // Removable Media (highest bit).
  UINT8 Reserved0 [2];
  UINT8 AddLen;                 // Additional length.
  UINT8 Reserved1 [3];
  UINT8 VendorID [USB_VENDOR_ID_LEN];
  UINT8 ProductID [USB_PRODUCT_ID_LEN];
  UINT8 ProductRevision [4];
} USB_MASS_INQUIRY_DATA;
#pragma pack()

#endif // _BDS_MB3_MISC_H.

