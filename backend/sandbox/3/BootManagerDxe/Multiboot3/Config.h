//
// FILENAME.
//      Config.h - SecureCore Technology(TM) MultiBootIII BOP Configuration Parameters.
//
// FUNCTIONAL DESCRIPTION.
//      This include file defines the configuration parameters for the
//      MultiBootIII BOP Driver, allowing its policies to
//      be managed through build-time options.
//
// NOTICE.
//      Copyright (C) 2009-2024 Phoenix Technologies.  All Rights Reserved.
//

#ifndef _SCT_H_CONFIG
#define _SCT_H_CONFIG

//
// Workaround delay for USB device polling.
//

#define USB_WAIT_TIMEOUT (395 * 1000)   // 300ms

//
// Driver-specific instrumentation.
//

#define OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3                 0 // enable MB3 BOP Debugging.
#define OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3_INIT            0 // enable MB3 BOP Debugging.
#define OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3_INSTRUMENTATION 0 // enable MB3 BOP Debugging.
#define OPTION_DEBUG_SYSTEM_BOOT_OPTION_MB3_PCILAN          0

#define CONFIG_Mb3SataPortIndex           1
#define CONFIG_Mb3HddConnectList          {L"PciRoot(0x0)/Pci(0x1F,0x0)", 0}, BOOT_MANAGER_CONNECTION_DEVICE_LIST_END
#define CONFIG_Mb3CdConnectList           {L"PciRoot(0x0)/Pci(0x1F,0x0)", 0}, BOOT_MANAGER_CONNECTION_DEVICE_LIST_END
#define CONFIG_Mb3RemovableConnectList    {L"PciRoot(0x0)/Pci(0x1F,0x0)", 0}, BOOT_MANAGER_CONNECTION_DEVICE_LIST_END
#define CONFIG_Mb3PciLanConnectList       {L"PciRoot(0x0)/Pci(0x1F,0x0)", 0}, BOOT_MANAGER_CONNECTION_DEVICE_LIST_END


#endif // not defined, _SCT_H_CONFIG
