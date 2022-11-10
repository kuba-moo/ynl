/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/psp.yaml */
/* YNL-GEN uapi header */

#ifndef _UAPI_LINUX_PSP_H
#define _UAPI_LINUX_PSP_H

#define PSP_FAMILY_NAME		"psp"
#define PSP_FAMILY_VERSION	1

enum psp_version {
	PSP_VERSION_HDR0_AES_GCM_128,
	PSP_VERSION_HDR0_AES_GCM_256,
	PSP_VERSION_HDR0_AES_GMAC_128,
	PSP_VERSION_HDR0_AES_GMAC_256,
};

enum {
	PSP_A_DEV_ID = 1,
	PSP_A_DEV_IFINDEX,
	PSP_A_DEV_PSP_VERSIONS_CAP,
	PSP_A_DEV_PSP_VERSIONS_ENA,

	__PSP_A_DEV_MAX,
	PSP_A_DEV_MAX = (__PSP_A_DEV_MAX - 1)
};

enum {
	PSP_A_KEYS_PAD = 1,
	PSP_A_KEYS_DEV_ID,
	PSP_A_KEYS_VERSION,
	PSP_A_KEYS_KEY,
	PSP_A_KEYS_SPI,

	__PSP_A_KEYS_MAX,
	PSP_A_KEYS_MAX = (__PSP_A_KEYS_MAX - 1)
};

enum {
	PSP_CMD_DEV_GET = 1,
	PSP_CMD_DEV_ADD_NTF,
	PSP_CMD_DEV_DEL_NTF,
	PSP_CMD_DEV_SET,
	PSP_CMD_DEV_CHANGE_NTF,
	PSP_CMD_TX_ASSOC_ADD,

	__PSP_CMD_MAX,
	PSP_CMD_MAX = (__PSP_CMD_MAX - 1)
};

#define PSP_MCGRP_MGMT	"mgmt"

#endif /* _UAPI_LINUX_PSP_H */
