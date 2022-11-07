// SPDX-License-Identifier: BSD-3-Clause
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/psp.yaml */
/* YNL-GEN kernel source */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "psp-nl-gen.h"

#include <linux/psp.h>

// PSP_CMD_DEV_GET - do
static const struct nla_policy psp_dev_get_nl_policy[PSP_A_DEV_ID + 1] = {
	[PSP_A_DEV_ID] = NLA_POLICY_MIN(NLA_U32, 1),
};

// PSP_CMD_DEV_SET - do
static const struct nla_policy psp_dev_set_nl_policy[PSP_A_DEV_PSP_VERSIONS_ENA + 1] = {
	[PSP_A_DEV_ID] = NLA_POLICY_MIN(NLA_U32, 1),
	[PSP_A_DEV_PSP_VERSIONS_ENA] = NLA_POLICY_MASK(NLA_U32, 0xf),
};

// PSP_CMD_TX_ASSOC_ADD - do
static const struct nla_policy psp_tx_assoc_add_nl_policy[PSP_A_KEYS_SOCK_FD + 1] = {
	[PSP_A_KEYS_VERSION] = NLA_POLICY_MAX(NLA_U32, 4),
	[PSP_A_KEYS_KEY] = { .type = NLA_BINARY, },
	[PSP_A_KEYS_SPI] = { .type = NLA_U32, },
	[PSP_A_KEYS_SOCK_FD] = { .type = NLA_U32, },
};

// Dummy reject-all policy
static const struct nla_policy psp_dummy_nl_policy[2] = {
};

// Ops table for psp
static const struct genl_split_ops psp_nl_ops[4] = {
	{
		.cmd		= PSP_CMD_DEV_GET,
		.pre_doit	= psp_device_get_and_lock,
		.doit		= psp_nl_dev_get_doit,
		.post_doit	= psp_device_unlock,
		.policy		= psp_dev_get_nl_policy,
		.maxattr	= PSP_A_DEV_ID,
	},
	{
		.cmd		= PSP_CMD_DEV_GET,
		.dumpit		= psp_nl_dev_get_dumpit,
		.policy		= psp_dummy_nl_policy,
		.maxattr	= 1,
	},
	{
		.cmd		= PSP_CMD_DEV_SET,
		.pre_doit	= psp_device_get_and_lock,
		.doit		= psp_nl_dev_set_doit,
		.post_doit	= psp_device_unlock,
		.policy		= psp_dev_set_nl_policy,
		.maxattr	= PSP_A_DEV_PSP_VERSIONS_ENA,
	},
	{
		.cmd		= PSP_CMD_TX_ASSOC_ADD,
		.doit		= psp_nl_tx_assoc_add_doit,
		.policy		= psp_tx_assoc_add_nl_policy,
		.maxattr	= PSP_A_KEYS_SOCK_FD,
	},
};

static const struct genl_multicast_group psp_nl_mcgrps[] = {
	[PSP_NLGRP_MGMT] = { "mgmt", },
};

struct genl_family psp_nl_family __ro_after_init = {
	.name		= PSP_FAMILY_NAME,
	.version	= PSP_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.small_ops	= psp_nl_ops,
	.n_small_ops	= ARRAY_SIZE(psp_nl_ops),
	.mcgrps		= psp_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(psp_nl_mcgrps),
};
