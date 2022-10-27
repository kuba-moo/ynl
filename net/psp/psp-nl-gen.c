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

// PSP_CMD_RX_ASSOC_ALLOC - do
static const struct nla_policy psp_rx_assoc_alloc_nl_policy[PSP_A_ASSOC_VERSION + 1] = {
	[PSP_A_ASSOC_DEV_ID] = NLA_POLICY_MIN(NLA_U32, 1),
	[PSP_A_ASSOC_VERSION] = NLA_POLICY_MAX(NLA_U32, 4),
};

// PSP_CMD_ASSOC_ADD - do
static const struct nla_policy psp_assoc_add_nl_policy[PSP_A_ASSOC_SOCK_FD + 1] = {
	[PSP_A_ASSOC_VERSION] = NLA_POLICY_MAX(NLA_U32, 4),
	[PSP_A_ASSOC_TX_KEY] = { .type = NLA_NESTED, },
	[PSP_A_ASSOC_RX_KEY] = { .type = NLA_NESTED, },
	[PSP_A_ASSOC_SOCK_FD] = { .type = NLA_U32, },
};

// Dummy reject-all policy
static const struct nla_policy psp_dummy_nl_policy[1 + 1] = {
};

// Ops table for psp
static const struct genl_split_ops psp_nl_ops[5] = {
	{
		.cmd		= PSP_CMD_DEV_GET,
		.pre_doit	= psp_device_get_locked,
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
		.pre_doit	= psp_device_get_locked,
		.doit		= psp_nl_dev_set_doit,
		.post_doit	= psp_device_unlock,
		.policy		= psp_dev_set_nl_policy,
		.maxattr	= PSP_A_DEV_PSP_VERSIONS_ENA,
	},
	{
		.cmd		= PSP_CMD_RX_ASSOC_ALLOC,
		.pre_doit	= psp_assoc_device_get_locked,
		.doit		= psp_nl_rx_assoc_alloc_doit,
		.post_doit	= psp_device_unlock,
		.policy		= psp_rx_assoc_alloc_nl_policy,
		.maxattr	= PSP_A_ASSOC_VERSION,
	},
	{
		.cmd		= PSP_CMD_ASSOC_ADD,
		.pre_doit	= psp_assoc_device_get_locked,
		.doit		= psp_nl_assoc_add_doit,
		.post_doit	= psp_device_unlock,
		.policy		= psp_assoc_add_nl_policy,
		.maxattr	= PSP_A_ASSOC_SOCK_FD,
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
	.split_ops	= psp_nl_ops,
	.n_split_ops	= ARRAY_SIZE(psp_nl_ops),
	.mcgrps		= psp_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(psp_nl_mcgrps),
};
