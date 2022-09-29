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

// Ops table for psp
static const struct genl_ops psp_nl_ops[1] = {
	{
		.cmd		= PSP_CMD_DEV_GET,
		.doit		= psp_nl_dev_get_doit,
		.dumpit		= psp_nl_dev_get_dumpit,
		.policy		= psp_dev_get_nl_policy,
		.maxattr	= PSP_A_DEV_ID + 1,
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
	.ops		= psp_nl_ops,
	.n_ops		= ARRAY_SIZE(psp_nl_ops),
	.mcgrps		= psp_nl_mcgrps,
	.n_mcgrps	= ARRAY_SIZE(psp_nl_mcgrps),
};
