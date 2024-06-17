// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include <linux/netdevice.h>
#include <linux/mlx5/fs.h>
#include "en.h"
#include "fs_core.h"
#include "en_accel/psp_fs.h"
#include "en_accel/psp.h"

struct mlx5e_psp_tx {
	struct mlx5_flow_namespace *ns;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *fg;
	struct mlx5_flow_handle *rule;
	struct mutex mutex; /* Protect PSP TX steering */
	u32 refcnt;
};

struct mlx5e_psp_fs {
	struct mlx5_core_dev *mdev;
	struct mlx5e_psp_tx *tx_fs;
	struct mlx5e_flow_steering *fs;
};

enum accel_psp_rule_action {
	ACCEL_PSP_RULE_ACTION_ENCRYPT,
};

struct mlx5e_accel_psp_rule {
	struct mlx5_flow_handle *rule;
	u8 action;
};

static void setup_fte_udp_psp(struct mlx5_flow_spec *spec, u16 udp_port)
{
	spec->match_criteria_enable |= MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET(fte_match_set_lyr_2_4, spec->match_criteria, udp_dport, 0xffff);
	MLX5_SET(fte_match_set_lyr_2_4, spec->match_value, udp_dport, udp_port);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, spec->match_criteria, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, spec->match_value, ip_protocol, IPPROTO_UDP);
}

static int accel_psp_fs_tx_create_ft_table(struct mlx5e_psp_fs *fs)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_table_attr ft_attr = {};
	struct mlx5_core_dev *mdev = fs->mdev;
	struct mlx5_flow_act flow_act = {};
	u32 *in, *mc, *outer_headers_c;
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_spec *spec;
	struct mlx5e_psp_tx *tx_fs;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *fg;
	int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!spec || !in) {
		err = -ENOMEM;
		goto out;
	}

	ft_attr.max_fte = 1;
#define MLX5E_PSP_PRIO 0
	ft_attr.prio = MLX5E_PSP_PRIO;
#define MLX5E_PSP_LEVEL 0
	ft_attr.level = MLX5E_PSP_LEVEL;
	ft_attr.autogroup.max_num_groups = 1;

	tx_fs = fs->tx_fs;
	ft = mlx5_create_flow_table(tx_fs->ns, &ft_attr);
	if (IS_ERR(ft)) {
		err = PTR_ERR(ft);
		mlx5_core_err(mdev, "PSP: fail to add psp tx flow table, err = %d\n", err);
		goto out;
	}

	mc = MLX5_ADDR_OF(create_flow_group_in, in, match_criteria);
	outer_headers_c = MLX5_ADDR_OF(fte_match_param, mc, outer_headers);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, ip_protocol);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, outer_headers_c, udp_dport);
	MLX5_SET_CFG(in, match_criteria_enable, MLX5_MATCH_OUTER_HEADERS);
	fg = mlx5_create_flow_group(ft, in);
	if (IS_ERR(fg)) {
		err = PTR_ERR(fg);
		mlx5_core_err(mdev, "PSP: fail to add psp tx flow group, err = %d\n", err);
		goto err_create_fg;
	}

	setup_fte_udp_psp(spec, PSP_DEFAULT_UDP_PORT);
	flow_act.crypto.type = MLX5_FLOW_CONTEXT_ENCRYPT_DECRYPT_TYPE_PSP;
	flow_act.flags |= FLOW_ACT_NO_APPEND;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_ALLOW |
			  MLX5_FLOW_CONTEXT_ACTION_CRYPTO_ENCRYPT;
	rule = mlx5_add_flow_rules(ft, spec, &flow_act, NULL, 0);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		mlx5_core_err(mdev, "PSP: fail to add psp tx flow rule, err = %d\n", err);
		goto err_add_flow_rule;
	}

	tx_fs->ft = ft;
	tx_fs->fg = fg;
	tx_fs->rule = rule;
	goto out;

err_add_flow_rule:
	mlx5_destroy_flow_group(fg);
err_create_fg:
	mlx5_destroy_flow_table(ft);
out:
	kvfree(in);
	kvfree(spec);
	return err;
}

static void accel_psp_fs_tx_destroy(struct mlx5e_psp_tx *tx_fs)
{
	if (!tx_fs->ft)
		return;

	mlx5_del_flow_rules(tx_fs->rule);
	mlx5_destroy_flow_group(tx_fs->fg);
	mlx5_destroy_flow_table(tx_fs->ft);
}

static int accel_psp_fs_tx_ft_get(struct mlx5e_psp_fs *fs)
{
	struct mlx5e_psp_tx *tx_fs = fs->tx_fs;
	int err = 0;

	mutex_lock(&tx_fs->mutex);
	if (tx_fs->refcnt++)
		goto out;

	err = accel_psp_fs_tx_create_ft_table(fs);
	if (err)
		tx_fs->refcnt--;
out:
	mutex_unlock(&tx_fs->mutex);
	return err;
}

static void accel_psp_fs_tx_ft_put(struct mlx5e_psp_fs *fs)
{
	struct mlx5e_psp_tx *tx_fs = fs->tx_fs;

	mutex_lock(&tx_fs->mutex);
	if (--tx_fs->refcnt)
		goto out;

	accel_psp_fs_tx_destroy(tx_fs);
out:
	mutex_unlock(&tx_fs->mutex);
}

static void accel_psp_fs_cleanup_tx(struct mlx5e_psp_fs *fs)
{
	struct mlx5e_psp_tx *tx_fs = fs->tx_fs;

	if (!tx_fs)
		return;

	mutex_destroy(&tx_fs->mutex);
	WARN_ON(tx_fs->refcnt);
	kfree(tx_fs);
	fs->tx_fs = NULL;
}

static int accel_psp_fs_init_tx(struct mlx5e_psp_fs *fs)
{
	struct mlx5_flow_namespace *ns;
	struct mlx5e_psp_tx *tx_fs;

	ns = mlx5_get_flow_namespace(fs->mdev, MLX5_FLOW_NAMESPACE_EGRESS_IPSEC);
	if (!ns)
		return -EOPNOTSUPP;

	tx_fs = kzalloc(sizeof(*tx_fs), GFP_KERNEL);
	if (!tx_fs)
		return -ENOMEM;

	mutex_init(&tx_fs->mutex);
	tx_fs->ns = ns;
	fs->tx_fs = tx_fs;
	return 0;
}

void mlx5_accel_psp_fs_cleanup_tx_tables(struct mlx5e_priv *priv)
{
	if (!priv->psp)
		return;

	accel_psp_fs_tx_ft_put(priv->psp->fs);
}

int mlx5_accel_psp_fs_init_tx_tables(struct mlx5e_priv *priv)
{
	if (!priv->psp)
		return 0;

	return accel_psp_fs_tx_ft_get(priv->psp->fs);
}

void mlx5e_accel_psp_fs_cleanup(struct mlx5e_psp_fs *fs)
{
	accel_psp_fs_cleanup_tx(fs);
	kfree(fs);
}

struct mlx5e_psp_fs *mlx5e_accel_psp_fs_init(struct mlx5e_priv *priv)
{
	struct mlx5e_psp_fs *fs;
	int err = 0;

	fs = kzalloc(sizeof(*fs), GFP_KERNEL);
	if (!fs)
		return ERR_PTR(-ENOMEM);

	fs->mdev = priv->mdev;
	err = accel_psp_fs_init_tx(fs);
	if (err)
		goto err_tx;

	fs->fs = priv->fs;

	return fs;
err_tx:
	kfree(fs);
	return ERR_PTR(err);
}
