// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
#include <linux/mlx5/device.h>
#include <net/psp.h>
#include <linux/psp.h>
#include "mlx5_core.h"
#include "psp.h"
#include "lib/crypto.h"
#include "en_accel/psp.h"
#include "en_accel/psp_fs.h"

struct mlx5e_psp_sa_entry {
	struct mlx5e_accel_psp_rule *psp_rule;
	u32 enc_key_id;
};

static int
mlx5e_psp_set_config(struct psp_dev *psd, struct psp_dev_config *conf,
		     struct netlink_ext_ack *extack)
{
	return 0; /* TODO: this should actually do things to the device */
}

static int
mlx5e_psp_rx_spi_alloc(struct psp_dev *psd, u32 version,
		       struct psp_key_parsed *assoc,
		       struct netlink_ext_ack *extack)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	enum mlx5_psp_gen_spi_in_key_size keysz;
	struct psp_key_spi key_spi = {};
	u8 keysz_bytes;
	int err;

	switch (version) {
	case PSP_VERSION_HDR0_AES_GCM_128:
		keysz = MLX5_PSP_GEN_SPI_IN_KEY_SIZE_128;
		keysz_bytes = 16;
		break;
	case PSP_VERSION_HDR0_AES_GCM_256:
		keysz = MLX5_PSP_GEN_SPI_IN_KEY_SIZE_256;
		keysz_bytes = 32;
		break;
	default:
		return -EINVAL;
	}

	err = mlx5e_psp_generate_key_spi(priv->mdev, keysz, keysz_bytes,
					 &key_spi);
	if (err)
		return err;

	assoc->spi = cpu_to_be32(key_spi.spi);
	memcpy(assoc->key, key_spi.key, keysz_bytes);
	return 0;
}

struct psp_key {
	u32 id;
};

static int mlx5e_psp_assoc_add(struct psp_dev *psd, struct psp_assoc *pas,
			       struct netlink_ext_ack *extack)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct psp_key_parsed *tx = &pas->tx;
	struct mlx5e_psp *psp = priv->psp;
	struct psp_key *nkey;
	int err;

	mdev = priv->mdev;
	nkey = (struct psp_key *)pas->drv_data;

	err = mlx5_create_encryption_key(mdev, tx->key,
					 pas->key_sz,
					 MLX5_ACCEL_OBJ_PSP_KEY,
					 &nkey->id);
	if (err) {
		mlx5_core_err(mdev, "Failed to create encryption key (err = %d)\n", err);
		return err;
	}

	atomic_inc(&psp->tx_key_cnt);
	return 0;
}

static void mlx5e_psp_assoc_del(struct psp_dev *psd, struct psp_assoc *pas)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	struct mlx5e_psp *psp = priv->psp;
	struct psp_key *nkey;

	nkey = (struct psp_key *)pas->drv_data;
	mlx5_destroy_encryption_key(priv->mdev, nkey->id);
	atomic_dec(&psp->tx_key_cnt);
}

static int mlx5e_psp_key_rotate(struct psp_dev *psd, struct netlink_ext_ack *exack)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);

	/* no support for protecting against external rotations */
	psd->generation = 0;

	return mlx5e_psp_rotate_key(priv->mdev);
}

static void mlx5e_psp_get_stats(struct psp_dev *psd, struct psp_dev_stats *stats)
{
	struct mlx5e_priv *priv = netdev_priv(psd->main_netdev);
	struct mlx5e_psp_stats nstats;

	mlx5e_accel_psp_fs_get_stats_fill(priv, &nstats);
	stats->rx_packets = nstats.psp_rx_pkts;
	stats->rx_bytes = nstats.psp_rx_bytes;
	stats->rx_auth_fail = nstats.psp_rx_pkts_auth_fail;
	stats->rx_error = nstats.psp_rx_pkts_frame_err;
	stats->rx_bad = nstats.psp_rx_pkts_drop;
	stats->tx_packets = nstats.psp_tx_pkts;
	stats->tx_bytes = nstats.psp_tx_bytes;
	stats->tx_error = atomic_read(&priv->psp->tx_drop);
}

static struct psp_dev_ops mlx5_psp_ops = {
	.set_config   = mlx5e_psp_set_config,
	.rx_spi_alloc = mlx5e_psp_rx_spi_alloc,
	.tx_key_add   = mlx5e_psp_assoc_add,
	.tx_key_del   = mlx5e_psp_assoc_del,
	.key_rotate   = mlx5e_psp_key_rotate,
	.get_stats    = mlx5e_psp_get_stats,
};

struct mlx5e_psp_stats *mlx5e_accel_psp_get_stats(struct mlx5e_priv *priv)
{
	return &priv->psp->stats;
}

void mlx5e_psp_unregister(struct mlx5e_priv *priv)
{
	if (!priv->psp || !priv->psp->psp)
		return;

	psp_dev_unregister(priv->psp->psp);
}

void mlx5e_psp_register(struct mlx5e_priv *priv)
{
	/* FW Caps missing */
	if (!priv->psp)
		return;

	priv->psp->caps.assoc_drv_spc = sizeof(u32);
	priv->psp->caps.versions = 1 << PSP_VERSION_HDR0_AES_GCM_128;
	if (MLX5_CAP_PSP(priv->mdev, psp_crypto_esp_aes_gcm_256_encrypt) &&
	    MLX5_CAP_PSP(priv->mdev, psp_crypto_esp_aes_gcm_256_decrypt))
		priv->psp->caps.versions |= 1 << PSP_VERSION_HDR0_AES_GCM_256;

	priv->psp->psp = psp_dev_create(priv->netdev, &mlx5_psp_ops,
					&priv->psp->caps, NULL);
	if (IS_ERR(priv->psp->psp))
		mlx5_core_err(priv->mdev, "PSP failed to register due to %pe\n",
			      priv->psp->psp);
}

int mlx5e_psp_init(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_psp_fs *fs;
	struct mlx5e_psp *psp;
	int err;

	if (!mlx5_is_psp_device(mdev)) {
		mlx5_core_dbg(mdev, "PSP offload not supported\n");
		return -EOPNOTSUPP;
	}

	if (!MLX5_CAP_ETH(mdev, swp)) {
		mlx5_core_dbg(mdev, "SWP not supported\n");
		return -EOPNOTSUPP;
	}

	if (!MLX5_CAP_ETH(mdev, swp_csum)) {
		mlx5_core_dbg(mdev, "SWP checksum not supported\n");
		return -EOPNOTSUPP;
	}

	if (!MLX5_CAP_ETH(mdev, swp_csum_l4_partial)) {
		mlx5_core_dbg(mdev, "SWP L4 partial checksum not supported\n");
		return -EOPNOTSUPP;
	}

	if (!MLX5_CAP_ETH(mdev, swp_lso)) {
		mlx5_core_dbg(mdev, "PSP LSO not supported\n");
		return -EOPNOTSUPP;
	}

	psp = kzalloc(sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return -ENOMEM;

	priv->psp = psp;
	fs = mlx5e_accel_psp_fs_init(priv);
	if (IS_ERR(fs)) {
		err = PTR_ERR(fs);
		goto out_err;
	}

	psp->fs = fs;

	mlx5_core_dbg(priv->mdev, "PSP attached to netdevice\n");
	return 0;

out_err:
	priv->psp = NULL;
	kfree(psp);
	return err;
}

void mlx5e_psp_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_psp *psp = priv->psp;

	if (!psp)
		return;

	WARN_ON(atomic_read(&psp->tx_key_cnt));
	mlx5e_accel_psp_fs_cleanup(psp->fs);
	priv->psp = NULL;
	kfree(psp);
}
