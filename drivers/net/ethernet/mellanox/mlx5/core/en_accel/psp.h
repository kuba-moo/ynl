/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5E_ACCEL_PSP_H__
#define __MLX5E_ACCEL_PSP_H__
#if IS_ENABLED(CONFIG_MLX5_EN_PSP)
#include <net/psp/types.h>
#include "en.h"

struct mlx5e_psp_stats {
	u64 psp_rx_pkts;
	u64 psp_rx_bytes;
	u64 psp_rx_pkts_auth_fail;
	u64 psp_rx_bytes_auth_fail;
	u64 psp_rx_pkts_frame_err;
	u64 psp_rx_bytes_frame_err;
	u64 psp_rx_pkts_drop;
	u64 psp_rx_bytes_drop;
	u64 psp_tx_pkts;
	u64 psp_tx_bytes;
	u64 psp_tx_pkts_drop;
	u64 psp_tx_bytes_drop;
};

struct mlx5e_psp {
	struct psp_dev *psp;
	struct psp_dev_caps caps;
	struct mlx5e_psp_fs *fs;
	atomic_t tx_key_cnt;
	atomic_t tx_drop;
	/* Stats manage */
	struct mlx5e_psp_stats stats;
};

struct psp_key_spi {
	u32 spi;
	__be32 key[PSP_MAX_KEY / sizeof(u32)];
	u16 keysz;
};

static inline bool mlx5_is_psp_device(struct mlx5_core_dev *mdev)
{
	if (!MLX5_CAP_GEN(mdev, psp))
		return false;

	if (!MLX5_CAP_PSP(mdev, psp_crypto_esp_aes_gcm_128_encrypt) ||
	    !MLX5_CAP_PSP(mdev, psp_crypto_esp_aes_gcm_128_decrypt))
		return false;

	return true;
}

void mlx5e_psp_register(struct mlx5e_priv *priv);
void mlx5e_psp_unregister(struct mlx5e_priv *priv);
int mlx5e_psp_init(struct mlx5e_priv *priv);
void mlx5e_psp_cleanup(struct mlx5e_priv *priv);
int mlx5e_psp_rotate_key(struct mlx5_core_dev *mdev);
int mlx5e_psp_generate_key_spi(struct mlx5_core_dev *mdev,
			       enum mlx5_psp_gen_spi_in_key_size keysz,
			       unsigned int keysz_bytes,
			       struct psp_key_spi *keys);
struct mlx5e_psp_stats *mlx5e_accel_psp_get_stats(struct mlx5e_priv *priv);
#else
static inline bool mlx5_is_psp_device(struct mlx5_core_dev *mdev)
{
	return false;
}

static inline void mlx5e_psp_register(struct mlx5e_priv *priv) { }
static inline void mlx5e_psp_unregister(struct mlx5e_priv *priv) { }
static inline int mlx5e_psp_init(struct mlx5e_priv *priv) { return 0; }
static inline void mlx5e_psp_cleanup(struct mlx5e_priv *priv) { }
static inline struct mlx5e_psp_stats *mlx5e_accel_psp_get_stats(struct mlx5e_priv *priv)
{
	return NULL;
}
#endif /* CONFIG_MLX5_EN_PSP */
#endif /* __MLX5E_ACCEL_PSP_H__ */
