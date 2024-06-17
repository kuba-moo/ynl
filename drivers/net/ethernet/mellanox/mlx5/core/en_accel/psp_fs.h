/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_PSP_FS_H__
#define __MLX5_PSP_FS_H__

#ifdef CONFIG_MLX5_EN_PSP

struct mlx5e_psp_fs;

struct mlx5e_psp_fs *mlx5e_accel_psp_fs_init(struct mlx5e_priv *priv);
void mlx5e_accel_psp_fs_cleanup(struct mlx5e_psp_fs *fs);
int mlx5_accel_psp_fs_init_tx_tables(struct mlx5e_priv *priv);
void mlx5_accel_psp_fs_cleanup_tx_tables(struct mlx5e_priv *priv);
int mlx5_accel_psp_fs_init_rx_tables(struct mlx5e_priv *priv);
void mlx5_accel_psp_fs_cleanup_rx_tables(struct mlx5e_priv *priv);
void mlx5e_accel_psp_fs_get_stats_fill(struct mlx5e_priv *priv, void *psp_stats);
#else
static inline int mlx5_accel_psp_fs_init_tx_tables(struct mlx5e_priv *priv)
{
	return 0;
}

static inline void mlx5_accel_psp_fs_cleanup_tx_tables(struct mlx5e_priv *priv) { }
static inline int mlx5_accel_psp_fs_init_rx_tables(struct mlx5e_priv *priv)
{
	return 0;
}
static inline void mlx5_accel_psp_fs_cleanup_rx_tables(struct mlx5e_priv *priv) { }
#endif /* CONFIG_MLX5_EN_PSP */
#endif /* __MLX5_PSP_FS_H__ */
