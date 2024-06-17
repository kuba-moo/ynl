/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#ifndef __MLX5_PSP_H__
#define __MLX5_PSP_H__
#include <linux/mlx5/driver.h>

struct mlx5_psp {
	struct mlx5_core_dev *mdev;
};

struct mlx5_psp *mlx5_psp_create(struct mlx5_core_dev *mdev);
void mlx5_psp_destroy(struct mlx5_psp *psp);

#endif /* __MLX5_PSP_H__ */
