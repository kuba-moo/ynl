// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */

#include "psp.h"

struct mlx5_psp *mlx5_psp_create(struct mlx5_core_dev *mdev)
{
	struct mlx5_psp *psp = kzalloc(sizeof(*psp), GFP_KERNEL);

	if (!psp)
		return ERR_PTR(-ENOMEM);

	psp->mdev = mdev;

	return psp;
}

void mlx5_psp_destroy(struct mlx5_psp *psp)
{
	if (IS_ERR_OR_NULL(psp))
		return;

	kfree(psp);
}
