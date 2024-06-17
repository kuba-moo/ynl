// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
#include <linux/workqueue.h>
#include <net/psp/types.h>
#include "mlx5_core.h"
#include "en_accel/psp.h"

int mlx5e_psp_rotate_key(struct mlx5_core_dev *mdev)
{
	u32 in[MLX5_ST_SZ_DW(psp_rotate_key_in)] = {};
	u32 out[MLX5_ST_SZ_DW(psp_rotate_key_out)];

	MLX5_SET(psp_rotate_key_in, in, opcode,
		 MLX5_CMD_OP_PSP_ROTATE_KEY);

	return mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
}

int mlx5e_psp_generate_key_spi(struct mlx5_core_dev *mdev,
			       enum mlx5_psp_gen_spi_in_key_size keysz,
			       unsigned int keysz_bytes,
			       struct psp_key_spi *keys)
{
	u32 in[MLX5_ST_SZ_DW(psp_gen_spi_in)] = {};
	int err, outlen, i;
	void *out, *outkey;

	WARN_ON_ONCE(keysz_bytes > PSP_MAX_KEY);

	outlen = MLX5_ST_SZ_BYTES(psp_gen_spi_out) + MLX5_ST_SZ_BYTES(key_spi);
	out = kzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(psp_gen_spi_in, in, opcode, MLX5_CMD_OP_PSP_GEN_SPI);
	MLX5_SET(psp_gen_spi_in, in, key_size, keysz);
	MLX5_SET(psp_gen_spi_in, in, num_of_spi, 1);
	err = mlx5_cmd_exec(mdev, in, sizeof(in), out, outlen);
	if (err)
		goto out;

	outkey = MLX5_ADDR_OF(psp_gen_spi_out, out, key_spi);
	keys->keysz = keysz_bytes * BITS_PER_BYTE;
	keys->spi = MLX5_GET(key_spi, outkey, spi);
	for (i = 0; i < keysz_bytes / sizeof(*keys->key); ++i)
		keys->key[i] = cpu_to_be32(MLX5_GET(key_spi,
						    outkey + (32 - keysz_bytes), key[i]));

out:
	kfree(out);
	return err;
}
