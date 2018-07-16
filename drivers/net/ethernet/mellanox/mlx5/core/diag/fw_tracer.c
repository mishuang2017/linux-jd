/*
 * Copyright (c) 2018, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "fw_tracer.h"

static int mlx5_query_mtrc_caps(struct mlx5_fw_tracer *tracer)
{
	u32 *string_db_base_address_out = tracer->str_db.base_address_out;
	u32 *string_db_size_out = tracer->str_db.size_out;
	struct mlx5_core_dev *dev = tracer->dev;
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	void *mtrc_cap_sp;
	int err, i;

	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_MTRC_CAP, 0, 0);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Error reading tracer caps %d\n",
			       err);
		return err;
	}

	if (!MLX5_GET(mtrc_cap, out, trace_to_memory)) {
		mlx5_core_dbg(dev, "FWTracer: Device does not support logging traces to memory\n");
		return -ENOTSUPP;
	}

	tracer->trc_ver = MLX5_GET(mtrc_cap, out, trc_ver);
	tracer->str_db.first_string_trace =
			MLX5_GET(mtrc_cap, out, first_string_trace);
	tracer->str_db.num_string_trace =
			MLX5_GET(mtrc_cap, out, num_string_trace);
	tracer->str_db.num_string_db = MLX5_GET(mtrc_cap, out, num_string_db);
	tracer->owner = !!MLX5_GET(mtrc_cap, out, trace_owner);

	for (i = 0; i < tracer->str_db.num_string_db; i++) {
		mtrc_cap_sp = MLX5_ADDR_OF(mtrc_cap, out, string_db_param[i]);
		string_db_base_address_out[i] = MLX5_GET(mtrc_string_db_param,
							 mtrc_cap_sp,
							 string_db_base_address);
		string_db_size_out[i] = MLX5_GET(mtrc_string_db_param,
						 mtrc_cap_sp, string_db_size);
	}

	return err;
}

static int mlx5_set_mtrc_caps_trace_owner(struct mlx5_fw_tracer *tracer,
					  u32 *out, u32 out_size,
					  u8 trace_owner)
{
	struct mlx5_core_dev *dev = tracer->dev;
	u32 in[MLX5_ST_SZ_DW(mtrc_cap)] = {0};

	MLX5_SET(mtrc_cap, in, trace_owner, trace_owner);

	return mlx5_core_access_reg(dev, in, sizeof(in), out, out_size,
				    MLX5_REG_MTRC_CAP, 0, 1);
}

static int mlx5_fw_tracer_ownership_acquire(struct mlx5_fw_tracer *tracer)
{
	struct mlx5_core_dev *dev = tracer->dev;
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};
	int err;

	err = mlx5_set_mtrc_caps_trace_owner(tracer, out, sizeof(out),
					     MLX5_FW_TRACER_ACQUIRE_OWNERSHIP);
	if (err) {
		mlx5_core_warn(dev, "FWTracer: Acquire tracer ownership failed %d\n",
			       err);
		return err;
	}

	tracer->owner = !!MLX5_GET(mtrc_cap, out, trace_owner);

	if (!tracer->owner)
		return -EBUSY;

	return 0;
}

static void mlx5_fw_tracer_ownership_release(struct mlx5_fw_tracer *tracer)
{
	u32 out[MLX5_ST_SZ_DW(mtrc_cap)] = {0};

	mlx5_set_mtrc_caps_trace_owner(tracer, out, sizeof(out),
				       MLX5_FW_TRACER_RELEASE_OWNERSHIP);
	tracer->owner = false;
}

static void mlx5_fw_tracer_ownership_change(struct work_struct *work)
{
	struct mlx5_fw_tracer *tracer = container_of(work, struct mlx5_fw_tracer,
						     ownership_change_work);
	struct mlx5_core_dev *dev = tracer->dev;
	int err;

	if (tracer->owner) {
		mlx5_fw_tracer_ownership_release(tracer);
		return;
	}

	err = mlx5_fw_tracer_ownership_acquire(tracer);
	if (err) {
		mlx5_core_dbg(dev, "FWTracer: Ownership was not granted %d\n", err);
		return;
	}
}

struct mlx5_fw_tracer *mlx5_fw_tracer_create(struct mlx5_core_dev *dev)
{
	struct mlx5_fw_tracer *tracer = NULL;
	int err;

	if (!MLX5_CAP_MCAM_REG(dev, tracer_registers)) {
		mlx5_core_dbg(dev, "FWTracer: Tracer capability not present\n");
		return NULL;
	}

	tracer = kzalloc(sizeof(*tracer), GFP_KERNEL);
	if (!tracer)
		return ERR_PTR(-ENOMEM);

	tracer->work_queue = create_singlethread_workqueue("mlx5_fw_tracer");
	if (!tracer->work_queue) {
		err = -ENOMEM;
		goto free_tracer;
	}

	tracer->dev = dev;

	INIT_WORK(&tracer->ownership_change_work, mlx5_fw_tracer_ownership_change);

	err = mlx5_query_mtrc_caps(tracer);
	if (err) {
		mlx5_core_dbg(dev, "FWTracer: Failed to query capabilities %d\n", err);
		goto destroy_workqueue;
	}

	mlx5_fw_tracer_ownership_change(&tracer->ownership_change_work);

	return tracer;

destroy_workqueue:
	tracer->dev = NULL;
	destroy_workqueue(tracer->work_queue);
free_tracer:
	kfree(tracer);
	return ERR_PTR(err);
}

void mlx5_fw_tracer_destroy(struct mlx5_fw_tracer *tracer)
{
	if (!tracer)
		return;

	cancel_work_sync(&tracer->ownership_change_work);

	if (tracer->owner)
		mlx5_fw_tracer_ownership_release(tracer);

	flush_workqueue(tracer->work_queue);
	destroy_workqueue(tracer->work_queue);
	kfree(tracer);
}
