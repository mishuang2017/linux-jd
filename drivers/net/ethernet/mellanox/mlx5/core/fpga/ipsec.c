/*
 * Copyright (c) 2017 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/mlx5/driver.h>

#include "mlx5_core.h"
#include "fpga/ipsec.h"
#include "fpga/sdk.h"
#include "fpga/core.h"

#define SBU_QP_QUEUE_SIZE 8
#define MLX5_FPGA_IPSEC_CMD_TIMEOUT_MSEC	(60 * 1000)

enum mlx5_fpga_ipsec_cmd_status {
	MLX5_FPGA_IPSEC_CMD_PENDING,
	MLX5_FPGA_IPSEC_CMD_SEND_FAIL,
	MLX5_FPGA_IPSEC_CMD_COMPLETE,
};

struct mlx5_ipsec_command_context {
	struct mlx5_fpga_dma_buf buf;
	enum mlx5_fpga_ipsec_cmd_status status;
	struct mlx5_ifc_fpga_ipsec_cmd_resp resp;
	int status_code;
	struct completion complete;
	struct mlx5_fpga_device *dev;
	struct list_head list; /* Item in pending_cmds */
	u8 command[0];
};

struct mlx5_fpga_ipsec {
	struct list_head pending_cmds;
	spinlock_t pending_cmds_lock; /* Protects pending_cmds */
	u32 caps[MLX5_ST_SZ_DW(ipsec_extended_cap)];
	struct mlx5_fpga_conn *conn;
};

static bool mlx5_fpga_is_ipsec_device(struct mlx5_core_dev *mdev)
{
	if (!mdev->fpga || !MLX5_CAP_GEN(mdev, fpga))
		return false;

	if (MLX5_CAP_FPGA(mdev, ieee_vendor_id) !=
	    MLX5_FPGA_CAP_SANDBOX_VENDOR_ID_MLNX)
		return false;

	if (MLX5_CAP_FPGA(mdev, sandbox_product_id) !=
	    MLX5_FPGA_CAP_SANDBOX_PRODUCT_ID_IPSEC)
		return false;

	return true;
}

static void mlx5_fpga_ipsec_send_complete(struct mlx5_fpga_conn *conn,
					  struct mlx5_fpga_device *fdev,
					  struct mlx5_fpga_dma_buf *buf,
					  u8 status)
{
	struct mlx5_ipsec_command_context *context;

	if (status) {
		context = container_of(buf, struct mlx5_ipsec_command_context,
				       buf);
		mlx5_fpga_warn(fdev, "IPSec command send failed with status %u\n",
			       status);
		context->status = MLX5_FPGA_IPSEC_CMD_SEND_FAIL;
		complete(&context->complete);
	}
}

static inline
int syndrome_to_errno(enum mlx5_ifc_fpga_ipsec_response_syndrome syndrome)
{
	switch (syndrome) {
	case MLX5_FPGA_IPSEC_RESPONSE_SUCCESS:
		return 0;
	case MLX5_FPGA_IPSEC_RESPONSE_SADB_ISSUE:
		return -EEXIST;
	case MLX5_FPGA_IPSEC_RESPONSE_ILLEGAL_REQUEST:
		return -EINVAL;
	case MLX5_FPGA_IPSEC_RESPONSE_WRITE_RESPONSE_ISSUE:
		return -EIO;
	}
	return -EIO;
}

static void mlx5_fpga_ipsec_recv(void *cb_arg, struct mlx5_fpga_dma_buf *buf)
{
	struct mlx5_ifc_fpga_ipsec_cmd_resp *resp = buf->sg[0].data;
	struct mlx5_ipsec_command_context *context;
	enum mlx5_ifc_fpga_ipsec_response_syndrome syndrome;
	struct mlx5_fpga_device *fdev = cb_arg;
	unsigned long flags;

	if (buf->sg[0].size < sizeof(*resp)) {
		mlx5_fpga_warn(fdev, "Short receive from FPGA IPSec: %u < %zu bytes\n",
			       buf->sg[0].size, sizeof(*resp));
		return;
	}

	mlx5_fpga_dbg(fdev, "mlx5_ipsec recv_cb syndrome %08x\n",
		      ntohl(resp->syndrome));

	spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
	context = list_first_entry_or_null(&fdev->ipsec->pending_cmds,
					   struct mlx5_ipsec_command_context,
					   list);
	if (context)
		list_del(&context->list);
	spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);

	if (!context) {
		mlx5_fpga_warn(fdev, "Received IPSec offload response without pending command request\n");
		return;
	}
	mlx5_fpga_dbg(fdev, "Handling response for %p\n", context);

	syndrome = ntohl(resp->syndrome);
	context->status_code = syndrome_to_errno(syndrome);
	context->status = MLX5_FPGA_IPSEC_CMD_COMPLETE;
	memcpy(&context->resp, resp, sizeof(*resp));

	if (context->status_code)
		mlx5_fpga_warn(fdev, "IPSec command failed with syndrome %08x\n",
			       syndrome);

	complete(&context->complete);
}

static void *mlx5_fpga_ipsec_cmd_exec(struct mlx5_core_dev *mdev,
				      const void *cmd, int cmd_size)
{
	struct mlx5_ipsec_command_context *context;
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned long flags;
	int res;

	if (!fdev || !fdev->ipsec)
		return ERR_PTR(-EOPNOTSUPP);

	if (cmd_size & 3)
		return ERR_PTR(-EINVAL);

	context = kzalloc(sizeof(*context) + cmd_size, GFP_ATOMIC);
	if (!context)
		return ERR_PTR(-ENOMEM);

	context->status = MLX5_FPGA_IPSEC_CMD_PENDING;
	context->dev = fdev;
	context->buf.complete = mlx5_fpga_ipsec_send_complete;
	init_completion(&context->complete);
	memcpy(&context->command, cmd, cmd_size);
	context->buf.sg[0].size = cmd_size;
	context->buf.sg[0].data = &context->command;

	spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
	list_add_tail(&context->list, &fdev->ipsec->pending_cmds);
	spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);

	res = mlx5_fpga_sbu_conn_sendmsg(fdev->ipsec->conn, &context->buf);
	if (res) {
		mlx5_fpga_warn(fdev, "Failure sending IPSec command: %d\n",
			       res);
		spin_lock_irqsave(&fdev->ipsec->pending_cmds_lock, flags);
		list_del(&context->list);
		spin_unlock_irqrestore(&fdev->ipsec->pending_cmds_lock, flags);
		kfree(context);
		return ERR_PTR(res);
	}
	/* Context will be freed by wait func after completion */
	return context;
}

static int mlx5_fpga_ipsec_cmd_wait(void *ctx)
{
	struct mlx5_ipsec_command_context *context = ctx;
	unsigned long timeout =
		msecs_to_jiffies(MLX5_FPGA_IPSEC_CMD_TIMEOUT_MSEC);
	int res;

	res = wait_for_completion_timeout(&context->complete, timeout);
	if (!res) {
		mlx5_fpga_warn(context->dev, "Failure waiting for IPSec command response\n");
		return -ETIMEDOUT;
	}

	if (context->status == MLX5_FPGA_IPSEC_CMD_COMPLETE)
		res = context->status_code;
	else
		res = -EIO;

	return res;
}

void *mlx5_fpga_ipsec_sa_cmd_exec(struct mlx5_core_dev *mdev,
				  struct mlx5_accel_ipsec_sa *cmd, int cmd_size)
{
	return mlx5_fpga_ipsec_cmd_exec(mdev, cmd, cmd_size);
}

int mlx5_fpga_ipsec_sa_cmd_wait(void *ctx)
{
	struct mlx5_ipsec_command_context *context = ctx;
	struct mlx5_accel_ipsec_sa *sa;
	int res;

	res = mlx5_fpga_ipsec_cmd_wait(ctx);
	if (res)
		goto out;

	sa = (struct mlx5_accel_ipsec_sa *)&context->command;
	if (sa->ipsec_sa_v1.sw_sa_handle != context->resp.sw_sa_handle) {
		mlx5_fpga_err(context->dev, "mismatch SA handle. cmd 0x%08x vs resp 0x%08x\n",
			      ntohl(sa->ipsec_sa_v1.sw_sa_handle),
			      ntohl(context->resp.sw_sa_handle));
		res = -EIO;
	}

out:
	kfree(context);
	return res;
}

u32 mlx5_fpga_ipsec_device_caps(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	u32 ret = 0;

	if (mlx5_fpga_is_ipsec_device(mdev)) {
		ret |= MLX5_ACCEL_IPSEC_CAP_DEVICE;
		ret |= MLX5_ACCEL_IPSEC_CAP_REQUIRED_METADATA;
	} else {
		return ret;
	}

	if (!fdev->ipsec)
		return ret;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, esp))
		ret |= MLX5_ACCEL_IPSEC_CAP_ESP;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, ipv6))
		ret |= MLX5_ACCEL_IPSEC_CAP_IPV6;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, lso))
		ret |= MLX5_ACCEL_IPSEC_CAP_LSO;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, rx_no_trailer))
		ret |= MLX5_ACCEL_IPSEC_CAP_RX_NO_TRAILER;

	if (MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps, v2_command))
		ret |= MLX5_ACCEL_IPSEC_CAP_V2_CMD;

	return ret;
}

unsigned int mlx5_fpga_ipsec_counters_count(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!fdev || !fdev->ipsec)
		return 0;

	return MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			number_of_ipsec_counters);
}

int mlx5_fpga_ipsec_counters_read(struct mlx5_core_dev *mdev, u64 *counters,
				  unsigned int counters_count)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;
	unsigned int i;
	__be32 *data;
	u32 count;
	u64 addr;
	int ret;

	if (!fdev || !fdev->ipsec)
		return 0;

	addr = (u64)MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			     ipsec_counters_addr_low) +
	       ((u64)MLX5_GET(ipsec_extended_cap, fdev->ipsec->caps,
			     ipsec_counters_addr_high) << 32);

	count = mlx5_fpga_ipsec_counters_count(mdev);

	data = kzalloc(sizeof(*data) * count * 2, GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mlx5_fpga_mem_read(fdev, count * sizeof(u64), addr, data,
				 MLX5_FPGA_ACCESS_TYPE_DONTCARE);
	if (ret < 0) {
		mlx5_fpga_err(fdev, "Failed to read IPSec counters from HW: %d\n",
			      ret);
		goto out;
	}
	ret = 0;

	if (count > counters_count)
		count = counters_count;

	/* Each counter is low word, then high. But each word is big-endian */
	for (i = 0; i < count; i++)
		counters[i] = (u64)ntohl(data[i * 2]) |
			      ((u64)ntohl(data[i * 2 + 1]) << 32);

out:
	kfree(data);
	return ret;
}

static int mlx5_fpga_ipsec_set_caps(struct mlx5_core_dev *mdev, u32 flags)
{
	struct mlx5_ipsec_command_context *context;
	struct mlx5_ifc_fpga_ipsec_cmd_cap cmd = {0};
	int err;

	cmd.cmd = htonl(MLX5_IPSEC_CMD_SET_CAP);
	cmd.flags = htonl(flags);
	context = mlx5_fpga_ipsec_cmd_exec(mdev, &cmd, sizeof(cmd));
	if (IS_ERR(context)) {
		err = PTR_ERR(context);
		goto out;
	}

	err = mlx5_fpga_ipsec_cmd_wait(context);
	if (err)
		goto out;

	if ((context->resp.flags & cmd.flags) != cmd.flags) {
		mlx5_fpga_err(context->dev, "Failed to set capabilities. cmd 0x%08x vs resp 0x%08x\n",
			      cmd.flags,
			      context->resp.flags);
		err = -EIO;
	}

out:
	return err;
}

static int mlx5_fpga_ipsec_enable_supported_caps(struct mlx5_core_dev *mdev)
{
	u32 dev_caps = mlx5_fpga_ipsec_device_caps(mdev);
	u32 flags = 0;

	if (dev_caps & MLX5_ACCEL_IPSEC_CAP_RX_NO_TRAILER)
		flags |= MLX5_FPGA_IPSEC_CAP_NO_TRAILER;

	return mlx5_fpga_ipsec_set_caps(mdev, flags);
}

int mlx5_fpga_ipsec_init(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_conn_attr init_attr = {0};
	struct mlx5_fpga_device *fdev = mdev->fpga;
	struct mlx5_fpga_conn *conn;
	int err;

	if (!mlx5_fpga_is_ipsec_device(mdev))
		return 0;

	fdev->ipsec = kzalloc(sizeof(*fdev->ipsec), GFP_KERNEL);
	if (!fdev->ipsec)
		return -ENOMEM;

	err = mlx5_fpga_get_sbu_caps(fdev, sizeof(fdev->ipsec->caps),
				     fdev->ipsec->caps);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to retrieve IPSec extended capabilities: %d\n",
			      err);
		goto error;
	}

	INIT_LIST_HEAD(&fdev->ipsec->pending_cmds);
	spin_lock_init(&fdev->ipsec->pending_cmds_lock);

	init_attr.rx_size = SBU_QP_QUEUE_SIZE;
	init_attr.tx_size = SBU_QP_QUEUE_SIZE;
	init_attr.recv_cb = mlx5_fpga_ipsec_recv;
	init_attr.cb_arg = fdev;
	conn = mlx5_fpga_sbu_conn_create(fdev, &init_attr);
	if (IS_ERR(conn)) {
		err = PTR_ERR(conn);
		mlx5_fpga_err(fdev, "Error creating IPSec command connection %d\n",
			      err);
		goto error;
	}
	fdev->ipsec->conn = conn;

	err = mlx5_fpga_ipsec_enable_supported_caps(mdev);
	if (err) {
		mlx5_fpga_err(fdev, "Failed to enable IPSec extended capabilities: %d\n",
			      err);
		goto err_destroy_conn;
	}

	return 0;

err_destroy_conn:
	mlx5_fpga_sbu_conn_destroy(conn);

error:
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
	return err;
}

void mlx5_fpga_ipsec_cleanup(struct mlx5_core_dev *mdev)
{
	struct mlx5_fpga_device *fdev = mdev->fpga;

	if (!mlx5_fpga_is_ipsec_device(mdev))
		return;

	mlx5_fpga_sbu_conn_destroy(fdev->ipsec->conn);
	kfree(fdev->ipsec);
	fdev->ipsec = NULL;
}
