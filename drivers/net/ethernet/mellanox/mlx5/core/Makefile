# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Mellanox 5th generation network adapters
# (ConnectX series) core & netdev driver
#

subdir-ccflags-y += -I$(src)

obj-$(CONFIG_MLX5_CORE) += mlx5_core.o

#
# mlx5 core basic
#
mlx5_core-y :=	main.o cmd.o debugfs.o fw.o eq.o uar.o pagealloc.o \
		health.o mcg.o cq.o srq.o alloc.o qp.o port.o mr.o pd.o \
		mad.o transobj.o vport.o sriov.o fs_cmd.o fs_core.o \
		fs_counters.o rl.o lag.o dev.o wq.o lib/gid.o  \
		diag/fs_tracepoint.o diag/fw_tracer.o

#
# Netdev basic
#
mlx5_core-$(CONFIG_MLX5_CORE_EN) += en_main.o en_common.o en_fs.o en_ethtool.o \
		en_tx.o en_rx.o en_dim.o en_txrx.o en_stats.o \
		en_selftest.o en/port.o

#
# Netdev extra
#
mlx5_core-$(CONFIG_MLX5_EN_ARFS)     += en_arfs.o
mlx5_core-$(CONFIG_MLX5_EN_RXNFC)    += en_fs_ethtool.o
mlx5_core-$(CONFIG_MLX5_CORE_EN_DCB) += en_dcbnl.o en/port_buffer.o
mlx5_core-$(CONFIG_MLX5_ESWITCH)     += en_rep.o en_tc.o

#
# Core extra
#
mlx5_core-$(CONFIG_MLX5_ESWITCH)   += eswitch.o eswitch_offloads.o
mlx5_core-$(CONFIG_MLX5_MPFS)      += lib/mpfs.o
mlx5_core-y += lib/vxlan.o
mlx5_core-y += lib/clock.o

#
# Ipoib netdev
#
mlx5_core-$(CONFIG_MLX5_CORE_IPOIB) += ipoib/ipoib.o ipoib/ethtool.o ipoib/ipoib_vlan.o

#
# Accelerations & FPGA
#
mlx5_core-$(CONFIG_MLX5_ACCEL) += accel/ipsec.o accel/tls.o

mlx5_core-$(CONFIG_MLX5_FPGA) += fpga/cmd.o fpga/core.o fpga/conn.o fpga/sdk.o \
				 fpga/ipsec.o fpga/tls.o

mlx5_core-$(CONFIG_MLX5_EN_IPSEC) += en_accel/ipsec.o en_accel/ipsec_rxtx.o \
				     en_accel/ipsec_stats.o

mlx5_core-$(CONFIG_MLX5_EN_TLS) += en_accel/tls.o en_accel/tls_rxtx.o en_accel/tls_stats.o

CFLAGS_tracepoint.o := -I$(src)
