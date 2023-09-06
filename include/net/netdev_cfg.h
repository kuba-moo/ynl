/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NETDEV_CFG_H
#define _LINUX_NETDEV_CFG_H

#include <linux/ethtool.h>

/**
 * struct netdev_cfg - datapath configuration for struct net_device
 */
struct netdev_cfg {
	/** @mtu: MTU of the interface */
	unsigned int mtu;

	/** @chan: ring counts */
	struct ethtool_channels chan;
};

/**
 * struct netdev_rxq_cfg - datapath configuration for an Rx queue
 */
struct netdev_rxq_cfg {
	/**
	 * @ring:  ring sizes
	 * @kring: additional ring descriptor/buffer config parameters
	 */
	struct ethtool_ringparam ring;
	struct kernel_ethtool_ringparam kring;
};

/**
 * struct netdev_nic_cfg - NIC datapath config parameters
 * @rxq_mem_size: size of the private struct holding queue memory (Rx)
 */
struct netdev_nic_cfg_info {
	unsigned int rxq_mem_size;

	/**
	 * @rxq_mem_alloc: allocate memory for a queue with given config,
	 *	qmem is a pointer to zero-initialized memory of size
	 *	@rxq_mem_size for the driver to use
	 * @rxq_mem_free: free queue memory
	 */
	int (*rxq_mem_alloc)(struct net_device *netdev,
			     const struct netdev_cfg *dcfg,
			     const struct netdev_rxq_cfg *qcfg,
			     void *qmem);
	void (*rxq_mem_free)(struct net_device *netdev,
			     const struct netdev_cfg *dcfg,
			     const struct netdev_rxq_cfg *qcfg,
			     void *qmem);
};

/* Internals start here, all the stuff below should be hidden from drivers
 * once the code covers enough configuration.
 */

struct netdev_nic_cfg {
	struct netdev_cfg cfg;

	/* dynamic state */
	struct netdev_rxq_cfg rqcfg;
	unsigned int rxq_cnt;
	void *rxqmem;

	/* global parameters */
	struct ethtool_ringparam ring;
	struct kernel_ethtool_ringparam kring;

	/* Clone when replacing */
	struct netdev_nic_cfg *other_cfg;
};

/* Prepopulate/free the current configuration, probe/remove */
int netdev_nic_cfg_init(struct net_device *netdev);
void netdev_nic_cfg_deinit(struct net_device *netdev);
/* Alloc mem for queues, ndo_open/ndo_stop */
int netdev_nic_cfg_start(struct net_device *netdev);
void netdev_nic_cfg_stop(struct net_device *netdev);

void *netdev_nic_cfg_rxqmem(struct net_device *netdev, unsigned int qid);

/* Runtime config */
int netdev_nic_recfg_start(struct net_device *netdev);
/* .. after start() caller modifies the config .. */
int netdev_nic_recfg_prep(struct net_device *netdev);
void netdev_nic_recfg_swap(struct net_device *netdev);
void netdev_nic_recfg_end(struct net_device *netdev);
#endif
