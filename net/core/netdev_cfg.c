/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/netdevice.h>
#include <net/netdev_cfg.h>

static int
netdev_nic_cfg_rxqmem_alloc(struct net_device *dev, struct netdev_nic_cfg *nic)
{
	const struct netdev_nic_cfg_info *info = dev->nic_cfg_info;
	struct netdev_cfg *dcfg = &nic->cfg;
	unsigned int i;
	int err;

	if (WARN_ON(!nic->rxq_cnt))
		return -EINVAL;

	nic->rxqmem = kvcalloc(nic->rxq_cnt, info->rxq_mem_size, GFP_KERNEL);
	if (!nic->rxqmem)
		return -ENOMEM;

	memcpy(&nic->rqcfg.ring, &nic->ring, sizeof(nic->ring));
	memcpy(&nic->rqcfg.kring, &nic->kring, sizeof(nic->kring));

	for (i = 0; i < nic->rxq_cnt; i++) {
		void *qmem = nic->rxqmem + i * info->rxq_mem_size;

		err = info->rxq_mem_alloc(dev, dcfg, &nic->rqcfg, qmem);
		if (err)
			goto err_qmem_free_prev;
	}

	return 0;

err_qmem_free_prev:
	while (i--) {
		void *qmem = nic->rxqmem + i * info->rxq_mem_size;

		info->rxq_mem_free(dev, dcfg, &nic->rqcfg, qmem);
	}
	kvfree(nic->rxqmem);
	nic->rxqmem = NULL;
	return err;
}

static void
netdev_nic_cfg_rxqmem_free(struct net_device *dev, struct netdev_nic_cfg *nic)
{
	const struct netdev_nic_cfg_info *info = dev->nic_cfg_info;
	unsigned int i;

	for (i = 0; i < nic->rxq_cnt; i++) {
		void *qmem = nic->rxqmem + i * info->rxq_mem_size;

		info->rxq_mem_free(dev, &nic->cfg, &nic->rqcfg, qmem);
	}
	kvfree(nic->rxqmem);
	nic->rxqmem = NULL;
}

int netdev_nic_cfg_init(struct net_device *dev)
{
	struct netdev_nic_cfg *nic;

	if (WARN_ON(!dev->nic_cfg_info ||
		    !dev->nic_cfg_info->rxq_mem_size))
		return -EINVAL;

	nic = kzalloc(sizeof(*nic), GFP_KERNEL);
	if (!nic)
		return -ENOMEM;

	nic->cfg.mtu = dev->mtu;
	dev->ethtool_ops->get_channels(dev, &nic->cfg.chan);
	dev->ethtool_ops->get_ringparam(dev, &nic->ring, &nic->kring, NULL);

	dev->nic_cfg = nic;

	return 0;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_init);

void netdev_nic_cfg_deinit(struct net_device *dev)
{
	WARN_ON(dev->nic_cfg->rxqmem || dev->nic_cfg->rxq_cnt);
	WARN_ON(dev->nic_cfg->other_cfg);
	kfree(dev->nic_cfg);
	dev->nic_cfg = NULL;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_deinit);

int netdev_nic_cfg_start(struct net_device *dev)
{
	struct ethtool_channels *chan = &dev->nic_cfg->cfg.chan;
	struct netdev_nic_cfg *nic = dev->nic_cfg;
	int err;

	/* Make sure driver already set the real_num_rx_queues */
	if (dev->real_num_rx_queues != chan->combined_count + chan->rx_count &&
	    dev->real_num_rx_queues != max(chan->combined_count,
					   chan->rx_count)) {
		WARN_ON(1);
		return -EINVAL;
	}

	nic->rxq_cnt = dev->real_num_rx_queues;

	err = netdev_nic_cfg_rxqmem_alloc(dev, nic);
	if (err)
		goto err_clear_qcnt;

	return 0;

err_clear_qcnt:
	nic->rxq_cnt = 0;
	return err;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_start);

void netdev_nic_cfg_stop(struct net_device *dev)
{
	netdev_nic_cfg_rxqmem_free(dev, dev->nic_cfg);
	dev->nic_cfg->rxq_cnt = 0;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_stop);

void *netdev_nic_cfg_rxqmem(struct net_device *dev, unsigned int qid)
{
	struct netdev_nic_cfg *nic = dev->nic_cfg;

	if (WARN_ON_ONCE(qid >= nic->rxq_cnt))
		return NULL;
	return nic->rxqmem + qid * dev->nic_cfg_info->rxq_mem_size;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_rxqmem);

int netdev_nic_recfg_start(struct net_device *dev)
{
	struct netdev_nic_cfg *new_cfg;

	if (WARN_ON(dev->nic_cfg->other_cfg))
		return -EBUSY;

	new_cfg = kmemdup(dev->nic_cfg, sizeof(*dev->nic_cfg), GFP_KERNEL);
	if (!new_cfg)
		return -ENOMEM;

	memset(&new_cfg->rqcfg, 0, sizeof(new_cfg->rqcfg));
	new_cfg->rxq_cnt = 0;
	new_cfg->rxqmem = NULL;

	dev->nic_cfg->other_cfg = new_cfg;

	return 0;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_start);

int netdev_nic_recfg_prep(struct net_device *dev)
{
	struct netdev_nic_cfg *nic = dev->nic_cfg->other_cfg;
	int err;

	if (!nic->rxq_cnt)
		nic->rxq_cnt = dev->real_num_rx_queues;

	err = netdev_nic_cfg_rxqmem_alloc(dev, nic);
	if (err)
		goto err_clear_qcnt;

	return 0;

err_clear_qcnt:
	nic->rxq_cnt = 0;
	return err;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_prep);

void netdev_nic_recfg_swap(struct net_device *dev)
{
	struct netdev_nic_cfg *new, *old;

	old = dev->nic_cfg;
	new = old->other_cfg;

	dev->nic_cfg = new;
	new->other_cfg = old;
	old->other_cfg = NULL;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_swap);

void netdev_nic_recfg_end(struct net_device *dev)
{
	netdev_nic_cfg_rxqmem_free(dev, dev->nic_cfg->other_cfg);
	kfree(dev->nic_cfg->other_cfg);
	dev->nic_cfg->other_cfg = NULL;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_end);
