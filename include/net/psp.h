/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __NET_PSP_H
#define __NET_PSP_H

#include <linux/mutex.h>
#include <linux/refcount.h>

struct net_device;
struct netlink_ext_ack;

/**
 * struct psp_dev_config - PSP device configuration
 * @versions: PSP versions enabled on the device
 */
struct psp_dev_config {
	u32 versions;
};

/**
 * struct psp_dev - PSP device struct allocated by the driver
 * @main_netdev: original netdevice of this PSP device
 * @ops:	driver callbacks
 * @caps:	device capabilities
 * @drv_priv:	driver priv pointer
 * @lock:	instance lock, protects all fields
 * @refcnt:	reference count for the instance
 * @id:		instance id
 * @config:	current device configuration
 */
struct psp_dev {
	struct net_device *main_netdev;

	struct psp_dev_ops *ops;
	struct psp_dev_caps *caps;
	void *drv_priv;

	struct mutex lock;
	refcount_t refcnt;

	u32 id;

	struct psp_dev_config config;
};

/**
 * struct psp_dev_caps - PSP device capabilities
 */
struct psp_dev_caps {
	/**
	 * @versions: mask of supported PSP versions
	 * Set this field to 0 to indicate PSP is not supported at all.
	 */
	u32 versions;

	/**
	 * @tx_assoc_drv_spc: size of driver-specific state in Tx assoc
	 * Determines the size of struct psp_tx_assoc::drv_spc
	 */
	u32 tx_assoc_drv_spc;
};

#define PSP_MAX_KEY	16

struct psp_tx_assoc {
	refcount_t refcnt;

	u32 spi;
	u8 key[PSP_MAX_KEY];
	u8 version;

	u8 drv_data[] __aligned(8);
};

/**
 * struct psp_dev_ops - netdev driver facing PSP callbacks
 */
struct psp_dev_ops {
	/**
	 * @set_config: set configuration of a PSP device
	 * Driver can inspect @psd->config for the previous configuration.
	 * Core will update @psd->config with @config on success.
	 */
	int (*set_config)(struct psp_dev *psd, struct psp_dev_config *conf,
			  struct netlink_ext_ack *extack);

	/**
	 * @tx_assoc_add: add a Tx association
	 * Install Tx association in the device. Core will allocate space
	 * for the driver to use at drv_data.
	 */
	int (*tx_assoc_add)(struct psp_dev *psd, struct psp_tx_assoc *tas,
			    struct netlink_ext_ack *extack);
};

struct psp_dev *
psp_dev_create(struct net_device *netdev, struct psp_dev_ops *psd_ops,
	       struct psp_dev_caps *psd_caps, void *priv_ptr);
void psp_dev_unregister(struct psp_dev *psd);

#endif /* __NET_PSP_H */
