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
};

#define PSP_MAX_KEY	32

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
};

#endif /* __NET_PSP_H */
