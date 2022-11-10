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

	struct list_head active_socks;
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
	 * @assoc_drv_spc: size of driver-specific state in Tx assoc
	 * Determines the size of struct psp_assoc::drv_spc
	 */
	u32 assoc_drv_spc;
};

#define PSP_MAX_KEY	16

struct psp_key_parsed {
	u32 spi;
	u8 key[PSP_MAX_KEY];
};

struct psp_assoc {
	struct psp_dev *psd;

	struct psp_key_parsed tx;
	struct psp_key_parsed rx;

	u8 version;

	refcount_t refcnt;
	struct rcu_head rcu;
	struct work_struct work;

	u8 drv_data[] __aligned(8);
};

struct psp_sock_state {
	struct psp_dev *psd;
	struct psp_assoc *tx;

	struct list_head dev;
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
	 * @rx_spi_alloc: allocate an Rx SPI+key pair
	 * Allocate an Rx SPI and resulting derived key.
	 * This key should remain valid until key rotation.
	 */
	int (*rx_spi_alloc)(struct psp_dev *psd, u32 version,
			    struct psp_key_parsed *assoc,
			    struct netlink_ext_ack *extack);

	/**
	 * @assoc_add: add an association
	 * Install an association in the device. Core will allocate space
	 * for the driver to use at drv_data.
	 * @assoc_del: remove an association
	 * Remove an association from the device.
	 */
	int (*assoc_add)(struct psp_dev *psd, struct psp_assoc *pas,
			 struct netlink_ext_ack *extack);
	void (*assoc_del)(struct psp_dev *psd, struct psp_assoc *pas);
};

/* Driver-facing API */
struct psp_dev *
psp_dev_create(struct net_device *netdev, struct psp_dev_ops *psd_ops,
	       struct psp_dev_caps *psd_caps, void *priv_ptr);
void psp_dev_unregister(struct psp_dev *psd);

/* Kernel-facing API */
void psp_assoc_put(struct psp_assoc *pas);

#ifdef CONFIG_PSP
void psp_sk_assoc_free(struct sock *sk);
#else
static inline void psp_sk_assoc_free(struct sock *sk) { }
#endif

#endif /* __NET_PSP_H */
