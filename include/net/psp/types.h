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
 * @generation:	current generation of the main key
 * @config:	current device configuration
 * @active_assocs:	list of registered associations
 * @prev_assocs:	associations which use old (but still usable) main key
 * @stale_assocs:	associations which use a rotated out key
 *
 * @stats.rotations:	See stats attr key-rotations
 * @stats.stales:	See stats attr stale-events
 */
struct psp_dev {
	struct net_device *main_netdev;

	struct psp_dev_ops *ops;
	struct psp_dev_caps *caps;
	void *drv_priv;

	struct mutex lock;
	refcount_t refcnt;

	u32 id;

	u8 generation;

	struct psp_dev_config config;

	struct list_head active_assocs;
	struct list_head prev_assocs;
	struct list_head stale_assocs;

	struct {
		unsigned long rotations;
		unsigned long stales;
	} stats;
};

#define PSP_GEN_VALID_MASK	0x7f

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

#define PSP_MAX_KEY	32

struct psp_skb_ext {
	__be32 spi;
	u16 generation;
	u16 version; /* version is just u8 but we don't want holes */
};

struct psp_key_parsed {
	__be32 spi;
	u8 key[PSP_MAX_KEY];
};

struct psp_assoc {
	struct psp_dev *psd;

	struct psp_key_parsed tx;
	struct psp_key_parsed rx;

	u8 generation;
	u8 version;
	u8 rx_required;

	refcount_t refcnt;
	struct rcu_head rcu;
	struct work_struct work;
	struct list_head assocs_list;

	u8 drv_data[] __aligned(8);
};

struct psp_dev_stats {
	union {
		struct {
			u64 rx_packets;
			u64 rx_bytes;
		};
		DECLARE_FLEX_ARRAY(u64, required);
	};
	char required_end[0];

	/* optional stats would go here */
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
	 * @key_rotate: rotate the main key
	 */
	int (*key_rotate)(struct psp_dev *psd, struct netlink_ext_ack *extack);

	/**
	 * @rx_spi_alloc: allocate an Rx SPI+key pair
	 * Allocate an Rx SPI and resulting derived key.
	 * This key should remain valid until key rotation.
	 */
	int (*rx_spi_alloc)(struct psp_dev *psd, u32 version,
			    struct psp_key_parsed *assoc,
			    struct netlink_ext_ack *extack);

	/**
	 * @tx_key_add: add a Tx key to the device
	 * Install an association in the device. Core will allocate space
	 * for the driver to use at drv_data.
	 * @tx_key_del: remove a Tx key from the device
	 * Remove an association from the device.
	 */
	int (*tx_key_add)(struct psp_dev *psd, struct psp_assoc *pas,
			  struct netlink_ext_ack *extack);
	void (*tx_key_del)(struct psp_dev *psd, struct psp_assoc *pas);

	/**
	 * @get_stats: get statistics from the device
	 * Stats required by the spec must be maintained and filled in.
	 * Stats must be filled in member-by-member, never memset the struct.
	 */
	void (*get_stats)(struct psp_dev *psd, struct psp_dev_stats *stats);
};

#endif /* __NET_PSP_H */
