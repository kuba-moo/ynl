/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _NET_SHAPER_H_
#define _NET_SHAPER_H_

#include <linux/types.h>

#include <uapi/linux/net_shaper.h>

struct net_device;
struct devlink;
struct netlink_ext_ack;

enum net_shaper_binding_type {
	NET_SHAPER_BINDING_TYPE_NETDEV,
	/* NET_SHAPER_BINDING_TYPE_DEVLINK_PORT, */
};

struct net_shaper_binding {
	enum net_shaper_binding_type type;
	union {
		struct net_device *netdev;
		struct devlink *devlink;
	};
};

struct net_shaper_handle {
	enum net_shaper_scope scope;
	int id;
};

/**
 * struct net_shaper_info - represents a shaping node on the NIC H/W
 * zeroed field are considered not set.
 * @parent: Unique identifier for the shaper parent, usually implied
 * @metric: Specify if the rate limits refers to PPS or BPS
 * @bw_min: Minimum guaranteed rate for this shaper
 * @bw_max: Maximum peak rate allowed for this shaper
 * @burst: Maximum burst for the peek rate of this shaper
 * @priority: Scheduling priority for this shaper
 * @weight: Scheduling weight for this shaper
 */
struct net_shaper_info {
	struct net_shaper_handle parent;
	enum net_shaper_metric metric;
	u64 bw_min;
	u64 bw_max;
	u64 burst;
	u32 priority;
	u32 weight;

	/* private: */
	u32 leaves; /* accounted only for NODE scope */
};

/**
 * struct net_shaper_ops - Operations on device H/W shapers
 *
 * The operations applies to either net_device and devlink objects.
 * The initial shaping configuration at device initialization is empty:
 * does not constraint the rate in any way.
 * The network core keeps track of the applied user-configuration in
 * the net_device or devlink structure.
 * The operations are serialized via a per device lock.
 *
 * Each shaper is uniquely identified within the device with a 'handle'
 * comprising the shaper scope and a scope-specific id.
 */
struct net_shaper_ops {
	/**
	 * @group: create the specified shapers scheduling group
	 *
	 * Nest the @leaves shapers identified by @leaves_handles under the
	 * @root shaper identified by @root_handle. All the shapers belong
	 * to the network device @dev. The @leaves and @leaves_handles shaper
	 * arrays size is specified by @leaves_count.
	 * Create either the @leaves and the @root shaper; or if they already
	 * exists, links them together in the desired way.
	 * @leaves scope must be NET_SHAPER_SCOPE_QUEUE.
	 */
	int (*group)(struct net_shaper_binding *binding, int leaves_count,
		     const struct net_shaper_handle *leaves_handles,
		     const struct net_shaper_info *leaves,
		     const struct net_shaper_handle *root_handle,
		     const struct net_shaper_info *root,
		     struct netlink_ext_ack *extack);

	/**
	 * @set: Updates the specified shaper
	 *
	 * Updates or creates the @shaper identified by the provided @handle
	 * on the given device @dev.
	 */
	int (*set)(struct net_shaper_binding *binding,
		   const struct net_shaper_handle *handle,
		   const struct net_shaper_info *shaper,
		   struct netlink_ext_ack *extack);

	/**
	 * @delete: Removes the specified shaper
	 *
	 * Removes the shaper configuration as identified by the given @handle
	 * on the specified device @dev, restoring the default behavior.
	 */
	int (*delete)(struct net_shaper_binding *binding,
		      const struct net_shaper_handle *handle,
		      struct netlink_ext_ack *extack);

	/**
	 * @capabilities: get the shaper features supported by the device
	 *
	 * Fills the bitmask @cap with the supported capabilities for the
	 * specified @scope and device @dev.
	 */
	void (*capabilities)(struct net_shaper_binding *binding,
			     enum net_shaper_scope scope, unsigned long *cap);
};

#endif
