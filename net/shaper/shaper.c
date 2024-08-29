// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/xarray.h>
#include <net/devlink.h>
#include <net/net_shaper.h>

#include "shaper_nl_gen.h"

#include "../core/dev.h"

#define NET_SHAPER_SCOPE_SHIFT	26
#define NET_SHAPER_ID_MASK	GENMASK(NET_SHAPER_SCOPE_SHIFT - 1, 0)
#define NET_SHAPER_SCOPE_MASK	GENMASK(31, NET_SHAPER_SCOPE_SHIFT)

#define NET_SHAPER_ID_UNSPEC NET_SHAPER_ID_MASK

struct net_shaper_data {
	struct xarray shapers;

	/* Serialize write ops and protects node_ids updates. */
	struct mutex lock;
	struct idr node_ids;
};

struct net_shaper_nl_ctx {
	struct net_shaper_binding binding;
	netdevice_tracker dev_tracker;
	u32 start_index;
};

static struct net_shaper_binding *net_shaper_binding_from_ctx(void *ctx)
{
	return &((struct net_shaper_nl_ctx *)ctx)->binding;
}

static struct net_shaper_data *
net_shaper_binding_data(struct net_shaper_binding *binding)
{
	/* The barrier pairs with cmpxchg on init. */
	if (binding->type == NET_SHAPER_BINDING_TYPE_NETDEV)
		return READ_ONCE(binding->netdev->net_shaper_data);

	/* No other type supported yet.*/
	return NULL;
}

static struct net_shaper_data *
net_shaper_binding_set_data(struct net_shaper_binding *binding,
			    struct net_shaper_data *data)
{
	if (binding->type == NET_SHAPER_BINDING_TYPE_NETDEV)
		return cmpxchg(&binding->netdev->net_shaper_data, NULL, data);

	/* No devlink implementation yet.*/
	return NULL;
}

static const struct net_shaper_ops *
net_shaper_binding_ops(struct net_shaper_binding *binding)
{
	if (binding->type == NET_SHAPER_BINDING_TYPE_NETDEV)
		return binding->netdev->netdev_ops->net_shaper_ops;

	/* No devlink implementation yet.*/
	return NULL;
}

static int net_shaper_fill_binding(struct sk_buff *msg,
				   const struct net_shaper_binding *binding,
				   u32 type)
{
	/* Should never happen, as currently only NETDEV is supported */
	if (WARN_ON_ONCE(binding->type != NET_SHAPER_BINDING_TYPE_NETDEV))
		return -EINVAL;

	if (nla_put_u32(msg, type, binding->netdev->ifindex))
		return -EMSGSIZE;

	return 0;
}

static int net_shaper_fill_handle(struct sk_buff *msg,
				  const struct net_shaper_handle *handle,
				  u32 type)
{
	struct nlattr *handle_attr;

	if (handle->scope == NET_SHAPER_SCOPE_UNSPEC)
		return 0;

	handle_attr = nla_nest_start_noflag(msg, type);
	if (!handle_attr)
		return -EMSGSIZE;

	if (nla_put_u32(msg, NET_SHAPER_A_HANDLE_SCOPE, handle->scope) ||
	    (handle->scope >= NET_SHAPER_SCOPE_QUEUE &&
	     nla_put_u32(msg, NET_SHAPER_A_HANDLE_ID, handle->id)))
		goto handle_nest_cancel;

	nla_nest_end(msg, handle_attr);
	return 0;

handle_nest_cancel:
	nla_nest_cancel(msg, handle_attr);
	return -EMSGSIZE;
}

static int
net_shaper_fill_one(struct sk_buff *msg,
		    const struct net_shaper_binding *binding,
		    const struct net_shaper_handle *handle,
		    const struct net_shaper_info *shaper,
		    const struct genl_info *info)
{
	void *hdr;

	hdr = genlmsg_iput(msg, info);
	if (!hdr)
		return -EMSGSIZE;

	if (net_shaper_fill_binding(msg, binding, NET_SHAPER_A_IFINDEX) ||
	    net_shaper_fill_handle(msg, &shaper->parent,
				   NET_SHAPER_A_PARENT) ||
	    net_shaper_fill_handle(msg, handle, NET_SHAPER_A_HANDLE) ||
	    ((shaper->bw_min || shaper->bw_max || shaper->burst) &&
	     nla_put_u32(msg, NET_SHAPER_A_METRIC, shaper->metric)) ||
	    (shaper->bw_min &&
	     nla_put_uint(msg, NET_SHAPER_A_BW_MIN, shaper->bw_min)) ||
	    (shaper->bw_max &&
	     nla_put_uint(msg, NET_SHAPER_A_BW_MAX, shaper->bw_max)) ||
	    (shaper->burst &&
	     nla_put_uint(msg, NET_SHAPER_A_BURST, shaper->burst)) ||
	    (shaper->priority &&
	     nla_put_u32(msg, NET_SHAPER_A_PRIORITY, shaper->priority)) ||
	    (shaper->weight &&
	     nla_put_u32(msg, NET_SHAPER_A_WEIGHT, shaper->weight)))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

/* Initialize the context fetching the relevant device and
 * acquiring a reference to it.
 */
static int net_shaper_ctx_init(const struct genl_info *info, int type,
			       struct net_shaper_nl_ctx *ctx)
{
	struct net *ns = genl_info_net(info);
	struct net_device *dev;
	int ifindex;

	memset(ctx, 0, sizeof(*ctx));
	if (GENL_REQ_ATTR_CHECK(info, type))
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[type]);
	dev = netdev_get_by_index(ns, ifindex, &ctx->dev_tracker, GFP_KERNEL);
	if (!dev) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[type]);
		return -ENOENT;
	}

	if (!dev->netdev_ops->net_shaper_ops) {
		NL_SET_BAD_ATTR(info->extack, info->attrs[type]);
		netdev_put(dev, &ctx->dev_tracker);
		return -EOPNOTSUPP;
	}

	ctx->binding.type = NET_SHAPER_BINDING_TYPE_NETDEV;
	ctx->binding.netdev = dev;
	return 0;
}

static void net_shaper_ctx_cleanup(struct net_shaper_nl_ctx *ctx)
{
	if (ctx->binding.type == NET_SHAPER_BINDING_TYPE_NETDEV)
		netdev_put(ctx->binding.netdev, &ctx->dev_tracker);
}

static u32 net_shaper_handle_to_index(const struct net_shaper_handle *handle)
{
	return FIELD_PREP(NET_SHAPER_SCOPE_MASK, handle->scope) |
		FIELD_PREP(NET_SHAPER_ID_MASK, handle->id);
}

static void net_shaper_index_to_handle(u32 index,
				       struct net_shaper_handle *handle)
{
	handle->scope = FIELD_GET(NET_SHAPER_SCOPE_MASK, index);
	handle->id = FIELD_GET(NET_SHAPER_ID_MASK, index);
}

static void net_shaper_default_parent(const struct net_shaper_handle *handle,
				      struct net_shaper_handle *parent)
{
	switch (handle->scope) {
	case NET_SHAPER_SCOPE_UNSPEC:
	case NET_SHAPER_SCOPE_NETDEV:
	case __NET_SHAPER_SCOPE_MAX:
		parent->scope = NET_SHAPER_SCOPE_UNSPEC;
		break;

	case NET_SHAPER_SCOPE_QUEUE:
	case NET_SHAPER_SCOPE_NODE:
		parent->scope = NET_SHAPER_SCOPE_NETDEV;
		break;
	}
	parent->id = 0;
}

#define NET_SHAPER_CACHE_NOT_VALID XA_MARK_0

/* Lookup the given shaper inside the cache. */
static struct net_shaper_info *
net_shaper_cache_lookup(struct net_shaper_binding *binding,
			const struct net_shaper_handle *handle)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	u32 index = net_shaper_handle_to_index(handle);

	if (!data || xa_get_mark(&data->shapers, index,
				 NET_SHAPER_CACHE_NOT_VALID))
		return NULL;

	return xa_load(&data->shapers, index);
}

/* Allocate on demand the per device shaper's cache. */
static struct net_shaper_data *
net_shaper_cache_init(struct net_shaper_binding *binding,
		      struct netlink_ext_ack *extack)
{
	struct net_shaper_data *new, *data = net_shaper_binding_data(binding);

	if (!data) {
		new = kmalloc(sizeof(*data), GFP_KERNEL);
		if (!new) {
			NL_SET_ERR_MSG(extack, "Can't allocate memory for shaper data");
			return NULL;
		}

		mutex_init(&new->lock);
		xa_init(&new->shapers);
		idr_init(&new->node_ids);

		/* No lock acquired yet, we can race with other operations. */
		data = net_shaper_binding_set_data(binding, new);
		if (!data)
			data = new;
		else
			kfree(new);
	}
	return data;
}

/* Prepare the cache to actually insert the given shaper, doing
 * in advance the needed allocations.
 */
static int net_shaper_cache_pre_insert(struct net_shaper_binding *binding,
				       struct net_shaper_handle *handle,
				       struct netlink_ext_ack *extack)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_info *prev, *cur;
	bool id_allocated = false;
	int ret, id, index;

	if (!data)
		return -ENOMEM;

	index = net_shaper_handle_to_index(handle);
	cur = xa_load(&data->shapers, index);
	if (cur)
		return 0;

	/* Allocated a new id, if needed. */
	if (handle->scope == NET_SHAPER_SCOPE_NODE &&
	    handle->id == NET_SHAPER_ID_UNSPEC) {
		id = idr_alloc(&data->node_ids, NULL,
			       0, NET_SHAPER_ID_UNSPEC, GFP_ATOMIC);

		if (id < 0) {
			NL_SET_ERR_MSG(extack, "Can't allocate new id for NODE shaper");
			return id;
		}

		handle->id = id;
		index = net_shaper_handle_to_index(handle);
		id_allocated = true;
	}

	cur = kmalloc(sizeof(*cur), GFP_KERNEL | __GFP_ZERO);
	if (!cur) {
		NL_SET_ERR_MSG(extack, "Can't allocate memory for cached shaper");
		ret = -ENOMEM;
		goto free_id;
	}

	/* Mark 'tentative' shaper inside the cache. */
	xa_lock(&data->shapers);
	prev = __xa_store(&data->shapers, index, cur, GFP_KERNEL);
	__xa_set_mark(&data->shapers, index, NET_SHAPER_CACHE_NOT_VALID);
	xa_unlock(&data->shapers);
	if (xa_err(prev)) {
		NL_SET_ERR_MSG(extack, "Can't insert shaper into cache");
		kfree(cur);
		ret = xa_err(prev);
		goto free_id;
	}
	return 0;

free_id:
	if (id_allocated)
		idr_remove(&data->node_ids, handle->id);
	return ret;
}

/* Commit the tentative insert with the actual values.
 * Must be called only after a successful net_shaper_pre_insert().
 */
static void net_shaper_cache_commit(struct net_shaper_binding *binding,
				    int nr_shapers,
				    const struct net_shaper_handle *handle,
				    const struct net_shaper_info *shapers)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_info *cur;
	int index;
	int i;

	xa_lock(&data->shapers);
	for (i = 0; i < nr_shapers; ++i) {
		index = net_shaper_handle_to_index(&handle[i]);

		cur = xa_load(&data->shapers, index);
		if (WARN_ON_ONCE(!cur))
			continue;

		/* Successful update: drop the tentative mark
		 * and update the cache.
		 */
		__xa_clear_mark(&data->shapers, index,
				NET_SHAPER_CACHE_NOT_VALID);
		*cur = shapers[i];
	}
	xa_unlock(&data->shapers);
}

static int net_shaper_parse_handle(const struct nlattr *attr,
				   const struct genl_info *info,
				   struct net_shaper_handle *handle)
{
	struct nlattr *tb[NET_SHAPER_A_HANDLE_MAX + 1];
	struct nlattr *scope_attr, *id_attr;
	u32 id = 0;
	int ret;

	ret = nla_parse_nested(tb, NET_SHAPER_A_HANDLE_MAX, attr,
			       net_shaper_handle_nl_policy, info->extack);
	if (ret < 0)
		return ret;

	scope_attr = tb[NET_SHAPER_A_HANDLE_SCOPE];
	if (!scope_attr) {
		NL_SET_BAD_ATTR(info->extack,
				tb[NET_SHAPER_A_HANDLE_SCOPE]);
		return -EINVAL;
	}

	handle->scope = nla_get_u32(scope_attr);

	/* The default id for NODE scope shapers is an invalid one
	 * to help the 'group' operation discriminate between new
	 * NODE shaper creation (ID_UNSPEC) and reuse of existing
	 * shaper (any other value).
	 */
	id_attr = tb[NET_SHAPER_A_HANDLE_ID];
	if (id_attr)
		id = nla_get_u32(id_attr);
	else if (handle->scope == NET_SHAPER_SCOPE_NODE)
		id = NET_SHAPER_ID_UNSPEC;

	handle->id = id;
	return 0;
}

static int net_shaper_parse_info(struct net_shaper_binding *binding,
				 struct nlattr **tb,
				 const struct genl_info *info,
				 struct net_shaper_handle *handle,
				 struct net_shaper_info *shaper,
				 bool *cached)
{
	struct net_shaper_info *old;
	int ret;

	/* The shaper handle is the only mandatory attribute. */
	if (NL_REQ_ATTR_CHECK(info->extack, NULL, tb, NET_SHAPER_A_HANDLE))
		return -EINVAL;

	ret = net_shaper_parse_handle(tb[NET_SHAPER_A_HANDLE], info, handle);
	if (ret)
		return ret;

	if (handle->scope == NET_SHAPER_SCOPE_UNSPEC) {
		NL_SET_BAD_ATTR(info->extack,
				info->attrs[NET_SHAPER_A_HANDLE]);
		return -EINVAL;
	}

	/* Fetch existing data, if any, so that user provide info will
	 * incrementally update the existing shaper configuration.
	 */
	old = net_shaper_cache_lookup(binding, handle);
	if (old)
		*shaper = *old;
	*cached = !!old;

	if (tb[NET_SHAPER_A_METRIC])
		shaper->metric = nla_get_u32(tb[NET_SHAPER_A_METRIC]);

	if (tb[NET_SHAPER_A_BW_MIN])
		shaper->bw_min = nla_get_uint(tb[NET_SHAPER_A_BW_MIN]);

	if (tb[NET_SHAPER_A_BW_MAX])
		shaper->bw_max = nla_get_uint(tb[NET_SHAPER_A_BW_MAX]);

	if (tb[NET_SHAPER_A_BURST])
		shaper->burst = nla_get_uint(tb[NET_SHAPER_A_BURST]);

	if (tb[NET_SHAPER_A_PRIORITY])
		shaper->priority = nla_get_u32(tb[NET_SHAPER_A_PRIORITY]);

	if (tb[NET_SHAPER_A_WEIGHT])
		shaper->weight = nla_get_u32(tb[NET_SHAPER_A_WEIGHT]);
	return 0;
}

/* Fetch the cached shaper info and update them with the user-provided
 * attributes.
 */
static int net_shaper_parse_info_nest(struct net_shaper_binding *binding,
				      const struct nlattr *attr,
				      const struct genl_info *info,
				      struct net_shaper_handle *handle,
				      struct net_shaper_info *shaper)
{
	struct nlattr *tb[NET_SHAPER_A_WEIGHT + 1];
	bool cached;
	int ret;

	ret = nla_parse_nested(tb, NET_SHAPER_A_WEIGHT, attr,
			       net_shaper_info_nl_policy, info->extack);
	if (ret < 0)
		return ret;

	ret = net_shaper_parse_info(binding, tb, info, handle, shaper, &cached);
	if (ret < 0)
		return ret;

	if (!cached)
		net_shaper_default_parent(handle, &shaper->parent);
	return 0;
}

static int net_shaper_generic_pre(struct genl_info *info, int type)
{
	struct net_shaper_nl_ctx *ctx;
	int ret;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ret = net_shaper_ctx_init(info, type, ctx);
	if (ret) {
		kfree(ctx);
		return ret;
	}

	info->user_ptr[0] = ctx;
	return 0;
}

int net_shaper_nl_pre_doit(const struct genl_split_ops *ops,
			   struct sk_buff *skb, struct genl_info *info)
{
	return net_shaper_generic_pre(info, NET_SHAPER_A_IFINDEX);
}

static void net_shaper_generic_post(struct genl_info *info)
{
	struct net_shaper_nl_ctx *ctx = info->user_ptr[0];

	net_shaper_ctx_cleanup(ctx);
	kfree(ctx);
}

void net_shaper_nl_post_doit(const struct genl_split_ops *ops,
			     struct sk_buff *skb, struct genl_info *info)
{
	net_shaper_generic_post(info);
}

int net_shaper_nl_pre_dumpit(struct netlink_callback *cb)
{
	struct net_shaper_nl_ctx *ctx = (struct net_shaper_nl_ctx *)cb->ctx;
	const struct genl_info *info = genl_info_dump(cb);

	BUILD_BUG_ON(sizeof(*ctx) > sizeof(cb->ctx));

	return net_shaper_ctx_init(info, NET_SHAPER_A_IFINDEX, ctx);
}

int net_shaper_nl_post_dumpit(struct netlink_callback *cb)
{
	struct net_shaper_nl_ctx *ctx = (struct net_shaper_nl_ctx *)cb->ctx;

	net_shaper_ctx_cleanup(ctx);
	return 0;
}

int net_shaper_nl_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net_shaper_binding *binding;
	struct net_shaper_handle handle;
	struct net_shaper_info *shaper;
	struct sk_buff *msg;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, NET_SHAPER_A_HANDLE))
		return -EINVAL;

	binding = net_shaper_binding_from_ctx(info->user_ptr[0]);
	ret = net_shaper_parse_handle(info->attrs[NET_SHAPER_A_HANDLE], info,
				      &handle);
	if (ret < 0)
		return ret;

	shaper = net_shaper_cache_lookup(binding, &handle);
	if (!shaper) {
		NL_SET_BAD_ATTR(info->extack,
				info->attrs[NET_SHAPER_A_HANDLE]);
		return -ENOENT;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = net_shaper_fill_one(msg, binding, &handle, shaper, info);
	if (ret)
		goto free_msg;

	ret =  genlmsg_reply(msg, info);
	if (ret)
		goto free_msg;

	return 0;

free_msg:
	nlmsg_free(msg);
	return ret;
}

int net_shaper_nl_get_dumpit(struct sk_buff *skb,
			     struct netlink_callback *cb)
{
	struct net_shaper_nl_ctx *ctx = (struct net_shaper_nl_ctx *)cb->ctx;
	const struct genl_info *info = genl_info_dump(cb);
	struct net_shaper_binding *binding;
	struct net_shaper_handle handle;
	struct net_shaper_info *shaper;
	struct net_shaper_data *data;
	unsigned long index;
	int ret;

	/* Don't error out dumps performed before any set operation. */
	binding = net_shaper_binding_from_ctx(ctx);
	data = net_shaper_binding_data(binding);
	if (!data)
		return 0;

	xa_for_each_range(&data->shapers, index, shaper, ctx->start_index,
			  U32_MAX) {
		net_shaper_index_to_handle(index, &handle);
		ret = net_shaper_fill_one(skb, binding, &handle, shaper, info);
		if (ret)
			return ret;

		ctx->start_index = index;
	}

	return 0;
}

/* Update the H/W and on success update the local cache, too. */
static int net_shaper_set(struct net_shaper_binding *binding,
			  const struct net_shaper_handle *h,
			  const struct net_shaper_info *shaper,
			  struct netlink_ext_ack *extack)
{
	struct net_shaper_data *data = net_shaper_cache_init(binding, extack);
	const struct net_shaper_ops *ops = net_shaper_binding_ops(binding);
	struct net_shaper_handle handle = *h;
	int ret;

	if (!data)
		return -ENOMEM;

	/* Should never happen: binding lookup validates the ops presence */
	if (WARN_ON_ONCE(!ops))
		return -EOPNOTSUPP;

	mutex_lock(&data->lock);
	if (handle.scope == NET_SHAPER_SCOPE_NODE &&
	    net_shaper_cache_lookup(binding, &handle)) {
		ret = -ENOENT;
		goto unlock;
	}

	ret = net_shaper_cache_pre_insert(binding, &handle, extack);
	if (ret)
		goto unlock;

	ret = ops->set(binding, &handle, shaper, extack);
	net_shaper_cache_commit(binding, 1, &handle, shaper);

unlock:
	mutex_unlock(&data->lock);
	return ret;
}

int net_shaper_nl_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net_shaper_binding *binding;
	struct net_shaper_handle handle;
	struct net_shaper_info shaper;
	struct nlattr *attr;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, NET_SHAPER_A_SHAPER))
		return -EINVAL;

	binding = net_shaper_binding_from_ctx(info->user_ptr[0]);
	attr = info->attrs[NET_SHAPER_A_SHAPER];
	ret = net_shaper_parse_info_nest(binding, attr, info, &handle,
					 &shaper);
	if (ret)
		return ret;

	return net_shaper_set(binding, &handle, &shaper, info->extack);
}

static int __net_shaper_delete(struct net_shaper_binding *binding,
			       const struct net_shaper_handle *h,
			       struct net_shaper_info *shaper,
			       struct netlink_ext_ack *extack)
{
	const struct net_shaper_ops *ops = net_shaper_binding_ops(binding);
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_handle parent_handle, handle = *h;
	int ret;

	/* Should never happen: we are under the cache lock, the cache
	 * is already initialized.
	 */
	if (WARN_ON_ONCE(!data || !ops))
		return -EINVAL;

again:
	parent_handle = shaper->parent;

	ret = ops->delete(binding, &handle, extack);
	if (ret < 0)
		return ret;

	xa_erase(&data->shapers, net_shaper_handle_to_index(&handle));
	if (handle.scope == NET_SHAPER_SCOPE_NODE)
		idr_remove(&data->node_ids, handle.id);
	kfree(shaper);

	/* Eventually delete the parent, if it is left over with no leaves. */
	if (parent_handle.scope == NET_SHAPER_SCOPE_NODE) {
		shaper = net_shaper_cache_lookup(binding, &parent_handle);
		if (shaper && !--shaper->leaves) {
			handle = parent_handle;
			goto again;
		}
	}
	return 0;
}

static int net_shaper_delete(struct net_shaper_binding *binding,
			     const struct net_shaper_handle *handle,
			     struct netlink_ext_ack *extack)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_info *shaper;
	int ret;

	/* The lock is null when the cache is not initialized, and thus
	 * no shaper has been created yet.
	 */
	if (!data)
		return -ENOENT;

	mutex_lock(&data->lock);
	shaper = net_shaper_cache_lookup(binding, handle);
	if (!shaper) {
		ret = -ENOENT;
		goto unlock;
	}

	if (handle->scope == NET_SHAPER_SCOPE_NODE) {
		/* TODO: implement support for scope NODE delete. */
		ret = -EINVAL;
		goto unlock;
	}

	ret = __net_shaper_delete(binding, handle, shaper, extack);

unlock:
	mutex_unlock(&data->lock);
	return ret;
}

int net_shaper_nl_delete_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net_shaper_binding *binding;
	struct net_shaper_handle handle;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, NET_SHAPER_A_HANDLE))
		return -EINVAL;

	binding = net_shaper_binding_from_ctx(info->user_ptr[0]);
	ret = net_shaper_parse_handle(info->attrs[NET_SHAPER_A_HANDLE], info,
				      &handle);
	if (ret)
		return ret;

	return net_shaper_delete(binding, &handle, info->extack);
}

static void net_shaper_flush(struct net_shaper_binding *binding)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_info *cur;
	unsigned long index;

	if (!data)
		return;

	mutex_lock(&data->lock);
	xa_lock(&data->shapers);
	xa_for_each(&data->shapers, index, cur) {
		__xa_erase(&data->shapers, index);
		kfree(cur);
	}
	xa_unlock(&data->shapers);
	idr_destroy(&data->node_ids);
	mutex_unlock(&data->lock);

	kfree(data);
}

void net_shaper_flush_netdev(struct net_device *dev)
{
	struct net_shaper_binding binding = {
		.type = NET_SHAPER_BINDING_TYPE_NETDEV,
		.netdev = dev,
	};

	net_shaper_flush(&binding);
}

static int __init shaper_init(void)
{
	return genl_register_family(&net_shaper_nl_family);
}

subsys_initcall(shaper_init);
