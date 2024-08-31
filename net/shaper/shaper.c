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

static void net_shaper_lock(struct net_shaper_binding *binding)
{
	switch (binding->type) {
	case NET_SHAPER_BINDING_TYPE_NETDEV:
		mutex_lock(&binding->netdev->lock);
		break;
	}
}

static void net_shaper_unlock(struct net_shaper_binding *binding)
{
	switch (binding->type) {
	case NET_SHAPER_BINDING_TYPE_NETDEV:
		mutex_unlock(&binding->netdev->lock);
		break;
	}
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

static const struct net_shaper_ops *
net_shaper_binding_ops(struct net_shaper_binding *binding)
{
	if (binding->type == NET_SHAPER_BINDING_TYPE_NETDEV)
		return binding->netdev->netdev_ops->net_shaper_ops;

	/* No devlink implementation yet.*/
	return NULL;
}

/* Count the number of [multi] attributes of the given type. */
static int net_shaper_list_len(struct genl_info *info, int type)
{
	struct nlattr *attr;
	int rem, cnt = 0;

	nla_for_each_attr_type(attr, type, genlmsg_data(info->genlhdr),
			       genlmsg_len(info->genlhdr), rem)
		cnt++;
	return cnt;
}

static int net_shaper_handle_size(void)
{
	return nla_total_size(nla_total_size(sizeof(u32)) +
			      nla_total_size(sizeof(u32)));
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
	struct net_shaper_data *new, *data;

	data = net_shaper_binding_data(binding);
	if (likely(data))
		return data;

	new = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!new)
		return NULL;

	switch (binding->type) {
	case NET_SHAPER_BINDING_TYPE_NETDEV:
		binding->netdev->net_shaper_data = data;
		break;
	}

	xa_init(&new->shapers);
	idr_init(&new->node_ids);
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

/* Rollback all the tentative inserts from the shaper cache. */
static void net_shaper_cache_rollback(struct net_shaper_binding *binding)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_handle handle;
	struct net_shaper_info *cur;
	unsigned long index;

	if (!data)
		return;

	xa_lock(&data->shapers);
	xa_for_each_marked(&data->shapers, index, cur,
			   NET_SHAPER_CACHE_NOT_VALID) {
		net_shaper_index_to_handle(index, &handle);
		if (handle.scope == NET_SHAPER_SCOPE_NODE)
			idr_remove(&data->node_ids, handle.id);
		__xa_erase(&data->shapers, index);
		kfree(cur);
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
		NL_SET_BAD_ATTR(info->extack, tb[NET_SHAPER_A_HANDLE_SCOPE]);
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

static int net_shaper_validate_caps(struct net_shaper_binding *binding,
				    struct nlattr **tb,
				    const struct genl_info *info,
				    struct net_shaper_handle *handle,
				    struct net_shaper_info *shaper,
				    bool nest)
{
	const struct net_shaper_ops *ops = net_shaper_binding_ops(binding);
	struct nlattr *bad = NULL;
	unsigned long caps = 0;

	ops->capabilities(binding, handle->scope, &caps);

	if (nest && !(caps & BIT(NET_SHAPER_A_CAPS_SUPPORT_NESTING))) {
		NL_SET_ERR_MSG(info->extack,
			       "nesting not supported at given scope");
		return -EOPNOTSUPP;
	}

	if (tb[NET_SHAPER_A_PRIORITY] &&
	    !(caps & BIT(NET_SHAPER_A_CAPS_SUPPORT_PRIORITY)))
		bad = tb[NET_SHAPER_A_PRIORITY];
	if (tb[NET_SHAPER_A_WEIGHT] &&
	    !(caps & BIT(NET_SHAPER_A_CAPS_SUPPORT_WEIGHT)))
		bad = tb[NET_SHAPER_A_WEIGHT];

	/* Check metric type if there is *any* rate-related setting */
	if (tb[NET_SHAPER_A_METRIC] || tb[NET_SHAPER_A_BURST] ||
	    tb[NET_SHAPER_A_BW_MIN] || tb[NET_SHAPER_A_BW_MAX]) {
		u32 metric_cap = NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS;

		if (tb[NET_SHAPER_A_METRIC])
			metric_cap += nla_get_u32(tb[NET_SHAPER_A_METRIC]);
		else
			metric_cap += shaper->metric;
		if (!(caps & BIT(metric_cap))) {
			if (tb[NET_SHAPER_A_METRIC])
				bad = tb[NET_SHAPER_A_METRIC];
			else /* force a failure of rate attrs */
				caps = 0;
		}
	}
	if (tb[NET_SHAPER_A_BW_MIN] &&
	    !(caps & BIT(NET_SHAPER_A_CAPS_SUPPORT_BW_MIN)))
		bad = tb[NET_SHAPER_A_BW_MIN];
	if (tb[NET_SHAPER_A_BW_MAX] &&
	    !(caps & BIT(NET_SHAPER_A_CAPS_SUPPORT_BW_MAX)))
		bad = tb[NET_SHAPER_A_BW_MAX];
	if (tb[NET_SHAPER_A_BURST] &&
	    !(caps & BIT(NET_SHAPER_A_CAPS_SUPPORT_BURST)))
		bad = tb[NET_SHAPER_A_BURST];
	/* Don't add checks here, add them above metric checking.
	 * Metric checking may force clear caps causing false positive hits.
	 */

	if (!caps)
		bad = tb[NET_SHAPER_A_HANDLE];

	if (bad) {
		NL_SET_BAD_ATTR(info->extack, bad);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int net_shaper_parse_info(struct net_shaper_binding *binding,
				 struct nlattr **tb,
				 const struct genl_info *info,
				 struct net_shaper_handle *handle,
				 struct net_shaper_info *shaper,
				 bool nest, bool *cached)
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
		NL_SET_BAD_ATTR(info->extack, tb[NET_SHAPER_A_HANDLE]);
		return -EINVAL;
	}

	ret = net_shaper_validate_caps(binding, tb, info, handle, shaper, nest);
	if (ret)
		return ret;

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
				      enum net_shaper_scope expected_scope,
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

	ret = net_shaper_parse_info(binding, tb, info, handle, shaper, false,
				    &cached);
	if (ret < 0)
		return ret;

	if (expected_scope != NET_SHAPER_SCOPE_UNSPEC &&
	    handle->scope != expected_scope) {
		NL_SET_BAD_ATTR(info->extack, tb[NET_SHAPER_A_HANDLE]);
		return -EINVAL;
	}

	if (!cached)
		net_shaper_default_parent(handle, &shaper->parent);
	return 0;
}

/* Alike net_parse_shaper_info(), but additionally allow the user specifying
 * the shaper's parent handle.
 */
static int net_shaper_parse_node(struct net_shaper_binding *binding,
				 const struct nlattr *attr,
				 const struct genl_info *info,
				 struct net_shaper_handle *handle,
				 struct net_shaper_info *shaper)
{
	struct nlattr *tb[NET_SHAPER_A_PARENT + 1];
	bool cached;
	int ret;

	ret = nla_parse_nested(tb, NET_SHAPER_A_PARENT, attr,
			       net_shaper_node_info_nl_policy,
			       info->extack);
	if (ret < 0)
		return ret;

	ret = net_shaper_parse_info(binding, tb, info, handle, shaper, true,
				    &cached);
	if (ret)
		return ret;

	if (handle->scope != NET_SHAPER_SCOPE_NODE &&
	    handle->scope != NET_SHAPER_SCOPE_NETDEV) {
		NL_SET_BAD_ATTR(info->extack, tb[NET_SHAPER_A_HANDLE]);
		return -EINVAL;
	}

	if (tb[NET_SHAPER_A_PARENT]) {
		ret = net_shaper_parse_handle(tb[NET_SHAPER_A_PARENT], info,
					      &shaper->parent);
		if (ret)
			return ret;

		if (shaper->parent.scope != NET_SHAPER_SCOPE_NODE &&
		    shaper->parent.scope != NET_SHAPER_SCOPE_NETDEV) {
			NL_SET_BAD_ATTR(info->extack, tb[NET_SHAPER_A_PARENT]);
			return -EINVAL;
		}
	}
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

int net_shaper_nl_cap_pre_doit(const struct genl_split_ops *ops,
			       struct sk_buff *skb, struct genl_info *info)
{
	return net_shaper_generic_pre(info, NET_SHAPER_A_CAPS_IFINDEX);
}

void net_shaper_nl_cap_post_doit(const struct genl_split_ops *ops,
				 struct sk_buff *skb, struct genl_info *info)
{
	net_shaper_generic_post(info);
}

int net_shaper_nl_cap_pre_dumpit(struct netlink_callback *cb)
{
	struct net_shaper_nl_ctx *ctx = (struct net_shaper_nl_ctx *)cb->ctx;

	return net_shaper_ctx_init(genl_info_dump(cb),
				   NET_SHAPER_A_CAPS_IFINDEX, ctx);
}

int net_shaper_nl_cap_post_dumpit(struct netlink_callback *cb)
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
		NL_SET_BAD_ATTR(info->extack, info->attrs[NET_SHAPER_A_HANDLE]);
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
	const struct net_shaper_ops *ops = net_shaper_binding_ops(binding);
	struct net_shaper_handle handle = *h;
	struct net_shaper_data *data;
	int ret;

	/* Should never happen: binding lookup validates the ops presence */
	if (WARN_ON_ONCE(!ops))
		return -EOPNOTSUPP;

	net_shaper_lock(binding);
	data = net_shaper_cache_init(binding, extack);
	if (!data) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	if (handle.scope == NET_SHAPER_SCOPE_NODE &&
	    net_shaper_cache_lookup(binding, &handle)) {
		ret = -ENOENT;
		goto exit_unlock;
	}

	ret = net_shaper_cache_pre_insert(binding, &handle, extack);
	if (ret)
		goto exit_unlock;

	ret = ops->set(binding, &handle, shaper, extack);
	net_shaper_cache_commit(binding, 1, &handle, shaper);

exit_unlock:
	net_shaper_unlock(binding);
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
	ret = net_shaper_parse_info_nest(binding, attr, info,
					 NET_SHAPER_SCOPE_UNSPEC,
					 &handle, &shaper);
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

static int __net_shaper_group(struct net_shaper_binding *binding,
			      bool cache_node, int leaves_count,
			      const struct net_shaper_handle *leaves_handles,
			      struct net_shaper_info *leaves,
			      struct net_shaper_handle *node_handle,
			      struct net_shaper_info *node,
			      struct netlink_ext_ack *extack)
{
	const struct net_shaper_ops *ops = net_shaper_binding_ops(binding);
	struct net_shaper_info *parent = NULL;
	struct net_shaper_handle leaf_handle;
	int i, ret;

	if (node_handle->scope == NET_SHAPER_SCOPE_NODE) {
		if (node_handle->id != NET_SHAPER_ID_UNSPEC &&
		    !net_shaper_cache_lookup(binding, node_handle)) {
			NL_SET_ERR_MSG_FMT(extack, "Node shaper %d:%d does not exists",
					   node_handle->scope, node_handle->id);
			return -ENOENT;
		}

		/* When unspecified, the node parent scope is inherited from
		 * the leaves.
		 */
		if (node->parent.scope == NET_SHAPER_SCOPE_UNSPEC) {
			for (i = 1; i < leaves_count; ++i) {
				if (leaves[i].parent.scope !=
				    leaves[0].parent.scope ||
				    leaves[i].parent.id !=
				    leaves[0].parent.id) {
					NL_SET_ERR_MSG_FMT(extack, "All the leaves shapers must have the same old parent");
					return -EINVAL;
				}
			}

			if (leaves_count > 0)
				node->parent = leaves[0].parent;
		}

	} else {
		net_shaper_default_parent(node_handle, &node->parent);
	}

	if (node->parent.scope == NET_SHAPER_SCOPE_NODE) {
		parent = net_shaper_cache_lookup(binding, &node->parent);
		if (!parent) {
			NL_SET_ERR_MSG_FMT(extack, "Node parent shaper %d:%d does not exists",
					   node->parent.scope, node->parent.id);
			return -ENOENT;
		}
	}

	if (cache_node) {
		/* For newly created node scope shaper, the following will
		 * update the handle, due to id allocation.
		 */
		ret = net_shaper_cache_pre_insert(binding, node_handle,
						  extack);
		if (ret)
			return ret;
	}

	for (i = 0; i < leaves_count; ++i) {
		leaf_handle = leaves_handles[i];

		ret = net_shaper_cache_pre_insert(binding, &leaf_handle,
						  extack);
		if (ret)
			goto rollback;

		if (leaves[i].parent.scope == node_handle->scope &&
		    leaves[i].parent.id == node_handle->id)
			continue;

		/* The leaves shapers will be nested to the node, update the
		 * linking accordingly.
		 */
		leaves[i].parent = *node_handle;
		node->leaves++;
	}

	ret = ops->group(binding, leaves_count, leaves_handles, leaves,
			 node_handle, node, extack);
	if (ret < 0)
		goto rollback;

	if (parent)
		parent->leaves++;
	if (cache_node)
		net_shaper_cache_commit(binding, 1, node_handle, node);
	net_shaper_cache_commit(binding, leaves_count, leaves_handles, leaves);
	return 0;

rollback:
	net_shaper_cache_rollback(binding);
	return ret;
}

static int __net_shaper_pre_del_node(struct net_shaper_binding *binding,
				     const struct net_shaper_handle *handle,
				     const struct net_shaper_info *shaper,
				     struct netlink_ext_ack *extack)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_handle *leaves_handles, node_handle;
	struct net_shaper_info *cur, *leaves, node = {};
	int ret, leaves_count = 0;
	unsigned long index;
	bool cache_node;

	if (!shaper->leaves)
		return 0;

	if (WARN_ON_ONCE(!data))
		return -EINVAL;

	/* Fetch the new node information. */
	node_handle = shaper->parent;
	cur = net_shaper_cache_lookup(binding, &node_handle);
	if (cur) {
		node = *cur;
	} else {
		/* A scope NODE shaper can be nested only to the NETDEV scope
		 * shaper without creating the latter, this check may fail only
		 * if the cache is in inconsistent status.
		 */
		if (WARN_ON_ONCE(node_handle.scope != NET_SHAPER_SCOPE_NETDEV))
			return -EINVAL;
	}

	leaves = kcalloc(shaper->leaves,
			 sizeof(struct net_shaper_info) +
			 sizeof(struct net_shaper_handle), GFP_KERNEL);
	if (!leaves)
		return -ENOMEM;

	leaves_handles = (struct net_shaper_handle *)&leaves[shaper->leaves];

	/* Build the leaves arrays. */
	xa_for_each(&data->shapers, index, cur) {
		if (cur->parent.scope != handle->scope ||
		    cur->parent.id != handle->id)
			continue;

		if (WARN_ON_ONCE(leaves_count == shaper->leaves)) {
			ret = -EINVAL;
			goto free;
		}

		net_shaper_index_to_handle(index,
					   &leaves_handles[leaves_count]);
		leaves[leaves_count++] = *cur;
	}

	/* When re-linking to the netdev shaper, avoid the eventual, implicit,
	 * creation of the new node, would be surprising since the user is
	 * doing a delete operation.
	 */
	cache_node = node_handle.scope != NET_SHAPER_SCOPE_NETDEV;
	ret = __net_shaper_group(binding, cache_node, leaves_count,
				 leaves_handles, leaves, &node_handle, &node,
				 extack);

free:
	kfree(leaves);
	return ret;
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

	net_shaper_lock(binding);
	shaper = net_shaper_cache_lookup(binding, handle);
	if (!shaper) {
		ret = -ENOENT;
		goto unlock;
	}

	if (handle->scope == NET_SHAPER_SCOPE_NODE) {
		ret = __net_shaper_pre_del_node(binding, handle, shaper,
						extack);
		if (ret)
			goto unlock;
	}

	ret = __net_shaper_delete(binding, handle, shaper, extack);

unlock:
	net_shaper_unlock(binding);
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

/* Update the H/W and on success update the local cache, too */
static int net_shaper_group(struct net_shaper_binding *binding,
			    int leaves_count,
			    const struct net_shaper_handle *leaves_handles,
			    struct net_shaper_info *leaves,
			    struct net_shaper_handle *node_handle,
			    struct net_shaper_info *node,
			    struct netlink_ext_ack *extack)
{
	struct net_shaper_handle *old_nodes;
	int i, ret, old_nodes_count = 0;
	struct net_shaper_data *data;

	net_shaper_lock(binding);
	data = net_shaper_cache_init(binding, extack);
	if (!data) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	old_nodes = kcalloc(leaves_count, sizeof(struct net_shaper_handle),
			    GFP_KERNEL);
	if (!old_nodes) {
		ret = -ENOMEM;
		goto exit_unlock;
	}

	for (i = 0; i < leaves_count; i++)
		if (leaves[i].parent.scope == NET_SHAPER_SCOPE_NODE &&
		    (leaves[i].parent.scope != node_handle->scope ||
		     leaves[i].parent.id != node_handle->id))
			old_nodes[old_nodes_count++] = leaves[i].parent;

	ret = __net_shaper_group(binding, true, leaves_count, leaves_handles,
				 leaves, node_handle, node, extack);

	/* Check if we need to delete any NODE left alone by the new leaves
	 * linkage.
	 */
	for (i = 0; i < old_nodes_count; ++i) {
		node = net_shaper_cache_lookup(binding, &old_nodes[i]);
		if (!node)
			continue;

		if (--node->leaves > 0)
			continue;

		/* Errors here are not fatal: the grouping operation is
		 * completed, and user-space can still explicitly clean-up
		 * left-over nodes.
		 */
		__net_shaper_delete(binding, &old_nodes[i], node, extack);
	}

	kfree(old_nodes);

exit_unlock:
	net_shaper_unlock(binding);
	return ret;
}

static int net_shaper_group_send_reply(struct genl_info *info,
				       struct net_shaper_handle *handle)
{
	struct net_shaper_binding *binding = info->user_ptr[0];
	struct sk_buff *msg;
	int ret = -EMSGSIZE;
	void *hdr;

	/* Prepare the msg reply in advance, to avoid device operation
	 * rollback.
	 */
	msg = genlmsg_new(net_shaper_handle_size(), GFP_KERNEL);
	if (!msg)
		return ret;

	hdr = genlmsg_iput(msg, info);
	if (!hdr)
		goto free_msg;

	if (net_shaper_fill_binding(msg, binding, NET_SHAPER_A_IFINDEX))
		goto free_msg;

	if (net_shaper_fill_handle(msg, handle, NET_SHAPER_A_HANDLE))
		goto free_msg;

	genlmsg_end(msg, hdr);

	ret = genlmsg_reply(msg, info);
	if (ret)
		goto free_msg;

	return ret;

free_msg:
	nlmsg_free(msg);
	return ret;
}

int net_shaper_nl_group_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net_shaper_handle *leaves_handles, node_handle;
	struct net_shaper_info *leaves, node;
	struct net_shaper_binding *binding;
	int i, ret, rem, leaves_count;
	struct nlattr *attr;

	if (GENL_REQ_ATTR_CHECK(info, NET_SHAPER_A_LEAVES) ||
	    GENL_REQ_ATTR_CHECK(info, NET_SHAPER_A_NODE))
		return -EINVAL;

	binding = net_shaper_binding_from_ctx(info->user_ptr[0]);
	leaves_count = net_shaper_list_len(info, NET_SHAPER_A_LEAVES);
	leaves = kcalloc(leaves_count, sizeof(struct net_shaper_info) +
			 sizeof(struct net_shaper_handle), GFP_KERNEL);
	if (!leaves) {
		GENL_SET_ERR_MSG_FMT(info, "Can't allocate memory for %d leaves shapers",
				     leaves_count);
		return -ENOMEM;
	}
	leaves_handles = (struct net_shaper_handle *)&leaves[leaves_count];

	ret = net_shaper_parse_node(binding, info->attrs[NET_SHAPER_A_NODE],
				    info, &node_handle, &node);
	if (ret)
		goto free_shapers;

	i = 0;
	nla_for_each_attr_type(attr, NET_SHAPER_A_LEAVES,
			       genlmsg_data(info->genlhdr),
			       genlmsg_len(info->genlhdr), rem) {
		if (WARN_ON_ONCE(i >= leaves_count))
			goto free_shapers;

		ret = net_shaper_parse_info_nest(binding, attr, info,
						 NET_SHAPER_SCOPE_QUEUE,
						 &leaves_handles[i],
						 &leaves[i]);
		if (ret)
			goto free_shapers;
		i++;
	}

	ret = net_shaper_group(binding, leaves_count, leaves_handles, leaves,
			       &node_handle, &node, info->extack);
	if (ret < 0)
		goto free_shapers;

	ret = net_shaper_group_send_reply(info, &node_handle);
	if (ret) {
		/* Error on reply is not fatal to avoid rollback a successful
		 * configuration.
		 */
		GENL_SET_ERR_MSG_FMT(info, "Can't send reply %d", ret);
		ret = 0;
	}

free_shapers:
	kfree(leaves);
	return ret;
}

static int
net_shaper_cap_fill_one(struct sk_buff *msg,
			struct net_shaper_binding *binding,
			enum net_shaper_scope scope, unsigned long flags,
			const struct genl_info *info)
{
	unsigned long cur;
	void *hdr;

	hdr = genlmsg_iput(msg, info);
	if (!hdr)
		return -EMSGSIZE;

	if (net_shaper_fill_binding(msg, binding, NET_SHAPER_A_CAPS_IFINDEX) ||
	    nla_put_u32(msg, NET_SHAPER_A_CAPS_SCOPE, scope))
		goto nla_put_failure;

	for (cur = NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS;
	     cur <= NET_SHAPER_A_CAPS_MAX; ++cur) {
		if (flags & BIT(cur) && nla_put_flag(msg, cur))
			goto nla_put_failure;
	}

	genlmsg_end(msg, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

int net_shaper_nl_cap_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct net_shaper_binding *binding = info->user_ptr[0];
	const struct net_shaper_ops *ops;
	enum net_shaper_scope scope;
	unsigned long flags = 0;
	struct sk_buff *msg;
	int ret;

	if (GENL_REQ_ATTR_CHECK(info, NET_SHAPER_A_CAPS_SCOPE))
		return -EINVAL;

	scope = nla_get_u32(info->attrs[NET_SHAPER_A_CAPS_SCOPE]);
	ops = net_shaper_binding_ops(binding);
	ops->capabilities(binding, scope, &flags);
	if (!flags)
		return -EOPNOTSUPP;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	ret = net_shaper_cap_fill_one(msg, binding, scope, flags, info);
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

int net_shaper_nl_cap_get_dumpit(struct sk_buff *skb,
				 struct netlink_callback *cb)
{
	const struct genl_info *info = genl_info_dump(cb);
	struct net_shaper_binding *binding;
	const struct net_shaper_ops *ops;
	enum net_shaper_scope scope;
	int ret;

	binding = net_shaper_binding_from_ctx(cb->ctx);
	ops = net_shaper_binding_ops(binding);
	for (scope = 0; scope <= NET_SHAPER_SCOPE_MAX; ++scope) {
		unsigned long flags = 0;

		ops->capabilities(binding, scope, &flags);
		if (!flags)
			continue;

		ret = net_shaper_cap_fill_one(skb, binding, scope, flags,
					      info);
		if (ret)
			return ret;
	}

	return 0;
}

static void net_shaper_flush(struct net_shaper_binding *binding)
{
	struct net_shaper_data *data = net_shaper_binding_data(binding);
	struct net_shaper_info *cur;
	unsigned long index;

	if (!data)
		return;

	net_shaper_lock(binding);
	xa_lock(&data->shapers);
	xa_for_each(&data->shapers, index, cur) {
		__xa_erase(&data->shapers, index);
		kfree(cur);
	}
	xa_unlock(&data->shapers);
	idr_destroy(&data->node_ids);
	net_shaper_unlock(binding);

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
