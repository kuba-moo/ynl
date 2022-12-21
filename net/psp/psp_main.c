// SPDX-License-Identifier: GPL-2.0-only

#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/xarray.h>
#include <net/net_namespace.h>
#include <net/psp.h>

#include "psp.h"
#include "psp-nl-gen.h"

DEFINE_XARRAY_ALLOC1(psp_devs);
struct mutex psp_devs_lock;

/**
 * DOC: PSP locking
 *
 * psp_devs_lock protects the psp_devs xarray.
 * Ordering is take the psp_devs_lock and then the instance lock.
 * Each instance has a refcount and will be freed async.
 */

/**
 * psp_dev_check_access() - check if user in a given net ns can access PSP dev
 * @psd:	PSP device structure user is trying to access
 * @net:	net namespace user is in
 */
int psp_dev_check_access(struct psp_dev *psd, struct net *net)
{
	if (dev_net(psd->main_netdev) == net)
		return 0;
	return -ENOENT;
}

/**
 * psp_dev_create() - create and register PSP device
 * @netdev:	main netdevice
 * @psd_ops:	driver callbacks
 * @psd_caps:	device capabilities
 * @priv_ptr:	back-pointer to driver private data
 *
 * Note that the @psd memory will be wiped.
 */
struct psp_dev *
psp_dev_create(struct net_device *netdev,
	       struct psp_dev_ops *psd_ops, struct psp_dev_caps *psd_caps,
	       void *priv_ptr)
{
	struct psp_dev *psd;
	static u32 last_id;
	int err;

	if (WARN_ON(!psd_caps->versions ||
		    !psd_ops->set_config))
		return NULL;

	psd = kzalloc(sizeof(*psd), GFP_KERNEL);

	psd->main_netdev = netdev;
	psd->ops = psd_ops;
	psd->caps = psd_caps;
	psd->drv_priv = priv_ptr;

	mutex_init(&psd->lock);
	refcount_set(&psd->refcnt, 1);

	mutex_lock(&psp_devs_lock);
	err = xa_alloc_cyclic(&psp_devs, &psd->id, psd, xa_limit_31b,
			      &last_id, GFP_KERNEL);
	if (err) {
		mutex_unlock(&psp_devs_lock);
		return NULL;
	}
	mutex_lock(&psd->lock);
	mutex_unlock(&psp_devs_lock);

	psp_nl_notify_dev(psd, PSP_CMD_DEV_ADD_NTF);

	mutex_unlock(&psd->lock);

	return psd;
}
EXPORT_SYMBOL_NS_GPL(psp_dev_create, NETDEV_PRIVATE);

void psp_dev_destroy(struct psp_dev *psd)
{
	mutex_destroy(&psd->lock);
	kfree(psd);
}

static struct notifier_block psp_netlink_notifier = {
	.notifier_call = psp_netlink_notify,
};

static int __net_init psp_pernet_init(struct net *net)
{
	struct psp_pernet *psp_net = psp_get_pernet(net);

	mutex_init(&psp_net->sockets_lock);
	xa_init(&psp_net->sockets);
	return 0;
}

static void __net_exit psp_pernet_exit(struct net *net)
{
	struct psp_pernet *psp_net = psp_get_pernet(net);

	WARN_ON_ONCE(!xa_empty(&psp_net->sockets));
	mutex_destroy(&psp_net->sockets_lock);
}

int psp_pernet_id;

static struct pernet_operations psp_pernet_ops = {
	.init = psp_pernet_init,
	.exit = psp_pernet_exit,
	.id = &psp_pernet_id,
	.size = sizeof(struct psp_pernet),
};

/**
 * psp_dev_unregister() - unregister PSP device
 * @psd:	PSP device structure
 */
void psp_dev_unregister(struct psp_dev *psd)
{
	mutex_lock(&psp_devs_lock);
	mutex_lock(&psd->lock);

	psp_nl_notify_dev(psd, PSP_CMD_DEV_DEL_NTF);
	xa_erase(&psp_devs, psd->id);
	psd->ops = NULL;
	psd->caps = NULL;
	psd->drv_priv = NULL;

	mutex_unlock(&psd->lock);
	mutex_unlock(&psp_devs_lock);

	psp_dev_put(psd);
}
EXPORT_SYMBOL_NS_GPL(psp_dev_unregister, NETDEV_PRIVATE);

static int __init psp_init(void)
{
	int err;

	mutex_init(&psp_devs_lock);

	err = register_pernet_subsys(&psp_pernet_ops);
	if (err)
		return err;

	err = netlink_register_notifier(&psp_netlink_notifier);
	if (err)
		goto err_unreg_pernet;

	err = genl_register_family(&psp_nl_family);
	if (err)
		goto err_unreg_ntf;

	return 0;

err_unreg_ntf:
	netlink_unregister_notifier(&psp_netlink_notifier);
err_unreg_pernet:
	unregister_pernet_subsys(&psp_pernet_ops);
	return err;
}

subsys_initcall(psp_init);
