/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PSP_PSP_H
#define __PSP_PSP_H

#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <net/netns/generic.h>
#include <net/psp.h>
#include <net/sock.h>

extern struct xarray psp_devs;
extern struct mutex psp_devs_lock;
extern int psp_pernet_id;

struct psp_pernet {
	struct xarray sockets;
	struct mutex sockets_lock;
};

struct psp_nl_sock {
};

void psp_dev_destroy(struct psp_dev *psd);
int psp_dev_check_access(struct psp_dev *psd, struct net *net);

void psp_nl_notify_dev(struct psp_dev *psd, u32 cmd);

int psp_netlink_notify(struct notifier_block *nb, unsigned long state,
		       void *_notify);

struct psp_assoc *psp_assoc_create(struct psp_dev *psd);
void psp_assoc_dev_del(struct psp_dev *psd, struct psp_assoc *pas);
int psp_sock_assoc_set(unsigned int fd, struct psp_assoc *pas);

static inline struct psp_pernet *psp_get_pernet(const struct net *net)
{
	return net_generic(net, psp_pernet_id);
}

static inline struct psp_assoc *psp_sk_assoc(struct sock *sk)
{
	return rcu_dereference_protected(sk->psp_assoc, sock_owned_by_user(sk));
}

static inline void psp_dev_get(struct psp_dev *psd)
{
	refcount_inc(&psd->refcnt);
}

static inline void psp_dev_put(struct psp_dev *psd)
{
	if (refcount_dec_and_test(&psd->refcnt))
		psp_dev_destroy(psd);
}

static inline bool psp_dev_is_registered(struct psp_dev *psd)
{
	lockdep_assert_held(&psd->lock);
	return !!psd->ops;
}

#endif /* __PSP_PSP_H */
