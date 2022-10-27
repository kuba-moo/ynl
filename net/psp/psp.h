/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PSP_PSP_H
#define __PSP_PSP_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <net/netns/generic.h>
#include <net/psp.h>

extern struct xarray psp_devs;
extern struct mutex psp_devs_lock;
extern int psp_pernet_id;

struct psp_pernet {
	struct xarray sockets;
	struct mutex sockets_lock;
};

struct psp_nl_sock {
};

struct psp_key_parsed {
};

static inline struct psp_pernet *psp_get_pernet(const struct net *net)
{
	return net_generic(net, psp_pernet_id);
}

int psp_dev_check_access(struct psp_dev *psd, struct net *net);

void psp_nl_notify_dev(struct psp_dev *psd, u32 cmd);

int psp_netlink_notify(struct notifier_block *nb, unsigned long state,
		       void *_notify);

int psp_sock_tx_assoc_set(int fd, struct psp_tx_assoc *tas);

#endif /* __PSP_PSP_H */
