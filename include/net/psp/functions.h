/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __NET_PSP_HELPERS_H
#define __NET_PSP_HELPERS_H

#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/psp/types.h>

/* Driver-facing API */
struct psp_dev *
psp_dev_create(struct net_device *netdev, struct psp_dev_ops *psd_ops,
	       struct psp_dev_caps *psd_caps, void *priv_ptr);
void psp_dev_unregister(struct psp_dev *psd);

/* Kernel-facing API */
void psp_assoc_put(struct psp_assoc *pas);

#if IS_ENABLED(CONFIG_INET_PSP)
void psp_sk_assoc_free(struct sock *sk);

static inline enum skb_drop_reason
psp_sk_rx_policy_check(struct sock *sk, struct sk_buff *skb)
{
	struct psp_skb_ext *pse;
	struct psp_assoc *pas;

	pse = skb_ext_find(skb, SKB_EXT_PSP);
	pas = rcu_dereference(sk->psp_assoc);
	if (!pse) {
		if (pas && pas->tx.spi)
			return SKB_DROP_REASON_PSP_INPUT;
		return 0;
	}

	if (pas && pas->rx.spi == pse->spi &&
	    pas->generation == pse->generation &&
	    pas->version == pse->version)
		return 0;
	return SKB_DROP_REASON_PSP_INPUT;
}

static inline struct psp_assoc *psp_skb_get_assoc_rcu(struct sk_buff *skb)
{
	if (!skb->sk || !sk_fullsock(skb->sk))
		return NULL;
	return rcu_dereference(skb->sk->psp_assoc);
}
#else
static inline void psp_sk_assoc_free(struct sock *sk) { }

static inline enum skb_drop_reason
psp_sk_rx_policy_check(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static inline struct psp_assoc *psp_skb_get_assoc_rcu(struct sk_buff *skb)
{
	return NULL;
}
#endif

#endif /* __NET_PSP_HELPERS_H */
