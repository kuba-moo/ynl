/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __NET_PSP_HOOKS_H
#define __NET_PSP_HOOKS_H

void psp_sk_destruct(struct sock *sk);

#ifdef CONFIG_PSP
int psp_sk_validate_xmit(struct net_device *netdev, struct sk_buff *skb)
{
	struct psp_sock_state *pss;

	if (!skb->sk)
		return 0;
	pss = rcu_deference(skb->sk->psp_state);
	if (pss && pss->psd != netdev->psd)
		return -EINVAL;
	return 0;
}
#else
static inline int psp_sk_validate_xmit(struct sk_buff *skb)
{
	return 0;
}
#endif

#endif /* __NET_PSP_HOOKS_H */
