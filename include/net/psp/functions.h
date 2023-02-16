/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __NET_PSP_HELPERS_H
#define __NET_PSP_HELPERS_H

#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/psp/types.h>

struct tcp_timewait_sock;

/* Driver-facing API */
struct psp_dev *
psp_dev_create(struct net_device *netdev, struct psp_dev_ops *psd_ops,
	       struct psp_dev_caps *psd_caps, void *priv_ptr);
void psp_dev_unregister(struct psp_dev *psd);

/* Kernel-facing API */
void psp_assoc_put(struct psp_assoc *pas);

static inline void *psp_assoc_drv_data(struct psp_assoc *pas)
{
	return pas->drv_data;
}

#if IS_ENABLED(CONFIG_INET_PSP)
void psp_sk_assoc_free(struct sock *sk);
void psp_twsk_init(struct tcp_timewait_sock *tw, struct sock *sk);
void psp_twsk_assoc_free(struct tcp_timewait_sock *tw);
enum skb_drop_reason
psp_twsk_rx_policy_check(struct tcp_timewait_sock *tw, struct sk_buff *skb);

static inline struct psp_assoc *psp_sk_assoc(struct sock *sk)
{
	return rcu_dereference_check(sk->psp_assoc, lockdep_sock_is_held(sk));
}

static inline void
psp_enqueue_set_decrypted(struct sock *sk, struct sk_buff *skb)
{
	struct psp_assoc *pas;

	pas = psp_sk_assoc(sk);
	if (pas && pas->tx.spi)
		skb->decrypted = 1;
}

static inline unsigned long
__psp_skb_coalesce_diff(const struct sk_buff *one, const struct sk_buff *two,
			unsigned long diffs)
{
	struct psp_skb_ext *a, *b;

	a = skb_ext_find(one, SKB_EXT_PSP);
	b = skb_ext_find(two, SKB_EXT_PSP);

	diffs |= (!!a) ^ (!!b);
	if (!diffs && unlikely(a))
		diffs |= memcmp(a, b, sizeof(*a));
	return diffs;
}

static inline enum skb_drop_reason
__psp_sk_rx_policy_check(struct psp_skb_ext *pse, struct psp_assoc *pas)
{
	if (!pse) {
		if (pas && READ_ONCE(pas->rx_required))
			return SKB_DROP_REASON_PSP_INPUT;
		return 0;
	}

	if (pas && pas->rx.spi == pse->spi &&
	    pas->generation == pse->generation &&
	    pas->version == pse->version)
		return 0;
	return SKB_DROP_REASON_PSP_INPUT;
}

static inline enum skb_drop_reason
psp_sk_rx_policy_check(struct sock *sk, struct sk_buff *skb)
{
	return __psp_sk_rx_policy_check(skb_ext_find(skb, SKB_EXT_PSP),
					psp_sk_assoc(sk));
}

static inline struct psp_assoc *psp_skb_get_assoc_rcu(struct sk_buff *skb)
{
	if (!skb->decrypted || !skb->sk || !sk_fullsock(skb->sk))
		return NULL;
	return rcu_dereference(skb->sk->psp_assoc);
}
#else
static inline void psp_sk_assoc_free(struct sock *sk) { }
static inline void
psp_twsk_init(struct tcp_timewait_sock *tw, struct sock *sk) { }
static inline void psp_twsk_assoc_free(struct tcp_timewait_sock *tw) { }

static inline struct psp_assoc *psp_sk_assoc(struct sock *sk)
{
	return NULL;
}

static inline void
psp_enqueue_set_decrypted(struct sock *sk, struct sk_buff *skb) { }

static inline unsigned long
__psp_skb_coalesce_diff(const struct sk_buff *one, const struct sk_buff *two,
			unsigned long diffs)
{
	return diffs;
}

static inline enum skb_drop_reason
psp_sk_rx_policy_check(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static inline enum skb_drop_reason
psp_twsk_rx_policy_check(struct tcp_timewait_sock *tw, struct sk_buff *skb)
{
	return 0;
}

static inline struct psp_assoc *psp_skb_get_assoc_rcu(struct sk_buff *skb)
{
	return NULL;
}
#endif

static inline unsigned long
psp_skb_coalesce_diff(const struct sk_buff *one, const struct sk_buff *two)
{
	return __psp_skb_coalesce_diff(one, two, 0);
}

#endif /* __NET_PSP_HELPERS_H */
