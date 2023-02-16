/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/file.h>
#include <linux/net.h>
#include <linux/rcupdate.h>

#include <net/psp.h>
#include "psp.h"

static struct sk_buff *
psp_validate_xmit(struct sock *sk, struct net_device *dev, struct sk_buff *skb)
{
	struct psp_assoc *pas;
	bool good;

	rcu_read_lock();
	pas = psp_skb_get_assoc_rcu(skb);
	good = !pas || dev->psp_dev == pas->psd;
	rcu_read_unlock();
	if (!good) {
		kfree_skb(skb);
		return NULL;
	}

	return skb;
}

struct psp_assoc *psp_assoc_create(struct psp_dev *psd)
{
	struct psp_assoc *pas;

	lockdep_assert_held(&psd->lock);

	pas = kzalloc(struct_size(pas, drv_data, psd->caps->assoc_drv_spc),
		      GFP_KERNEL_ACCOUNT);
	if (!pas)
		return NULL;

	pas->psd = psd;
	psp_dev_get(psd);
	refcount_set(&pas->refcnt, 1);

	list_add_tail(&pas->assocs_list, &psd->active_assocs);

	return pas;
}

static struct psp_assoc *psp_assoc_dummy(struct psp_assoc *pas)
{
	struct psp_dev *psd = pas->psd;
	size_t sz;

	lockdep_assert_held(&psd->lock);

	sz = struct_size(pas, drv_data, psd->caps->assoc_drv_spc);
	return kmemdup(pas, sz, GFP_KERNEL);
}

static int psp_dev_tx_key_add(struct psp_dev *psd, struct psp_assoc *pas,
			      struct netlink_ext_ack *extack)
{
	return psd->ops->tx_key_add(psd, pas, extack);
}

void psp_dev_tx_key_del(struct psp_dev *psd, struct psp_assoc *pas)
{
	if (pas->tx.spi)
		psd->ops->tx_key_del(psd, pas);
	list_del(&pas->assocs_list);
}

static void psp_assoc_free(struct work_struct *work)
{
	struct psp_assoc *pas = container_of(work, struct psp_assoc, work);
	struct psp_dev *psd = pas->psd;

	mutex_lock(&psd->lock);
	if (psd->ops)
		psp_dev_tx_key_del(psd, pas);
	mutex_unlock(&psd->lock);
	psp_dev_put(psd);
	kfree(pas);
}

static void psp_assoc_free_queue(struct rcu_head *head)
{
	struct psp_assoc *pas = container_of(head, struct psp_assoc, rcu);

	INIT_WORK(&pas->work, psp_assoc_free);
	schedule_work(&pas->work);
}

/**
 * psp_assoc_put() - release a reference on a PSP association
 * @pas: association to release
 */
void psp_assoc_put(struct psp_assoc *pas)
{
	if (pas && refcount_dec_and_test(&pas->refcnt))
		call_rcu(&pas->rcu, psp_assoc_free_queue);
}

void psp_sk_assoc_free(struct sock *sk)
{
	rcu_read_lock();
	psp_assoc_put(rcu_dereference(sk->psp_assoc));
	rcu_assign_pointer(sk->psp_assoc, NULL);
	rcu_read_unlock();
}

int psp_sock_assoc_set_rx(unsigned int fd, struct psp_assoc *pas,
			  struct psp_key_parsed *key,
			  struct netlink_ext_ack *extack)
{
	struct socket *sock;
	struct sock *sk;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return err;

	sk = sock->sk;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) {
		NL_SET_ERR_MSG(extack, "Unsupported socket family");
		err = -EOPNOTSUPP;
		goto exit_sock_put;
	}

	memcpy(&pas->rx, key, sizeof(*key));

	lock_sock(sk);

	if (psp_sk_assoc(sk)) {
		NL_SET_ERR_MSG(extack, "Socket already has PSP state");
		err = -EBUSY;
		goto exit_unlock;
	}

	refcount_inc(&pas->refcnt);
	rcu_assign_pointer(sk->psp_assoc, pas);
	err = 0;

exit_unlock:
	release_sock(sk);
exit_sock_put:
	sockfd_put(sock);

	return err;
}

int psp_sock_assoc_set_tx(unsigned int fd, struct psp_dev *psd,
			  struct psp_key_parsed *key,
			  struct netlink_ext_ack *extack)
{
	struct psp_assoc *pas, *dummy;
	struct socket *sock;
	struct sock *sk;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return err;

	sk = sock->sk;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) {
		NL_SET_ERR_MSG(extack, "Unsupported socket family");
		err = -EOPNOTSUPP;
		goto exit_sock_put;
	}

	lock_sock(sk);

	pas = psp_sk_assoc(sk);
	if (!pas) {
		NL_SET_ERR_MSG(extack, "Socket has no Rx key");
		err = -EINVAL;
		goto exit_unlock;
	}
	if (pas->psd != psd) {
		NL_SET_ERR_MSG(extack, "Rx key from different device");
		err = -EINVAL;
		goto exit_unlock;
	}
	if (pas->tx.spi) {
		NL_SET_ERR_MSG(extack, "Tx key already set");
		err = -EBUSY;
		goto exit_unlock;
	}

	dummy = psp_assoc_dummy(pas);
	memcpy(&dummy->tx, key, sizeof(*key));
	err = psp_dev_tx_key_add(psd, dummy, extack);
	if (err)
		goto exit_free_dummy;

	memcpy(pas->drv_data, dummy->drv_data, psd->caps->assoc_drv_spc);
	memcpy(&pas->tx, key, sizeof(*key));
	WRITE_ONCE(pas->rx_required, 1);

	WRITE_ONCE(sk->sk_validate_xmit_skb, psp_validate_xmit);

exit_free_dummy:
	kfree(dummy);
exit_unlock:
	release_sock(sk);
exit_sock_put:
	sockfd_put(sock);

	return err;
}
