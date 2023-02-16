/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/file.h>
#include <linux/net.h>
#include <linux/rcupdate.h>

#include <net/psp.h>
#include "psp.h"

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

void psp_assoc_dev_del(struct psp_dev *psd, struct psp_assoc *pas)
{
	psd->ops->assoc_del(psd, pas);
	list_del(&pas->assocs_list);
}

static void psp_assoc_free(struct work_struct *work)
{
	struct psp_assoc *pas = container_of(work, struct psp_assoc, work);
	struct psp_dev *psd = pas->psd;

	mutex_lock(&psd->lock);
	if (psd->ops)
		psp_assoc_dev_del(psd, pas);
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
int psp_sock_assoc_set(unsigned int fd, struct psp_assoc *pas)
{
	struct psp_assoc *old;
	struct socket *sock;
	struct sock *sk;
	int err;

	sock = sockfd_lookup(fd, &err);
	if (!sock)
		return err;

	sk = sock->sk;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) {
		sockfd_put(sock);
		return -EOPNOTSUPP;
	}

	lock_sock(sk);

	old = psp_sk_assoc(sk);

	refcount_inc(&pas->refcnt);
	rcu_assign_pointer(sk->psp_assoc, pas);

	release_sock(sk);

	sockfd_put(sock);
	psp_assoc_put(old);

	return 0;
}
