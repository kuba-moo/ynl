/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/file.h>
#include <linux/net.h>
#include <linux/rcupdate.h>

#include <net/psp.h>
#include "psp.h"

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
	lock_sock(sk);

	old = psp_sk_assoc(sk);

	refcount_inc(&pas->refcnt);
	rcu_assign_pointer(sk->psp_assoc, pas);

	release_sock(sk);
	sockfd_put(sock);

	psp_assoc_put(old);

	return 0;
}
