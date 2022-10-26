/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/file.h>
#include <linux/net.h>
#include <net/psp.h>
#include "psp.h"

int psp_sock_tx_assoc_set(int fd, struct psp_tx_assoc *tas)
{
	struct psp_sock_state *pss; //, *old;
	struct socket *sock;
	struct file *file;
//	struct sock *sk;
	int err;

	if (fd < 0)
		return -EBADF;

	file = fget(fd);
	if (!file)
		return -EBADF;

	sock = sock_from_file(file);
	if (!sock) {
		err = -ENOTSOCK;
		goto err_put;
	}

	pss = kzalloc(sizeof(*pss), GFP_KERNEL_ACCOUNT);
	if (!pss) {
		err = -ENOMEM;
		goto err_put;
	}

	pss->tx = tas;

//	old = rcu /* TODO: rcu lifetime for the pss */
//	rcu_assign_pointer(sk->psp_state, pss);

	fput(file);

	return 0;
err_put:
	fput(file);
	return err;
}
