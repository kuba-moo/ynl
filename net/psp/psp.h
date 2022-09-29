/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PSP_PSP_H
#define __PSP_PSP_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <net/psp.h>

extern struct xarray psp_devs;
extern struct mutex psp_devs_lock;

int psp_dev_check_access(struct psp_dev *psd, struct net *net);

void psp_nl_notify_dev(struct psp_dev *psd, u32 cmd);

#endif /* __PSP_PSP_H */
