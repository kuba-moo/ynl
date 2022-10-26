/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/skbuff.h>
#include <linux/xarray.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include <linux/psp.h>
#include "psp-nl-gen.h"
#include "psp.h"

/* Device stuff */

static struct psp_dev *
psp_device_get_and_lock(struct net *net, struct nlattr *dev_id)
{
	struct psp_dev *psd;
	int err;

	mutex_lock(&psp_devs_lock);
	psd = xa_load(&psp_devs, nla_get_u32(dev_id));
	if (!psd) {
		mutex_unlock(&psp_devs_lock);
		return ERR_PTR(-ENODEV);
	}

	mutex_lock(&psd->lock);
	mutex_unlock(&psp_devs_lock);

	err = psp_dev_check_access(psd, net);
	if (err) {
		mutex_unlock(&psd->lock);
		return ERR_PTR(err);
	}

	return psd;
}

int psp_device_get_locked(const struct genl_split_ops *ops,
			  struct sk_buff *skb, struct genl_info *info)
{
	if (GENL_REQ_ATTR_CHECK(info, PSP_A_DEV_ID))
		return -EINVAL;

	info->user_ptr[0] = psp_device_get_and_lock(genl_info_net(info),
						    info->attrs[PSP_A_DEV_ID]);
	return PTR_ERR_OR_ZERO(info->user_ptr[0]);
}

void
psp_device_unlock(const struct genl_split_ops *ops, struct sk_buff *skb,
		  struct genl_info *info)
{
	struct psp_dev *psd = info->user_ptr[0];

	mutex_unlock(&psd->lock);
}

static int
psp_nl_dev_fill(struct psp_dev *psd, struct sk_buff *rsp,
		u32 portid, u32 seq, int flags, u32 cmd)
{
	void *hdr;
	int err;

	hdr = genlmsg_put(rsp, portid, seq, &psp_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(rsp, PSP_A_DEV_ID, psd->id) ||
	    nla_put_u32(rsp, PSP_A_DEV_IFINDEX, psd->main_netdev->ifindex) ||
	    nla_put_u32(rsp, PSP_A_DEV_PSP_VERSIONS_CAP, psd->caps->versions) ||
	    nla_put_u32(rsp, PSP_A_DEV_PSP_VERSIONS_ENA, psd->config.versions))
		goto err_cancel_msg;

	genlmsg_end(rsp, hdr);
	return 0;

err_cancel_msg:
	genlmsg_cancel(rsp, hdr);
	return err;
}

void psp_nl_notify_dev(struct psp_dev *psd, u32 cmd)
{
	struct sk_buff *ntf;

	if (!genl_has_listeners(&psp_nl_family, dev_net(psd->main_netdev),
				PSP_NLGRP_MGMT))
		return;

	ntf = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!ntf)
		return;

	if (psp_nl_dev_fill(psd, ntf, 0, 0, 0, cmd)) {
		nlmsg_free(ntf);
		return;
	}

	genlmsg_multicast_netns(&psp_nl_family, dev_net(psd->main_netdev), ntf,
				0, PSP_NLGRP_MGMT, GFP_KERNEL);
}

int psp_nl_dev_get_doit(struct sk_buff *req, struct genl_info *info)
{
	struct psp_dev *psd = info->user_ptr[0];
	struct sk_buff *rsp;
	int err;

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	err = psp_nl_dev_fill(psd, rsp, info->snd_portid, info->snd_seq,
			      0, PSP_CMD_DEV_GET);
	if (err)
		goto err_free_msg;

	return genlmsg_reply(rsp, info);

err_free_msg:
	nlmsg_free(rsp);
	return err;
}

static int
psp_nl_dev_get_dumpit_one(struct sk_buff *rsp, struct netlink_callback *cb,
			  struct psp_dev *psd)
{
	if (psp_dev_check_access(psd, sock_net(rsp->sk)))
		return 0;

	return psp_nl_dev_fill(psd, rsp, NETLINK_CB(cb->skb).portid,
			       cb->nlh->nlmsg_seq, NLM_F_MULTI,
			       PSP_CMD_DEV_GET);
}

int psp_nl_dev_get_dumpit(struct sk_buff *rsp, struct netlink_callback *cb)
{
	struct psp_dev *psd;
	unsigned long index;
	int err = 0;

	mutex_lock(&psp_devs_lock);
	xa_for_each_start(&psp_devs, index, psd, cb->args[0]) {
		mutex_lock(&psd->lock);
		err = psp_nl_dev_get_dumpit_one(rsp, cb, psd);
		mutex_unlock(&psd->lock);
		if (err)
			break;

	}
	mutex_unlock(&psp_devs_lock);

	if (err != -EMSGSIZE)
		return err;

	cb->args[0] = index;
	return rsp->len;
}

int psp_nl_dev_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct psp_dev *psd = info->user_ptr[0];
	struct psp_dev_config new_config;
	int err;

	memcpy(&new_config, &psd->config, sizeof(new_config));

	if (info->attrs[PSP_A_DEV_PSP_VERSIONS_ENA]) {
		new_config.versions =
			nla_get_u32(info->attrs[PSP_A_DEV_PSP_VERSIONS_ENA]);
		if (new_config.versions & ~psd->caps->versions) {
			NL_SET_ERR_MSG(info->extack, "Requested PSP versions not supported by the device");
			return -EINVAL;
		}
	} else {
		NL_SET_ERR_MSG(info->extack, "No settings present");
		return -EINVAL;
	}

	if (!memcmp(&new_config, &psd->config, sizeof(new_config)))
		return 0;

	err = psd->ops->set_config(psd, &new_config, info->extack);
	if (err)
		return err;

	memcpy(&psd->config, &new_config, sizeof(new_config));

	psp_nl_notify_dev(psd, PSP_CMD_DEV_CHANGE_NTF);

	return 0;
}

/* Socket handling */

static void psp_nl_sock_free(struct psp_nl_sock *psp_nl_sock)
{
	kfree(psp_nl_sock);
}

int psp_netlink_notify(struct notifier_block *nb, unsigned long state,
		       void *_notify)
{
	struct netlink_notify *notify = _notify;
	struct psp_nl_sock *psp_nl_sock;
	struct psp_pernet *psp_net;

	if (state != NETLINK_URELEASE || notify->protocol != NETLINK_GENERIC)
		return NOTIFY_DONE;

	psp_net = psp_get_pernet(notify->net);

	psp_nl_sock = xa_erase(&psp_net->sockets, notify->portid);
	if (psp_nl_sock)
		psp_nl_sock_free(psp_nl_sock);

	return NOTIFY_OK;
}

static struct psp_nl_sock *psp_nl_sock(struct sock *sk, struct genl_info *info)
{
	struct psp_pernet *psp_net = psp_get_pernet(genl_info_net(info));
	struct psp_nl_sock *psp_nl_sock, *old;

	if (!info->snd_portid)
		return ERR_PTR(-EINVAL);

	mutex_lock(&psp_net->sockets_lock);

	psp_nl_sock = xa_load(&psp_net->sockets, info->snd_portid);
	if (psp_nl_sock)
		goto exit_unlock;

	psp_nl_sock = kzalloc(sizeof(*psp_nl_sock), GFP_KERNEL);
	if (!psp_nl_sock) {
		psp_nl_sock = ERR_PTR(-ENOMEM);
		goto exit_unlock;
	}

	old = xa_store(&psp_net->sockets, info->snd_portid, psp_nl_sock,
		       GFP_KERNEL);
	if (!old)
		goto exit_unlock;
	if (!xa_is_err(old)) {
		WARN_ON_ONCE(1);
		goto exit_unlock;
	}

	psp_nl_sock_free(psp_nl_sock);
	psp_nl_sock = ERR_PTR(xa_err(old));

exit_unlock:
	mutex_unlock(&psp_net->sockets_lock);

	return psp_nl_sock;
}

/* Key etc. */

int psp_assoc_device_get_locked(const struct genl_split_ops *ops,
				struct sk_buff *skb, struct genl_info *info);
{
	struct nlattr *id = info->attrs[PSP_A_ASSOC_DEV_ID];

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_ASSOC_DEV_ID))
		return -EINVAL;

	info->user_ptr[0] = psp_device_get_and_lock(genl_info_net(info), id);
	return PTR_ERR_OR_ZERO(info->user_ptr[0]);

}

static int psp_nl_tx_assoc_check_key_size(struct genl_info *info)
{
	int key_sz;

	switch (nla_get_u32(info->attrs[PSP_A_KEYS_VERSION])) {
	case PSP_VERSION_HDR0_AES_GCM_128:
	case PSP_VERSION_HDR0_AES_GMAC_128:
		key_sz = 8;
		break;
	case PSP_VERSION_HDR0_AES_GCM_256:
	case PSP_VERSION_HDR0_AES_GMAC_256:
		key_sz = 16;
		break;
	default:
		/* can't happen b/c of policy but make compilers happy */
		return -EINVAL;
	}
	if (nla_len(info->attrs[PSP_A_KEYS_KEY]) != key_sz) {
		NL_SET_ERR_MSG(info->extack, "Invalid key size for selected protocol version");
		return -EINVAL;
	}

	return key_sz;
}

int psp_nl_assoc_add_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct psp_dev *psd = info->user_ptr[0];
	struct psp_nl_sock *psp_nl;
	struct psp_tx_assoc *tas;
	struct sk_buff *rsp;
	int key_sz;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_DEV_ID) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_VERSION) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_KEY) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_SPI))
		return -EINVAL;

	psp_nl = psp_nl_sock(skb->sk, info);
	if (IS_ERR(psp_nl))
		return PTR_ERR(psp_nl);

	err = psp_nl_tx_assoc_check_key_size(info);
	if (err < 0)
		return err;
	key_sz = err;

	rsp = genlmsg_new_reply(info, GENLMSG_DEFAULT_SIZE, GFP_KERNEL,
				&psp_nl_family, PSP_CMD_TX_ASSOC_ADD);
	if (!rsp)
		return -ENOMEM;

	tas = kzalloc(struct_size(tas, drv_data, psd->caps->tx_assoc_drv_spc),
		      GFP_KERNEL_ACCOUNT);
	if (!tas) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	refcount_set(&tas->refcnt, 1);

	tas->version	= nla_get_u32(info->attrs[PSP_A_KEYS_VERSION]);
	tas->spi	= nla_get_u32(info->attrs[PSP_A_KEYS_SPI]);
	memcpy(tas->key, nla_data(info->attrs[PSP_A_KEYS_KEY]), key_sz);

	err = psd->ops->tx_assoc_add(psd, tas, info->extack);
	if (err)
		goto err_free_tas;

	if (info->attrs[PSP_A_KEYS_SOCK_FD]) {
		int fd = nla_get_u32(info->attrs[PSP_A_KEYS_SOCK_FD]);

		err = psp_sock_tx_assoc_set(fd, tas);
		if (err)
			goto err_dev_del;
	}

	return genlmsg_reply(rsp, info);

err_dev_del:
	psd->ops->tx_assoc_del(psd, tas);
err_free_tas:
	kfree(tas);
err_free_msg:
	nlmsg_free(rsp);
	return err;
}
