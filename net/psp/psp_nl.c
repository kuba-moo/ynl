/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/skbuff.h>
#include <linux/xarray.h>
#include <net/genetlink.h>
#include <net/psp.h>
#include <net/sock.h>

#include "psp-nl-gen.h"
#include "psp.h"

/* Netlink helpers */

static struct sk_buff *psp_nl_reply_new(struct genl_info *info)
{
	struct sk_buff *rsp;
	void *hdr;

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp)
		return NULL;

	hdr = genlmsg_put_reply(rsp, info, &psp_nl_family, 0,
				info->genlhdr->cmd);
	if (!hdr) {
		nlmsg_free(rsp);
		return NULL;
	}

	return rsp;
}

static int psp_nl_reply_send(struct sk_buff *rsp, struct genl_info *info)
{
	/* Note that this *only* works with a single message per skb */
	void *hdr = rsp->data + NLMSG_HDRLEN + GENL_HDRLEN;

	genlmsg_end(rsp, hdr);

	return genlmsg_reply(rsp, info);
}

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
				struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *id = info->attrs[PSP_A_ASSOC_DEV_ID];

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_ASSOC_DEV_ID))
		return -EINVAL;

	info->user_ptr[0] = psp_device_get_and_lock(genl_info_net(info), id);
	return PTR_ERR_OR_ZERO(info->user_ptr[0]);

}

static unsigned int psp_nl_assoc_key_size(u32 version)
{
	switch (version) {
	case PSP_VERSION_HDR0_AES_GCM_128:
	case PSP_VERSION_HDR0_AES_GMAC_128:
		return 16;
	case PSP_VERSION_HDR0_AES_GCM_256:
	case PSP_VERSION_HDR0_AES_GMAC_256:
		return 32;
	default:
		/* Netlink policies should prevent us from getting here */
		WARN_ON_ONCE(1);
		return 0;
	}
}

static int
psp_nl_parse_key(struct genl_info *info, u32 attr, struct psp_key_parsed *key,
		 unsigned int key_sz)
{
	struct nlattr *nest = info->attrs[attr];
	struct nlattr *tb[PSP_A_KEYS_SPI + 1];
	int err;

	err = nla_parse_nested(tb, ARRAY_SIZE(tb) - 1, nest,
			       psp_keys_nl_policy, info->extack);
	if (err)
		return err;

	if (NL_REQ_ATTR_CHECK(info->extack, nest, tb, PSP_A_KEYS_KEY) ||
	    NL_REQ_ATTR_CHECK(info->extack, nest, tb, PSP_A_KEYS_SPI))
		return -EINVAL;

	if (nla_len(tb[PSP_A_KEYS_KEY]) != key_sz) {
		NL_SET_ERR_MSG_ATTR(info->extack, tb[PSP_A_KEYS_KEY],
				    "incorrect key length");
		return -EINVAL;
	}

	key->spi = cpu_to_be32(nla_get_u32(tb[PSP_A_KEYS_SPI]));
	memcpy(key->key, nla_data(tb[PSP_A_KEYS_KEY]), key_sz);

	return 0;
}

static int
psp_nl_put_key(struct sk_buff *skb, u32 attr, u32 version,
	       struct psp_key_parsed *key)
{
	int key_sz = psp_nl_assoc_key_size(version);
	void *nest;

	nest = nla_nest_start(skb, attr);

	if (nla_put_u32(skb, PSP_A_KEYS_SPI, be32_to_cpu(key->spi)) ||
	    nla_put(skb, PSP_A_KEYS_KEY, key_sz, key->key)) {
		nla_nest_cancel(skb, nest);
		return -EMSGSIZE;
	}

	nla_nest_end(skb, nest);

	return 0;
}

int psp_nl_rx_assoc_alloc_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct psp_dev *psd = info->user_ptr[0];
	struct psp_key_parsed key;
	struct sk_buff *rsp;
	u32 version;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_ASSOC_VERSION))
		return -EINVAL;

	version = nla_get_u32(info->attrs[PSP_A_ASSOC_VERSION]);

	rsp = psp_nl_reply_new(info);
	if (!rsp)
		return -ENOMEM;

	err = psd->ops->rx_spi_alloc(psd, version, &key, info->extack);
	if (err)
		goto err_free_rsp;

	if (nla_put_u32(rsp, PSP_A_ASSOC_DEV_ID, psd->id) ||
	    nla_put_u32(rsp, PSP_A_ASSOC_VERSION, version) ||
	    psp_nl_put_key(rsp, PSP_A_ASSOC_RX_KEY, version, &key)) {
		err = -EMSGSIZE;
		goto err_free_rsp;
	}

	return psp_nl_reply_send(rsp, info);

err_free_rsp:
	nlmsg_free(rsp);
	return err;
}

int psp_nl_assoc_add_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct psp_dev *psd = info->user_ptr[0];
	struct psp_nl_sock *psp_nl;
	struct psp_assoc *pas;
	struct sk_buff *rsp;
	unsigned int key_sz;
	u32 version;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_ASSOC_DEV_ID) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_ASSOC_VERSION) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_ASSOC_TX_KEY) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_ASSOC_RX_KEY))
		return -EINVAL;

	psp_nl = psp_nl_sock(skb->sk, info);
	if (IS_ERR(psp_nl))
		return PTR_ERR(psp_nl);

	version = nla_get_u32(info->attrs[PSP_A_ASSOC_VERSION]);
	key_sz = psp_nl_assoc_key_size(version);
	if (!key_sz)
		return -EINVAL;

	pas = psp_assoc_create(psd);
	if (!pas)
		return -ENOMEM;

	err = psp_nl_parse_key(info, PSP_A_ASSOC_RX_KEY, &pas->rx, key_sz);
	if (err < 0)
		goto err_free_pas;
	err = psp_nl_parse_key(info, PSP_A_ASSOC_TX_KEY, &pas->tx, key_sz);
	if (err < 0)
		goto err_free_pas;

	rsp = psp_nl_reply_new(info);
	if (!rsp)
		goto err_free_pas;

	err = psd->ops->assoc_add(psd, pas, info->extack);
	if (err)
		goto err_free_msg;

	if (info->attrs[PSP_A_ASSOC_SOCK_FD]) {
		int fd = nla_get_u32(info->attrs[PSP_A_ASSOC_SOCK_FD]);

		err = psp_sock_assoc_set(fd, pas);
		if (err)
			goto err_dev_del;
	}

	/* TODO: allow ref'ing the association onto the socket */
	psp_assoc_put(pas);

	return psp_nl_reply_send(rsp, info);

err_dev_del:
	psd->ops->assoc_del(psd, pas);
err_free_msg:
	nlmsg_free(rsp);
err_free_pas:
	kfree(pas);
	return err;
}
