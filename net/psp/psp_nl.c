/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/skbuff.h>
#include <linux/xarray.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include <linux/psp.h>
#include "psp-nl-gen.h"
#include "psp.h"

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
	struct sk_buff *rsp;
	struct psp_dev *psd;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_DEV_ID))
		return -EINVAL;

	psd = psp_device_get_and_lock(genl_info_net(info),
				      info->attrs[PSP_A_DEV_ID]);
	if (IS_ERR(psd))
		return PTR_ERR(psd);

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp) {
		err = -ENOMEM;
		goto err_unlock;
	}

	err = psp_nl_dev_fill(psd, rsp, info->snd_portid, info->snd_seq,
			      0, PSP_CMD_DEV_GET);
	if (err)
		goto err_free_msg;

	mutex_unlock(&psd->lock);

	return genlmsg_reply(rsp, info);

err_free_msg:
	nlmsg_free(rsp);
err_unlock:
	mutex_unlock(&psd->lock);
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
	struct psp_dev_config new_config;
	struct psp_dev *psd;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_DEV_ID))
		return -EINVAL;

	psd = psp_device_get_and_lock(genl_info_net(info),
				      info->attrs[PSP_A_DEV_ID]);
	if (IS_ERR(psd))
		return PTR_ERR(psd);

	memcpy(&new_config, &psd->config, sizeof(new_config));

	if (info->attrs[PSP_A_DEV_PSP_VERSIONS_ENA]) {
		new_config.versions =
			nla_get_u32(info->attrs[PSP_A_DEV_PSP_VERSIONS_ENA]);
		if (new_config.versions & ~psd->caps->versions) {
			NL_SET_ERR_MSG(info->extack, "Requested PSP versions not supported by the device");
			err = -EINVAL;
			goto err_unlock;
		}
	} else {
		NL_SET_ERR_MSG(info->extack, "No settings present");
		err = -EINVAL;
		goto err_unlock;
	}

	if (!memcmp(&new_config, &psd->config, sizeof(new_config))) {
		err = 0;
		goto err_unlock;
	}

	err = psd->ops->set_config(psd, &new_config, info->extack);
	if (err)
		goto err_unlock;

	memcpy(&psd->config, &new_config, sizeof(new_config));

	psp_nl_notify_dev(psd, PSP_CMD_DEV_CHANGE_NTF);

	mutex_unlock(&psd->lock);

	return 0;

err_unlock:
	mutex_unlock(&psd->lock);
	return err;
}

int psp_nl_tx_assoc_add_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct psp_tx_assoc *tas;
	struct psp_dev *psd;
	struct sk_buff *rsp;
	size_t key_sz;
	u32 version;
	void *hdr;
	int err;

	if (GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_DEV_ID) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_VERSION) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_KEY) ||
	    GENL_REQ_ATTR_CHECK(info, PSP_A_KEYS_SPI))
		return -EINVAL;

	psd = psp_device_get_and_lock(genl_info_net(info),
				      info->attrs[PSP_A_KEYS_DEV_ID]);
	if (IS_ERR(psd))
		return PTR_ERR(psd);

	version = nla_get_u32(info->attrs[PSP_A_KEYS_VERSION]);
	switch (version) {
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
		err = -EINVAL;
		goto err_unlock;
	}
	if (nla_len(info->attrs[PSP_A_KEYS_KEY]) != key_sz) {
		NL_SET_ERR_MSG(info->extack, "Invalid key size for selected protocol version");
		err = -EINVAL;
		goto err_unlock;
	}

	rsp = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!rsp) {
		err = -ENOMEM;
		goto err_unlock;
	}

	hdr = genlmsg_put(rsp, info->snd_portid, info->snd_seq,
			  &psp_nl_family, 0, PSP_CMD_TX_ASSOC_ADD);
	if (!hdr) {
		err = -EMSGSIZE;
		goto err_free_msg;
	}

	tas = kzalloc(struct_size(tas, drv_data, psd->caps->tx_assoc_drv_spc),
		      GFP_KERNEL);
	if (!tas) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	tas->version = version;
	tas->spi = nla_get_u32(info->attrs[PSP_A_KEYS_SPI]);
	memcpy(tas->key, nla_data(info->attrs[PSP_A_KEYS_KEY]), key_sz);
	refcount_set(&tas->refcnt, 1);

	err = psd->ops->tx_assoc_add(psd, tas, info->extack);
	if (err)
		goto err_free_tas;

	mutex_unlock(&psd->lock);

	return genlmsg_reply(rsp, info);

err_free_tas:
	kfree(tas);
err_free_msg:
	nlmsg_free(rsp);
err_unlock:
	mutex_unlock(&psd->lock);
	return err;
}
