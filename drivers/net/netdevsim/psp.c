/* SPDX-License-Identifier: GPL-2.0 */

#include <net/psp.h>
#include <net/ip6_checksum.h>

#include "netdevsim.h"

MODULE_IMPORT_NS(NETDEV_PRIVATE);

struct psp_insert {
	struct udphdr udp;
	struct psphdr psp;
};

enum skb_drop_reason
nsim_do_psp(struct sk_buff *skb, struct netdevsim *ns,
	    struct netdevsim *peer_ns, struct skb_ext **psp_ext)
{
	struct psp_skb_ext *pse;
	struct psp_insert *psp;
	struct psp_assoc *pas;
	unsigned int offs;
	void *start;
	void **ptr;
	int err;

	pas = psp_skb_get_assoc_rcu(skb);
	if (likely(!pas))
		return 0;

	if (!skb_transport_header_was_set(skb))
		return SKB_DROP_REASON_PSP_OUTPUT;

	ptr = psp_assoc_drv_data(pas);
	if (*ptr != ns) {
		pr_err_ratelimited("drv priv mismatch %px != %px\n", *ptr, ns);
		return SKB_DROP_REASON_PSP_OUTPUT;
	}

	/* Fake inserting the headers */
	err = skb_cow_head(skb, sizeof(*psp));
	if (err < 0)
		return SKB_DROP_REASON_NOMEM;

	offs = skb_transport_offset(skb);

	start = skb_push(skb, sizeof(*psp));
	psp = start + offs;

	memmove(start, start + sizeof(*psp), offs);

	psp->udp.source = htons(1234);
	psp->udp.dest = htons(PSP_DEFAULT_UDP_PORT);
	psp->udp.len = htons(skb->len - offs);
	psp->udp.check = 0;

	psp->psp.nexthdr = IPPROTO_TCP;
	psp->psp.hdrlen = PSP_HDRLEN_NOOPT;
	psp->psp.crypt_offset = FIELD_PREP(PSPHDR_CRYPT_OFFSET, 0);
	psp->psp.verfl = FIELD_PREP(PSPHDR_VERFL_VERSION, pas->version) |
			 FIELD_PREP(PSPHDR_VERFL_ONE, 1);
	psp->psp.spi = pas->tx.spi;
	psp->psp.iv = cpu_to_be64(sched_clock());

	/* Now pretend we just received this frame */
	if (peer_ns->psp.dev->config.versions & (1 << pas->version)) {
		skb_pull(skb, sizeof(*psp));
		memmove(skb->data, start, offs);

		skb->decrypted = 1;
		/* Allocate a fresh ext which has only PSP in it.
		 * skb_scrub_packet() would reset the old ext, anyway.
		 */
		skb_ext_reset(skb);
		pse = skb_ext_add(skb, SKB_EXT_PSP);
		if (!pse)
			return SKB_DROP_REASON_NOMEM;
		*psp_ext = skb->extensions;
		refcount_inc(&(*psp_ext)->refcnt);

		pse->spi = pas->tx.spi;
		/* We cheat a bit and put the generation in the key.
		 * In real life if generation was too old decrypt would fail
		 * here because device key is out of the picture.
		 */
		pse->generation = pas->tx.key[0];
		pse->version = pas->version;

		u64_stats_update_begin(&peer_ns->syncp);
		peer_ns->psp.rx_packets++;
		peer_ns->psp.rx_bytes += skb->len - ETH_HLEN;
		u64_stats_update_end(&peer_ns->syncp);
	} else {
		struct ipv6hdr *ip6h;
		struct iphdr *iph;
		__wsum csum;

		skb->mac_header		-= sizeof(*psp);
		skb->network_header	-= sizeof(*psp);
		skb->transport_header	-= sizeof(*psp);

		csum = skb_checksum(skb, skb_transport_offset(skb),
				    ntohs(psp->udp.len), 0);

		switch (skb->protocol) {
		case htons(ETH_P_IP):
			iph = ip_hdr(skb);
			iph->protocol = IPPROTO_UDP;
			be16_add_cpu(&iph->tot_len, sizeof(*psp));
			ip_send_check(iph);
			psp->udp.check = udp_v4_check(ntohs(psp->udp.len),
						      iph->saddr,
						      iph->daddr, csum);
			break;
#if IS_ENABLED(CONFIG_IPV6)
		case htons(ETH_P_IPV6):
			ip6h = ipv6_hdr(skb);
			ip6h->nexthdr =	IPPROTO_UDP;
			be16_add_cpu(&ip6h->payload_len, sizeof(*psp));
			psp->udp.check = udp_v6_check(ntohs(psp->udp.len),
						      &ip6h->saddr,
						      &ip6h->daddr, csum);
			break;
#endif
		}

		psp->udp.check	= psp->udp.check ?: CSUM_MANGLED_0;
		skb->ip_summed	= CHECKSUM_NONE;
	}

	u64_stats_update_begin(&ns->syncp);
	ns->psp.tx_packets++;
	ns->psp.tx_bytes += skb->len - ETH_HLEN;
	u64_stats_update_end(&ns->syncp);

	return 0;
}

static int
nsim_psp_set_config(struct psp_dev *psd, struct psp_dev_config *conf,
		    struct netlink_ext_ack *extack)
{
	return 0;
}

static int
nsim_rx_spi_alloc(struct psp_dev *psd, u32 version,
		  struct psp_key_parsed *assoc,
		  struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = psd->drv_priv;
	unsigned int new;
	int i;

	new = ++ns->psp.spi & PSP_SPI_KEY_ID;
	if (psd->generation & 1)
		new |= PSP_SPI_KEY_PHASE;

	assoc->spi = cpu_to_be32(new);
	assoc->key[0] = psd->generation;
	for (i = 1; i < PSP_MAX_KEY; i++)
		assoc->key[i] = ns->psp.spi + i;

	return 0;
}

static int nsim_assoc_add(struct psp_dev *psd, struct psp_assoc *pas,
			  struct netlink_ext_ack *extack)
{
	struct netdevsim *ns = psd->drv_priv;
	void **ptr = psp_assoc_drv_data(pas);

	/* Copy drv_priv from psd to assoc */
	*ptr = psd->drv_priv;

	pr_info("PSP assoc add: rx:%u tx:%u\n",
		be32_to_cpu(pas->rx.spi), be32_to_cpu(pas->tx.spi));

	ns->psp.assoc_cnt++;
	return 0;
}

static int nsim_key_rotate(struct psp_dev *psd, struct netlink_ext_ack *extack)
{
	pr_info("PSP key rotation\n");

	return 0;
}

static void nsim_assoc_del(struct psp_dev *psd, struct psp_assoc *pas)
{
	struct netdevsim *ns = psd->drv_priv;
	void **ptr = psp_assoc_drv_data(pas);

	*ptr = NULL;
	ns->psp.assoc_cnt--;
}

static void nsim_get_stats(struct psp_dev *psd, struct psp_dev_stats *stats)
{
	struct netdevsim *ns = psd->drv_priv;
	unsigned int start;

	/* WARNING: do *not* blindly zero stats in real drivers!
	 * All required stats must be reported by the device!
	 */
	memset(stats, 0, offsetof(struct psp_dev_stats, required_end));

	do {
		start = u64_stats_fetch_begin(&ns->syncp);
		stats->rx_bytes = ns->psp.rx_bytes;
		stats->rx_packets = ns->psp.rx_packets;
		stats->tx_bytes = ns->psp.tx_bytes;
		stats->tx_packets = ns->psp.tx_packets;
	} while (u64_stats_fetch_retry(&ns->syncp, start));
}

static struct psp_dev_ops nsim_psp_ops = {
	.set_config	= nsim_psp_set_config,
	.rx_spi_alloc	= nsim_rx_spi_alloc,
	.tx_key_add	= nsim_assoc_add,
	.tx_key_del	= nsim_assoc_del,
	.key_rotate	= nsim_key_rotate,
	.get_stats	= nsim_get_stats,
};

static struct psp_dev_caps nsim_psp_caps = {
	.versions = 1 << PSP_VERSION_HDR0_AES_GCM_128 |
		    1 << PSP_VERSION_HDR0_AES_GMAC_128 |
		    1 << PSP_VERSION_HDR0_AES_GCM_256 |
		    1 << PSP_VERSION_HDR0_AES_GMAC_256,
	.assoc_drv_spc = sizeof(void *),
};

void nsim_psp_uninit(struct netdevsim *ns)
{
	if (!IS_ERR(ns->psp.dev))
		psp_dev_unregister(ns->psp.dev);
	WARN_ON(ns->psp.assoc_cnt);
}

static ssize_t
nsim_psp_rereg_write(struct file *file, const char __user *data, size_t count,
		     loff_t *ppos)
{
	struct netdevsim *ns = file->private_data;
	int err;

	nsim_psp_uninit(ns);

	ns->psp.dev = psp_dev_create(ns->netdev, &nsim_psp_ops,
				     &nsim_psp_caps, ns);
	err = PTR_ERR_OR_ZERO(ns->psp.dev);
	return err ?: count;
}

static const struct file_operations nsim_psp_rereg_fops = {
	.open = simple_open,
	.write = nsim_psp_rereg_write,
	.llseek = generic_file_llseek,
	.owner = THIS_MODULE,
};

int nsim_psp_init(struct netdevsim *ns)
{
	struct dentry *ddir = ns->nsim_dev_port->ddir;
	int err;

	ns->psp.dev = psp_dev_create(ns->netdev, &nsim_psp_ops,
				     &nsim_psp_caps, ns);
	err = PTR_ERR_OR_ZERO(ns->psp.dev);
	if (err)
		return err;

	debugfs_create_file("psp_rereg", 0200, ddir, ns, &nsim_psp_rereg_fops);
	return 0;
}
