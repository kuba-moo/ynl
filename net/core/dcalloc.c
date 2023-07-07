#include "dcalloc.h"

#include <linux/dma-mapping.h>
#include <linux/sizes.h>
#include <linux/slab.h>

static bool dma_sal_in_use(struct dma_slow_allocator *sal)
{
	return refcount_read(&sal->user_cnt);
}

int dma_slow_huge_init(struct dma_slow_huge *shu, void *addr,
		       unsigned int size, dma_addr_t dma, gfp_t gfp)
{
	struct dma_slow_buddy *bud;

	bud = kzalloc(sizeof(*bud), gfp);
	if (!bud)
		return -ENOMEM;

	shu->addr = addr;
	shu->size = size;
	shu->dma = dma;

	INIT_LIST_HEAD(&shu->buddy_list);

	bud->size = size;
	bud->free = true;
	list_add(&bud->list, &shu->buddy_list);

	return 0;
}

static struct dma_slow_buddy *
dma_slow_bud_split(struct dma_slow_buddy *bud, gfp_t gfp)
{
	struct dma_slow_buddy *right;

	right = kzalloc(sizeof(*bud), gfp);
	if (!right)
		return NULL;

	bud->size /= 2;

	right->offset = bud->offset + bud->size;
	right->size = bud->size;
	right->free = true;

	list_add(&right->list, &bud->list);

	return bud;
}

static bool dma_slow_bud_coalesce(struct dma_slow_huge *shu)
{
	struct dma_slow_buddy *bud, *left = NULL, *right = NULL;

	list_for_each_entry(bud, &shu->buddy_list, list) {
		if (left && bud &&
		    left->free && bud->free &&
		    left->size == bud->size &&
		    (left->offset & bud->offset) == left->offset) {
			right = bud;
			break;
		}
		left = bud;
	}

	if (!right)
		return false;

	left->size *= 2;
	list_del(&right->list);
	kfree(right);
	return true;
}

static void *
__dma_sal_alloc_buddy(struct dma_slow_allocator *sal, struct dma_slow_huge *shu,
		      unsigned int size, dma_addr_t *dma, gfp_t gfp)
{
	struct dma_slow_buddy *small_fit = NULL;
	struct dma_slow_buddy *bud;

	if (shu->size < size)
		return NULL;

	list_for_each_entry(bud, &shu->buddy_list, list) {
		if (!bud->free || bud->size < size)
			continue;

		if (!small_fit || small_fit->size > bud->size)
			small_fit = bud;
		if (bud->size == size)
			break;
	}
	if (!small_fit)
		return NULL;
	bud = small_fit;

	while (bud->size >= size * 2) {
		bud = dma_slow_bud_split(bud, gfp);
		if (!bud)
			return NULL;
	}

	bud->free = false;
	*dma = shu->dma + bud->offset;
	return shu->addr + (bud->offset >> sal->ops->ptr_shf);
}

static void *
dma_sal_alloc_buddy(struct dma_slow_allocator *sal, unsigned int size,
		    dma_addr_t *dma, gfp_t gfp)
{
	struct dma_slow_huge *shu;
	void *addr;

	list_for_each_entry(shu, &sal->huge, huge) {
		addr = __dma_sal_alloc_buddy(sal, shu, size, dma, gfp);
		if (addr)
			return addr;
	}

	if (!sal->ops->alloc_huge)
		return NULL;

	shu = kzalloc(sizeof(*shu), gfp);
	if (!shu)
		return NULL;
	if (sal->ops->alloc_huge(sal, shu, size, gfp)) {
		kfree(shu);
		return NULL;
	}
	list_add(&shu->huge, &sal->huge);

	return __dma_sal_alloc_buddy(sal, shu, size, dma, gfp);
}

static bool
__dma_sal_free_buddy(struct dma_slow_allocator *sal, struct dma_slow_huge *shu,
		     void *addr, unsigned int size, dma_addr_t dma)
{
	struct dma_slow_buddy *bud;
	dma_addr_t exp_dma;
	void *exp_addr;

	list_for_each_entry(bud, &shu->buddy_list, list) {
		exp_dma = shu->dma + bud->offset;
		exp_addr = shu->addr + (bud->offset >> sal->ops->ptr_shf);

		if (exp_addr != addr)
			continue;

		if (exp_dma != dma || bud->size != size)
			pr_warn("mep param mismatch: %u %u, %lu %lu\n",
				bud->size, size, (ulong)exp_dma, (ulong)dma);
		if (bud->free)
			pr_warn("double free: %d %lu\n", size, (ulong)dma);
		bud->free = true;
		return true;
	}

	return false;
}

static void
dma_slow_maybe_free_huge(struct dma_slow_allocator *sal,
			 struct dma_slow_huge *shu)
{
	struct dma_slow_buddy *bud;

	bud = list_first_entry(&shu->buddy_list, typeof(*bud), list);
	if (!bud->free || bud->size != shu->size)
		return;

	if (!sal->ops->alloc_huge)
		return;

	kfree(bud);

	sal->ops->free_huge(sal, shu);
	list_del(&shu->huge);
	kfree(shu);
}

static bool
dma_sal_free_buddy(struct dma_slow_allocator *sal, void *addr,
		   unsigned int order, dma_addr_t dma)
{
	struct dma_slow_huge *shu;
	bool freed = false;

	list_for_each_entry(shu, &sal->huge, huge) {
		freed = __dma_sal_free_buddy(sal, shu, addr, order, dma);
		if (freed)
			break;
	}
	if (freed) {
		while (dma_slow_bud_coalesce(shu))
			/* I know, it's not efficient.
			 * But all of SAL is on the config path.
			 */;
		dma_slow_maybe_free_huge(sal, shu);
	}
	return freed;
}

static void *
dma_sal_alloc_fb(struct dma_slow_allocator *sal, unsigned int size,
		 dma_addr_t *dma, gfp_t gfp)
{
	struct dma_slow_fall *fb;

	fb = kzalloc(sizeof(*fb), gfp);
	if (!fb)
		return NULL;
	fb->size = size;

	if (sal->ops->alloc_fall(sal, fb, size, gfp)) {
		kfree(fb);
		return NULL;
	}
	list_add(&fb->fb, &sal->fallback);

	*dma = fb->dma;
	return fb->addr;
}

static bool dma_sal_free_fb(struct dma_slow_allocator *sal, void *addr,
			    unsigned int size, dma_addr_t dma)
{
	struct dma_slow_fall *fb, *pos;

	fb = NULL;
	list_for_each_entry(pos, &sal->fallback, fb)
		if (pos->addr == addr) {
			fb = pos;
			break;
		}

	if (!fb) {
		pr_warn("free: address %px not found\n", addr);
		return false;
	}

	if (fb->size != size || fb->dma != dma)
		pr_warn("free: param mismatch: %u %u, %lu %lu\n",
			fb->size, size, (ulong)fb->dma, (ulong)dma);

	list_del(&fb->fb);
	sal->ops->free_fall(sal, fb);
	kfree(fb);
	return true;
}

void *dma_sal_alloc(struct dma_slow_allocator *sal, unsigned int size,
		    dma_addr_t *dma, gfp_t gfp)
{
	void *ret;

	ret = dma_sal_alloc_buddy(sal, size, dma, gfp);
	if (!ret)
		ret = dma_sal_alloc_fb(sal, size, dma, gfp);
	if (!ret)
		return NULL;

	dma_slow_get(sal);
	return ret;
}

void dma_sal_free(struct dma_slow_allocator *sal, void *addr,
		  unsigned int size, dma_addr_t dma)
{
	if (!dma_sal_free_buddy(sal, addr, size, dma) &&
	    !dma_sal_free_fb(sal, addr, size, dma))
		return;

	dma_slow_put(sal);
}

void dma_sal_init(struct dma_slow_allocator *sal,
		  const struct dma_slow_allocator_ops *ops,
		  struct device *dev)
{
	sal->ops = ops;
	sal->dev = dev;

	INIT_LIST_HEAD(&sal->huge);
	INIT_LIST_HEAD(&sal->fallback);

	refcount_set(&sal->user_cnt, 1);
}

/*****************************
 ***  DMA COCOA allocator  ***
 *****************************/
static int
dma_cocoa_alloc_huge(struct dma_slow_allocator *sal, struct dma_slow_huge *shu,
		     unsigned int size, gfp_t gfp)
{
	if (size >= SZ_2M)
		return -ENOMEM;

	shu->addr = dma_alloc_coherent(sal->dev, SZ_2M, &shu->dma, gfp);
	if (!shu->addr)
		return -ENOMEM;

	if (dma_slow_huge_init(shu, shu->addr, SZ_2M, shu->dma, gfp))
		goto err_free_dma;

	return 0;

err_free_dma:
	dma_free_coherent(sal->dev, SZ_2M, shu->addr, shu->dma);
	return -ENOMEM;
}

static void
dma_cocoa_free_huge(struct dma_slow_allocator *sal, struct dma_slow_huge *shu)
{
	dma_free_coherent(sal->dev, SZ_2M, shu->addr, shu->dma);
}

static int
dma_cocoa_alloc_fall(struct dma_slow_allocator *sal, struct dma_slow_fall *fb,
		     unsigned int size, gfp_t gfp)
{
	fb->addr = dma_alloc_coherent(sal->dev, size, &fb->dma, gfp);
	if (!fb->addr)
		return -ENOMEM;
	return 0;
}

static void
dma_cocoa_free_fall(struct dma_slow_allocator *sal, struct dma_slow_fall *fb)
{
	dma_free_coherent(sal->dev, fb->size, fb->addr, fb->dma);
}

struct dma_slow_allocator_ops dma_cocoa_ops = {
	.alloc_huge	= dma_cocoa_alloc_huge,
	.free_huge	= dma_cocoa_free_huge,
	.alloc_fall	= dma_cocoa_alloc_fall,
	.free_fall	= dma_cocoa_free_fall,
};

struct dma_cocoa {
	struct dma_slow_allocator sal;
};

struct dma_cocoa *dma_cocoa_create(struct device *dev, gfp_t gfp)
{
	struct dma_cocoa *cocoa;

	cocoa = kzalloc(sizeof(*cocoa), gfp);
	if (!cocoa)
		return NULL;

	dma_sal_init(&cocoa->sal, &dma_cocoa_ops, dev);

	return cocoa;
}

void dma_cocoa_destroy(struct dma_cocoa *cocoa)
{
	dma_slow_put(&cocoa->sal);
	WARN_ON(dma_sal_in_use(&cocoa->sal));
	kfree(cocoa);
}

void *dma_cocoa_alloc(struct dma_cocoa *cocoa, unsigned long size,
		      dma_addr_t *dma, gfp_t gfp)
{
	void *addr;

	size = roundup_pow_of_two(size);
	addr = dma_sal_alloc(&cocoa->sal, size, dma, gfp);
	if (!addr)
		return NULL;
	memset(addr, 0, size);
	return addr;
}

void dma_cocoa_free(struct dma_cocoa *cocoa, unsigned long size, void *addr,
		    dma_addr_t dma)
{
	size = roundup_pow_of_two(size);
	return dma_sal_free(&cocoa->sal, addr, size, dma);
}

/*****************************
 ***   DMA MEP allocator   ***
 *****************************/

#include <linux/cma.h>

static struct cma *mep_cma;
static int mep_err;

int __init mep_cma_init(void);
int __init mep_cma_init(void)
{
	int order_per_bit;

	order_per_bit = min(30 - PAGE_SHIFT, MAX_ORDER - 1);
	order_per_bit = min(order_per_bit, HUGETLB_PAGE_ORDER);

	mep_err = cma_declare_contiguous_nid(0,		/* base */
					     SZ_4G,	/* size */
					     0,		/* limit */
					     SZ_1G,	/* alignment */
					     order_per_bit,  /* order_per_bit */
					     false,	/* fixed */
					     "net_mep",	/* name */
					     &mep_cma,	/* res_cma */
					     NUMA_NO_NODE);  /* nid */
	if (mep_err)
		pr_warn("Net MEP init failed: %d\n", mep_err);
	else
		pr_info("Net MEP reserved 4G of memory\n");

	return 0;
}

/** ----- MEP (slow / ctrl) allocator ----- */

void mp_huge_split(struct page *page, unsigned int order)
{
	int i;

	split_page(page, order);
	/* The subsequent pages have a poisoned next, and since we only
	 * OR in the PP_SIGNATURE this will mess up PP detection.
	 */
	for (i = 0; i < (1 << order); i++)
		page[i].pp_magic &= 3UL;
}

struct mem_provider {
	struct dma_slow_allocator sal;

	struct work_struct work;
};

static int
dma_mep_alloc_fall(struct dma_slow_allocator *sal, struct dma_slow_fall *fb,
		   unsigned int size, gfp_t gfp)
{
	int order = get_order(size);

	fb->addr = alloc_pages(gfp, order);
	if (!fb->addr)
		return -ENOMEM;

	fb->dma = dma_map_page_attrs(sal->dev, fb->addr, 0, size,
				     DMA_BIDIRECTIONAL, DMA_ATTR_SKIP_CPU_SYNC);
	if (dma_mapping_error(sal->dev, fb->dma)) {
		put_page(fb->addr);
		return -ENOMEM;
	}

	mp_huge_split(fb->addr, order);
	return 0;
}

static void
dma_mep_free_fall(struct dma_slow_allocator *sal, struct dma_slow_fall *fb)
{
	int order = get_order(fb->size);
	struct page *page;
	int i;

	page = fb->addr;
	dma_unmap_page_attrs(sal->dev, fb->dma, fb->size,
			     DMA_BIDIRECTIONAL, DMA_ATTR_SKIP_CPU_SYNC);
	for (i = 0; i < (1 << order); i++)
		put_page(page + i);
}

static void mep_release_work(struct work_struct *work)
{
	struct mem_provider *mep;

	mep = container_of(work, struct mem_provider, work);

	while (!list_empty(&mep->sal.huge)) {
		struct dma_slow_buddy *bud;
		struct dma_slow_huge *shu;

		shu = list_first_entry(&mep->sal.huge, typeof(*shu), huge);

		dma_unmap_page_attrs(mep->sal.dev, shu->dma, SZ_1G,
				     DMA_BIDIRECTIONAL, DMA_ATTR_SKIP_CPU_SYNC);
		cma_release(mep_cma, shu->addr, SZ_1G / PAGE_SIZE);

		bud = list_first_entry_or_null(&shu->buddy_list,
					       typeof(*bud), list);
		if (WARN_ON(!bud || bud->size != SZ_1G))
			continue;
		kfree(bud);

		list_del(&shu->huge);
		kfree(shu);
	}
	put_device(mep->sal.dev);
	kfree(mep);
}

static void dma_mep_release(struct dma_slow_allocator *sal)
{
	struct mem_provider *mep;

	mep = container_of(sal, struct mem_provider, sal);

	INIT_WORK(&mep->work, mep_release_work);
	schedule_work(&mep->work);
}

struct dma_slow_allocator_ops dma_mep_ops = {
	.ptr_shf	= PAGE_SHIFT - order_base_2(sizeof(struct page)),

	.alloc_fall	= dma_mep_alloc_fall,
	.free_fall	= dma_mep_free_fall,

	.release	= dma_mep_release,
};

struct mem_provider *mep_create(struct device *dev)
{
	struct mem_provider *mep;
	int i;

	mep = kzalloc(sizeof(*mep), GFP_KERNEL);
	if (!mep)
		return NULL;

	dma_sal_init(&mep->sal, &dma_mep_ops, dev);
	get_device(mep->sal.dev);

	if (mep_err)
		goto done;

	/* Hardcoded for now */
	for (i = 0; i < 2; i++) {
		const unsigned int order = 30 - PAGE_SHIFT; /* 1G */
		struct dma_slow_huge *shu;
		struct page *page;

		shu = kzalloc(sizeof(*shu), GFP_KERNEL);
		if (!shu)
			break;

		page = cma_alloc(mep_cma, SZ_1G / PAGE_SIZE, order, false);
		if (!page) {
			pr_err("mep: CMA alloc failed\n");
			goto err_free_shu;
		}

		shu->dma = dma_map_page_attrs(mep->sal.dev, page, 0,
					      PAGE_SIZE << order,
					      DMA_BIDIRECTIONAL,
					      DMA_ATTR_SKIP_CPU_SYNC);
		if (dma_mapping_error(mep->sal.dev, shu->dma)) {
			pr_err("mep: DMA map failed\n");
			goto err_free_page;
		}

		if (dma_slow_huge_init(shu, page, SZ_1G, shu->dma,
				       GFP_KERNEL)) {
			pr_err("mep: shu init failed\n");
			goto err_unmap;
		}

		mp_huge_split(page, 30 - PAGE_SHIFT);

		list_add(&shu->huge, &mep->sal.huge);
		continue;

err_unmap:
		dma_unmap_page_attrs(mep->sal.dev, shu->dma, SZ_1G,
				     DMA_BIDIRECTIONAL, DMA_ATTR_SKIP_CPU_SYNC);
err_free_page:
		put_page(page);
err_free_shu:
		kfree(shu);
		break;
	}
done:
	if (list_empty(&mep->sal.huge))
		pr_warn("mep: no huge pages acquired\n");

	return mep;
}
EXPORT_SYMBOL_GPL(mep_create);

void mep_destroy(struct mem_provider *mep)
{
	dma_slow_put(&mep->sal);
}
EXPORT_SYMBOL_GPL(mep_destroy);

struct page *mep_alloc(struct mem_provider *mep, unsigned int order,
		       dma_addr_t *dma, gfp_t gfp)
{
	return dma_sal_alloc(&mep->sal, PAGE_SIZE << order, dma, gfp);
}
EXPORT_SYMBOL_GPL(mep_alloc);

void mep_free(struct mem_provider *mep, struct page *page,
	      unsigned int order, dma_addr_t dma)
{
	dma_sal_free(&mep->sal, page, PAGE_SIZE << order, dma);
}
EXPORT_SYMBOL_GPL(mep_free);
