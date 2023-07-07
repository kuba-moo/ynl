#ifndef __DCALLOC_H
#define __DCALLOC_H

#include <linux/dma-mapping.h>
#include <net/dcalloc.h>

struct device;

/* struct dma_slow_huge - AKA @shu, large block which will get chopped up */
struct dma_slow_huge {
	void *addr;
	unsigned int size;
	dma_addr_t dma;

	struct list_head huge;
	struct list_head buddy_list;	/* struct dma_slow_buddy */
};

/* Single allocation piece */
struct dma_slow_buddy {
	unsigned int offset;
	unsigned int size;

	bool free;

	struct list_head list;
};

/* struct dma_slow_fall - AKA @fb, fallback when huge can't be allocated */
struct dma_slow_fall {
	void *addr;
	unsigned int size;
	dma_addr_t dma;

	struct list_head fb;
};

/* struct dma_slow_allocator - AKA @sal, per device allocator */
struct dma_slow_allocator {
	const struct dma_slow_allocator_ops *ops;
	struct device *dev;

	unsigned int ptr_shf;
	refcount_t user_cnt;

	struct list_head huge;		/* struct dma_slow_huge */
	struct list_head fallback;	/* struct dma_slow_fall */
};

struct dma_slow_allocator_ops {
	u8	ptr_shf;

	int (*alloc_huge)(struct dma_slow_allocator *sal,
			  struct dma_slow_huge *shu,
			  unsigned int size, gfp_t gfp);
	void (*free_huge)(struct dma_slow_allocator *sal,
			  struct dma_slow_huge *fb);
	int (*alloc_fall)(struct dma_slow_allocator *sal,
			  struct dma_slow_fall *fb,
			  unsigned int size, gfp_t gfp);
	void (*free_fall)(struct dma_slow_allocator *sal,
			  struct dma_slow_fall *fb);

	void (*release)(struct dma_slow_allocator *sal);
};

int dma_slow_huge_init(struct dma_slow_huge *shu, void *addr,
		       unsigned int size, dma_addr_t dma, gfp_t gfp);

void dma_sal_init(struct dma_slow_allocator *sal,
		  const struct dma_slow_allocator_ops *ops,
		  struct device *dev);

void *dma_sal_alloc(struct dma_slow_allocator *sal, unsigned int size,
		    dma_addr_t *dma, gfp_t gfp);
void dma_sal_free(struct dma_slow_allocator *sal, void *addr,
		  unsigned int size, dma_addr_t dma);

static inline void dma_slow_get(struct dma_slow_allocator *sal)
{
	refcount_inc(&sal->user_cnt);
}

static inline void dma_slow_put(struct dma_slow_allocator *sal)
{
	if (!refcount_dec_and_test(&sal->user_cnt))
		return;

	if (sal->ops->release)
		sal->ops->release(sal);
}

/* misc */
void mp_huge_split(struct page *page, unsigned int order);

#endif
