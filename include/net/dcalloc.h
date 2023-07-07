#ifndef __NET_DCALLOC_H
#define __NET_DCALLOC_H

#include <linux/types.h>

struct device;

struct dma_cocoa;

struct dma_cocoa *dma_cocoa_create(struct device *dev, gfp_t gfp);
void dma_cocoa_destroy(struct dma_cocoa *cocoa);

void *dma_cocoa_alloc(struct dma_cocoa *cocoa, unsigned long size,
		      dma_addr_t *dma, gfp_t gfp);
void dma_cocoa_free(struct dma_cocoa *cocoa, unsigned long size, void *addr,
		    dma_addr_t dma);

#endif
