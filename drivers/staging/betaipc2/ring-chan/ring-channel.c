/*
 * Ring channels provide a general producer-consumer interface for relaying
 * data from to the LCD components. Specifically ring channels are used for
 * establishing a high-performance communication channels between LCD components
 *
 * Authors: Anton Burtsev, Scotty Bauer
 * Date:    October 2011,  Feburary 2015
 *
 */


#include <asm-generic/getorder.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include "ring-channel.h"


static inline unsigned long bsrl(unsigned long x)
{
	unsigned long ret;
	asm("bsr %1,%0" : "=r"(ret) : "r"(x));
	return ret;

}

static inline unsigned long lower_power_of_two(unsigned long x)
{

	return 0x80000000000000UL >> (__builtin_clzl(x)-1);
}


/* Stolen from  xen/mm.h */
static inline int get_order_from_pages(unsigned long nr_pages)
{
	int order;
	nr_pages--;
	for ( order = 0; nr_pages; order++ )
		nr_pages >>= 1;
	return order;
}

int ttd_ring_channel_alloc(struct ttd_ring_channel *ring_channel,
			   unsigned long size_in_pages,
			   unsigned long size_of_a_rec) {
	return ttd_ring_channel_alloc_with_metadata(ring_channel,
						    size_in_pages, size_of_a_rec, 0);
}

void ttd_ring_channel_free(struct ttd_ring_channel *ring_channel) {

	if (ring_channel->recs) {
		free_pages((unsigned long) ring_channel->recs,
			   ring_channel->buf_order);
		ring_channel->recs = NULL;
	}

	if (ring_channel->buf) {
		free_pages((unsigned long) ring_channel->buf,
			   ring_channel->header_order);
		ring_channel->buf = NULL;
	}
}


int ttd_ring_channel_alloc_with_metadata(struct ttd_ring_channel *ring_channel,
                                         unsigned long size_in_pages,
                                         unsigned long size_of_a_rec,
                                         unsigned long priv_metadata_size)
{
	int           ret;
	unsigned long order, header_order;
	unsigned long size_of_header_in_pages;
	pr_debug("Allocating ring channel\n");
	ttd_ring_channel_init(ring_channel);


	/* number of pages required for this */
	header_order = get_order(priv_metadata_size +
					    sizeof(struct ttd_buf));


	if ( (ring_channel->buf = (void *)  __get_free_pages(GFP_KERNEL, header_order)) == NULL ) {
		pr_err("Xen deterministic time-travel buffers: memory allocation failed\n");
		return -EINVAL;
	}


	size_of_header_in_pages = 1 << header_order;
	pr_debug("Allocating ring channel: header area size:%lu, in pages:%lu\n",
		 priv_metadata_size + sizeof(struct ttd_buf), size_of_header_in_pages);

	order = get_order_from_pages(size_in_pages);
	if ( (ring_channel->recs = (char *) __get_free_pages(GFP_KERNEL, order)) == NULL ) {
		pr_err("Xen deterministic time-travel buffers: memory allocationcd failed, "
		       "size in pages:%lu, order:%lu\n", size_in_pages, order);
		ret = -EINVAL; goto cleanup;
	}


	ring_channel->priv_metadata = (char *) (ring_channel->buf + 1);
	ring_channel->buf->cons = ring_channel->buf->prod = 0;

	ttd_ring_channel_reinit_stats(ring_channel->buf);

	ring_channel->size_of_a_rec = size_of_a_rec;
	pr_debug("Size of a rec is %lu\n", size_of_a_rec);


	/*ring_channel->size_in_recs  = (lower_power_of_two(size_in_pages * PAGE_SIZE))
	  / ring_channel->size_of_a_rec;*/

	ring_channel->size_in_recs = (size_in_pages * PAGE_SIZE) /
		ring_channel->size_of_a_rec;

	pr_debug("size in recs is %lu lower_power_of_two returned %lu and in hex %lxwith input %lu and hex %lx\n",
		 ring_channel->size_in_recs,
		 lower_power_of_two(size_in_pages * PAGE_SIZE),
		 lower_power_of_two(size_in_pages * PAGE_SIZE),
		 (size_in_pages * PAGE_SIZE), (size_in_pages * PAGE_SIZE));
	if (ring_channel->size_in_recs == 0) {
		pr_err(" Size_in_recs was incorrectly 0\n");
		ret = -EINVAL; goto cleanup;
	}

	/* Init shared buffer structures */

	ring_channel->buf->payload_buffer_mfn =
		(unsigned long) ring_channel->recs; /*NOTE*/


	ring_channel->buf->payload_buffer_size = size_in_pages * PAGE_SIZE;
	ring_channel->buf->size_of_a_rec = ring_channel->size_of_a_rec;

	ring_channel->buf->size_in_recs = ring_channel->size_in_recs;

	//ring_channel->highwater = ring_channel->size_in_recs >> 2; /* 25% high water */
	ring_channel->highwater = ring_channel->size_in_recs >> 1; /* 50% high water */
	ring_channel->emergency_margin = ring_channel->size_in_recs >> 4; /* 5% we are very close */

	pr_debug("New ring channel: payload area {requested:%lu, allocated:%lu, wasted on allocation:%lu (order:%lu), \n"
		 "metadata area {size:%lu, buffer size: %lu, full header: %lu, "
		 "allocated:%lu, wasted on allocation:%lu (order:%lu)} \n"
		 "rec: {requested size:%lu, size ^2:%lu, rownded down size in recs:%lu, "
		 "possible size in recs:%lu, wasted:%lu} "
		 "highwater: %lu, emergency margin: %lu\n",
		 size_in_pages * PAGE_SIZE,
		 ((unsigned long)1 << order) * PAGE_SIZE,
		 ((1 << order) * PAGE_SIZE) - size_in_pages * PAGE_SIZE, order,
		 priv_metadata_size, (unsigned long) sizeof(struct ttd_buf),
		 priv_metadata_size + sizeof(struct ttd_buf),
		 ((unsigned long)1 << header_order) * PAGE_SIZE,
		 ((1 << header_order)* PAGE_SIZE) - priv_metadata_size - sizeof(struct ttd_buf),
		 header_order, size_of_a_rec,
		 ttd_ring_channel_size_of_a_rec(ring_channel),
		 ttd_ring_channel_size_in_recs(ring_channel),
		 (size_in_pages * PAGE_SIZE)/ring_channel->size_of_a_rec,
		 (size_in_pages * PAGE_SIZE)/ring_channel->size_of_a_rec - ttd_ring_channel_size_in_recs(ring_channel),
		 ttd_ring_channel_highwater(ring_channel),
		 ttd_ring_channel_emergency_margin(ring_channel));

	ring_channel->header_order = header_order;
	ring_channel->buf_order = order;

	return 0;

 cleanup:

	ttd_ring_channel_free(ring_channel);
	return ret;

}

