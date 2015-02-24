/*
 * common/ring-channel.c
 *
 * This file is part of the Flux deterministic time-travel infrastructure.
 * Ring channels provide a general producer-consumer interface for relaying
 * data from to the guest components. Specifically ring channels are used for
 * establishing a high-performance communication channels between Xen microkernel
 * and loggin, replay, and devd daemons.
 *
 * Authors: Anton Burtsev Scotty Bauer
 * Date:    October 2011 Feburary 2015
 *
 */

#ifndef __XEN_RING_CHANNEL_H__
#define __XEN_RING_CHANNEL_H__

#include <linux/string.h>


/*
 * This structure contains the metadata for a single trace buffer.  The head
 * field, indexes into an array of struct t_rec's.
 */
struct ttd_buf {
	unsigned long   cons;      /* Next item to be consumed by control tools. */
	unsigned long   prod;      /* Next item to be produced by Xen.           */

	/* Shape of the buffer */
	unsigned long      payload_buffer_mfn;
	unsigned long      payload_buffer_size;

	unsigned long      size_of_a_rec;        /* size of a single record */

	unsigned long      size_in_recs;         /* size of the buffer in recs */

	/* Stats for the buffer */

	unsigned long long avg_queue_size;      /* average size of the request queue in the buffer */
	unsigned long long msgs_sent;            /* total number of messages sent */
	unsigned long msgs_by_type[128];          /* count how many messages of individual type we record */
	unsigned long long tx_notifications;     /* total number of TX notifications */
	unsigned long long tx_hit_emergency_margin; /* total number of times the channel gets emergently full */
	unsigned long long rx_notifications;     /* total number of RX notifications */
	unsigned long long msgs_with_extra_reg_space; /* total number of messages which asked for extra space in registers */
	unsigned long msgs_with_extra_reg_space_by_type[128]; /* count how many times an individual event type asks for more space */
	unsigned long long msgs_with_extra_data_space; /* total number of messages which asked for extra space for data */
	unsigned long msgs_with_extra_data_space_by_type[128]; /* count how many times an individual event type asks for more space */

	/* 'ttd_nr_recs' records follow immediately after the meta-data header.    */
};


struct ttd_ring_channel {
	struct ttd_buf   *buf;                  /* pointer to the buffer metadata   */
	unsigned long     buf_mfn;
	unsigned long     buf_order;

	void             *priv_metadata;        /* pointer to the private buffer metadata  */
	unsigned long     priv_metadata_size;   /* size of the private buffer metadata  */
	unsigned long     header_order;   /* size of the private buffer metadata  */

	char             *recs;                 /* pointer to buffer data areas      */

	unsigned long     size_of_a_rec;        /* size of a single record */


	unsigned long     size_in_recs;         /* size of the buffer in recs */

	unsigned long     highwater;            /* buffer is quite full, time to notify other end */ 
	unsigned long     emergency_margin;     /* buffer is nearly full, time to freeze everything */

};

static inline void ttd_ring_channel_reinit_stats(struct ttd_buf *buf)
{
	buf->avg_queue_size = 0;
	buf->msgs_sent = 0;
	buf->tx_notifications = 0;
	buf->rx_notifications = 0;
	buf->tx_hit_emergency_margin = 0;
	buf->msgs_with_extra_reg_space = 0;
	buf->msgs_with_extra_data_space = 0;

	memset(buf->msgs_by_type, 0,
	       sizeof(buf->msgs_by_type));

	memset(buf->msgs_with_extra_reg_space_by_type, 0,
	       sizeof(buf->msgs_with_extra_reg_space_by_type));

	memset(buf->msgs_with_extra_data_space_by_type, 0,
	       sizeof(buf->msgs_with_extra_data_space_by_type));
}

static inline void ttd_ring_channel_init(struct ttd_ring_channel *ring_channel)
{
	memset(ring_channel, 0, sizeof(*ring_channel));
	return;
}

static inline void ttd_ring_channel_buf_init(struct ttd_buf *buf)
{
	memset(buf, 0, sizeof(*buf));
	return;
}

int ttd_ring_channel_alloc(struct ttd_ring_channel *ring_channel,
			   unsigned long size_in_pages,
			   unsigned long size_of_a_rec);

int ttd_ring_channel_alloc_with_metadata(struct ttd_ring_channel *ring_channel,
					 unsigned long size_in_pages,
					 unsigned long size_of_a_rec,
					 unsigned long priv_metadata_size);

void ttd_ring_channel_free(struct ttd_ring_channel *ring_channel);

static inline void
*ttd_ring_channel_get_priv_metadata(struct ttd_ring_channel *ring_channel)
{
	return ring_channel->priv_metadata;
}

static inline unsigned long
ttd_ring_channel_get_prod(struct ttd_ring_channel *ring_channel) {
	return ring_channel->buf->prod;
};

static inline unsigned long
ttd_ring_channel_inc_prod(struct ttd_ring_channel *ring_channel) {
	return (ring_channel->buf->prod++);
};

static inline void
ttd_ring_channel_set_prod(struct ttd_ring_channel *ring_channel, unsigned long prod) {
	ring_channel->buf->prod = prod;
	return;
};

static inline unsigned long
ttd_ring_channel_get_cons(struct ttd_ring_channel *ring_channel) {
	return ring_channel->buf->cons;
};

static inline unsigned long
ttd_ring_channel_inc_cons(struct ttd_ring_channel *ring_channel) {
	return (ring_channel->buf->cons++);
};


static inline void ttd_ring_channel_set_cons(struct ttd_ring_channel *ring_channel,
					     unsigned long cons) {
	ring_channel->buf->cons = cons;
	return;
};

static inline char *ttd_ring_channel_get_rec_slow(struct ttd_ring_channel *ring_channel,
						  unsigned long cons) {
	return (ring_channel->recs
		+ (cons % ring_channel->size_in_recs)
		* ring_channel->size_of_a_rec);
};


static inline unsigned long ttd_ring_channel_get_index_mod_slow(struct ttd_ring_channel *ring_channel, unsigned long index) {
	return (index % ring_channel->size_in_recs);
}


static inline unsigned long ttd_ring_channel_size_in_recs(struct ttd_ring_channel *ring_channel) {
	return ring_channel->size_in_recs;
}

static inline unsigned long ttd_ring_channel_size_of_a_rec(struct ttd_ring_channel *ring_channel) {
	return ring_channel->size_of_a_rec;
}

static inline unsigned long ttd_ring_channel_size(struct ttd_ring_channel *ring_channel) {
	return ring_channel->size_in_recs * ring_channel->size_of_a_rec;
}


static inline unsigned long ttd_ring_channel_highwater(struct ttd_ring_channel *ring_channel) {
	return ring_channel->highwater;
}

static inline unsigned long ttd_ring_channel_emergency_margin(struct ttd_ring_channel *ring_channel) {
	return ring_channel->emergency_margin;
}

#endif

