#ifndef __FOOBAR_GLUE_HELPER_H__
#define __FOOBAR_GLUE_HELPER_H__

#include <linux/foobar_device.h>
#include <libcap.h>
#include <libfipc.h>
#include <thc_ipc.h>
#include <liblcd/glue_cspace.h>
#include <liblcd/liblcd.h>
#include <liblcd/sync_ipc_poll.h>
#include <linux/kthread.h>

enum dispatch_t {
	REGISTER_FOOBAR,
	UNREGISTER_FOOBAR,
	ALLOC_FOOBARDEV,
	FREE_FOOBARDEV,
	INIT,
	UNINIT,
	TRIGGER_EXIT,
};

#define fipc_test_pause()    asm volatile ( "pause\n": : :"memory" );

#define ASYNC_RPC_BUFFER_ORDER 12

struct foobar_device_container {
	struct foobar_device foobar_device;
	struct cptr other_ref;
	struct cptr my_ref;
};
struct foobar_device_ops_container {
	struct foobar_device_ops foobar_device_ops;
	struct cptr other_ref;
	struct cptr my_ref;
};
struct trampoline_hidden_args {
	void *struct_container;
	struct glue_cspace *cspace;
	struct lcd_trampoline_handle *t_handle;
	struct thc_channel *async_chnl;
	struct cptr sync_ep;
};

int glue_cap_init(void);

int glue_cap_create(struct glue_cspace **cspace);

void glue_cap_destroy(struct glue_cspace *cspace);

void glue_cap_exit(void);

void glue_cap_remove(
	struct glue_cspace *cspace, 
	cptr_t c);

int glue_cap_insert_foobar_device_type(struct glue_cspace *cspace,
		struct foobar_device_container *foobar_device_container,
		struct cptr *c_out);
int glue_cap_insert_foobar_device_ops_type(struct glue_cspace *cspace,
		struct foobar_device_ops_container *foobar_device_ops_container,
		struct cptr *c_out);
int glue_cap_lookup_foobar_device_type(struct glue_cspace *cspace,
		struct cptr c,
		struct foobar_device_container **foobar_device_container);
int glue_cap_lookup_foobar_device_ops_type(struct glue_cspace *cspace,
		struct cptr c,
		struct foobar_device_ops_container **foobar_device_ops_container);

static inline
int
async_msg_get_fn_type(struct fipc_message *msg)
{
	return fipc_get_flags(msg) >> THC_RESERVED_MSG_FLAG_BITS;
}

static inline
void
async_msg_set_fn_type(struct fipc_message *msg, int type)
{
	uint32_t flags = fipc_get_flags(msg);
	/* ensure type is in range */
	type &= (1 << (32 - THC_RESERVED_MSG_FLAG_BITS)) - 1;
	/* erase old type */
	flags &= ((1 << THC_RESERVED_MSG_FLAG_BITS) - 1);
	/* install new type */
	flags |= (type << THC_RESERVED_MSG_FLAG_BITS);
	fipc_set_flags(msg, flags);
}

static inline
int
async_msg_blocking_send_start(struct thc_channel *chnl, 
			struct fipc_message **out)
{
	int ret;
	for (;;) {
		/* Poll until we get a free slot or error */
		ret = fipc_send_msg_start(thc_channel_to_fipc(chnl), out);
		if (!ret || ret != -EWOULDBLOCK)
			return ret;
		cpu_relax();
		if (kthread_should_stop())
			return -EIO;
	}
}

#endif
