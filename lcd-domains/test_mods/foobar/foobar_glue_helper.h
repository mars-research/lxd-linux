#ifndef __FOOBAR_GLUE_HELPER_H__
#define __FOOBAR_GLUE_HELPER_H__

struct foobar_device_container {
	struct foobar_device foobar_device;
	struct cptr other_ref;
	struct cptr my_ref;
};
struct foobar_device_ops_register_foobar_container {
	struct foobar_device_ops foobar_device_ops_register_foobar;
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
int glue_cap_insert_foobar_device_type(struct glue_cspace *cspace,
		struct foobar_device_container *foobar_device_container,
		struct cptr *c_out);
int glue_cap_insert_foobar_device_ops_register_foobar_type(struct glue_cspace *cspace,
		struct foobar_device_ops_container *foobar_device_ops_register_foobar_container,
		struct cptr *c_out);
int glue_cap_lookup_foobar_device_type(struct glue_cspace *cspace,
		struct cptr c,
		struct foobar_device_container **foobar_device_container);
int glue_cap_lookup_foobar_device_ops_register_foobar_type(struct glue_cspace *cspace,
		struct cptr c,
		struct foobar_device_ops_container **foobar_device_ops_register_foobar_container);
