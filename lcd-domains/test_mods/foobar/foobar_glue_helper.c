#include <lcd_config/pre_hook.h>

#include <libcap.h>
#include <liblcd/liblcd.h>
#include <linux/slab.h>
#include "foobar_glue_helper.h"

#include <lcd_config/post_hook.h>

/* ------------------------------------------------------------ */

static struct cap_type_system *glue_libcap_type_system;

struct type_ops_id {
	struct cap_type_ops ops;
	cap_type_t libcap_type;
};

enum glue_type {
	GLUE_TYPE_FOOBAR_DEVICE_CONTAINER,
	GLUE_TYPE_FOOBAR_DEVICE_OPS_CONTAINER,
	GLUE_NR_TYPES,

};

static int dummy_func(struct cspace *cspace, struct cnode *cnode,
		void *object)
{
	return 0;
}

static struct type_ops_id glue_libcap_type_ops[GLUE_NR_TYPES] = {
	{
		{
			.name = "struct foobar_device",
			.delete = dummy_func,
			.revoke = dummy_func,
		}
	},
	{
		{
			.name = "struct foobar_device_ops",
			.delete = dummy_func,
			.revoke = dummy_func,
		}
	},
};

int glue_cap_init(void)
{
	int ret;
	int i;
	cap_type_t libcap_type;
	/*
	 * Alloc and init microkernel type system
	 */
	ret = cap_type_system_alloc(&glue_libcap_type_system);
	if (ret) {
		LIBLCD_ERR("alloc glue type system failed");
		goto fail1;
	}
	ret = cap_type_system_init(glue_libcap_type_system);
	if (ret) {
		LIBLCD_ERR("init glue type system failed");
		goto fail2;
	}
	/*
	 * Add types
	 */
	for (i = 0; i < GLUE_NR_TYPES; i++) {

		libcap_type = cap_register_private_type(
			glue_libcap_type_system,
			0,
			&glue_libcap_type_ops[i].ops);
		if (libcap_type == CAP_TYPE_ERR) {
			LIBLCD_ERR("failed to register glue cap type %s",
				glue_libcap_type_ops[i].ops.name);
			ret = -EIO;
			goto fail3;
		}
		glue_libcap_type_ops[i].libcap_type = libcap_type;
	}

	return 0;

fail3:
	cap_type_system_destroy(glue_libcap_type_system);
fail2:
	cap_type_system_free(glue_libcap_type_system);
	glue_libcap_type_system = NULL;
fail1:
	return ret;
}

int glue_cap_create(struct glue_cspace **cspace_out)
{
	return glue_cspace_alloc_init(glue_libcap_type_system, cspace_out);
}

void glue_cap_destroy(struct glue_cspace *cspace)
{
	glue_cspace_destroy_free(cspace);
}

void glue_cap_exit(void)
{
	/*
	 * Destroy and free type system if necessary
	 */
	if (glue_libcap_type_system) {
		cap_type_system_destroy(glue_libcap_type_system);
		cap_type_system_free(glue_libcap_type_system);
		glue_libcap_type_system = NULL;
	}
}

int glue_cap_insert_foobar_device_type(struct glue_cspace *cspace,
		struct foobar_device_container *foobar_device_container,
		struct cptr *c_out)
{
	return glue_cspace_insert(cspace,
		foobar_device_container,
		glue_libcap_type_ops[ GLUE_TYPE_FOOBAR_DEVICE_CONTAINER ].libcap_type,
		c_out);

}

int glue_cap_lookup_foobar_device_type(struct glue_cspace *cspace,
		struct cptr c,
		struct foobar_device_container **foobar_device_container)
{
	return glue_cspace_lookup(cspace,
		c,
		glue_libcap_type_ops[ GLUE_TYPE_FOOBAR_DEVICE_CONTAINER ].libcap_type,
		( void  ** )foobar_device_container);

}

int glue_cap_insert_foobar_device_ops_type(struct glue_cspace *cspace,
		struct foobar_device_ops_container *foobar_device_ops_container,
		struct cptr *c_out)
{
	return glue_cspace_insert(cspace,
		foobar_device_ops_container,
		glue_libcap_type_ops[ GLUE_TYPE_FOOBAR_DEVICE_OPS_CONTAINER ].libcap_type,
		c_out);

}

int glue_cap_lookup_foobar_device_ops_type(struct glue_cspace *cspace,
		struct cptr c,
		struct foobar_device_ops_container **foobar_device_ops_container)
{
	return glue_cspace_lookup(cspace,
		c,
		glue_libcap_type_ops[ GLUE_TYPE_FOOBAR_DEVICE_OPS_CONTAINER ].libcap_type,
		( void  ** )foobar_device_ops_container);
}

