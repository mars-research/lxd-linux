enum glue_type {
	GLUE_TYPE_FOOBAR_DEVICE_CONTAINER,
	GLUE_TYPE_FOOBAR_DEVICE_OPS_REGISTER_FOOBAR_CONTAINER,
	GLUE_NR_TYPES,

};
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

int glue_cap_insert_foobar_device_ops_register_foobar_type(struct glue_cspace *cspace,
		struct foobar_device_ops_container *foobar_device_ops_register_foobar_container,
		struct cptr *c_out)
{
	return glue_cspace_insert(cspace,
		foobar_device_ops_register_foobar_container,
		glue_libcap_type_ops[ GLUE_TYPE_FOOBAR_DEVICE_OPS_REGISTER_FOOBAR_CONTAINER ].libcap_type,
		c_out);

}

int glue_cap_lookup_foobar_device_ops_register_foobar_type(struct glue_cspace *cspace,
		struct cptr c,
		struct foobar_device_ops_container **foobar_device_ops_register_foobar_container)
{
	return glue_cspace_lookup(cspace,
		c,
		glue_libcap_type_ops[ GLUE_TYPE_FOOBAR_DEVICE_OPS_REGISTER_FOOBAR_CONTAINER ].libcap_type,
		( void  ** )foobar_device_ops_register_foobar_container);

}

