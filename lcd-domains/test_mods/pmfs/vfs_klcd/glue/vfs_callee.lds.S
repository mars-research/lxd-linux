/* NOTE: The Linux build system is gonna put a bunch of crap and warnings
 * at the top of the auto-generated vfs_callee.lds. Just ignore it really. */

#include <liblcd/trampoline_link.h>
 
SECTIONS
{
	LCD_TRAMPOLINE_LINKER_SECTION(super_block_alloc_inode_trampoline)
	LCD_TRAMPOLINE_LINKER_SECTION(super_block_destroy_inode_trampoline)
    	LCD_TRAMPOLINE_LINKER_SECTION(super_block_evict_inode_trampoline)
}
INSERT AFTER .text;
