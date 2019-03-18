#include <liblcd/trampoline_link.h>

SECTIONS
{
	LCD_TRAMPOLINE_LINKER_SECTION(init_trampoline)
	LCD_TRAMPOLINE_LINKER_SECTION(uninit_trampoline)
}
INSERT AFTER .text;
