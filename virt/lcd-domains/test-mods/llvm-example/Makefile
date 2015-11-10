
# The main character of this story - the code we're isolating
obj-$(CONFIG_LCD_TEST_MOD_LLVM_EXAMPLE_LCD)  += \
				lcd-test-mod-llvm-example-lcd.o

lcd-test-mod-llvm-example-lcd-y              += lcd.o


ifdef CONFIG_LCD_COMPILE_FOR_SMACK

# Building for SMACK.

# Use whole program llvm, dragonegg, etc.
export LLVM_COMPILER=dragonegg
export LLVM_DRAGONEGG_PLUGIN=/usr/lib/gcc/x86_64-linux-gnu/4.6/plugin/dragonegg.so

export CC=wllvm

# Compile and link main.o and environment.o to close off environment.
lcd-test-mod-llvm-example-lcd-y              += main.o environment.o

else

lcd-test-mod-llvm-example-lcd-y              += $(LIBLCD)

endif

# --------------------------------------------------

# Only compile the boot module if we are building for the real environment
ifndef CONFIG_LCD_COMPILE_FOR_SMACK

obj-$(CONFIG_LCD_TEST_MOD_LLVM_EXAMPLE_BOOT) += \
				lcd-test-mod-llvm-example-boot.o

lcd-test-mod-llvm-example-boot-y             += boot.o

endif

