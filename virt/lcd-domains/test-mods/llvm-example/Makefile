
# The main character of this story - the code we're isolating
obj-$(CONFIG_LCD_TEST_MOD_LLVM_EXAMPLE_LCD)  += \
				lcd-test-mod-llvm-example-lcd.o

lcd-test-mod-llvm-example-lcd-y              += lcd.o


ifdef CONFIG_LCD_COMPILE_FOR_SMACK

# Building for SMACK.

# Use whole program llvm, clang, etc.
export LLVM_COMPILER=clang
export CC=wllvm

# Compile and link main.o and environment.o to close off environment.
lcd-test-mod-llvm-example-lcd-y              += smack_main.o environment.o

# Tell clang not to complain
CFLAGS_REMOVE_lcd.o := -fno-delete-null-pointer-checks \
					       -mpreferred-stack-boundary=3 \
					       -maccumulate-outgoing-args \
					       -fconserve-stack \
					       -DCC_HAVE_ASM_GOTO

CFLAGS_REMOVE_smack_main.o := -fno-delete-null-pointer-checks \
					       -mpreferred-stack-boundary=3 \
					       -maccumulate-outgoing-args \
					       -fconserve-stack \
					       -DCC_HAVE_ASM_GOTO

CFLAGS_REMOVE_environment.o := -fno-delete-null-pointer-checks  \
					       -mpreferred-stack-boundary=3 \
					       -maccumulate-outgoing-args \
					       -fconserve-stack \
					       -DCC_HAVE_ASM_GOTO

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

