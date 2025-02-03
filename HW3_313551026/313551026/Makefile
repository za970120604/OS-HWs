# Kernel module source file and name
obj-m := kfetch_mod_313551026.o
MODULE_NAME := kfetch_mod_313551026

# Default target: Compile the module
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# Clean up build artifacts
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

# Load the kernel module
load:
	@sudo insmod $(MODULE_NAME).ko || echo "Failed to load module $(MODULE_NAME).ko"

# Unload the kernel module
unload:
	@sudo rmmod $(MODULE_NAME) || echo "Failed to unload module $(MODULE_NAME)"

# Ensure phony targets
.PHONY: all clean load unload
