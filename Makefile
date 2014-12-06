ifneq ($(KERNELRELEASE),)
	obj-m := rootkit.o
	rootkit-y := HookEngine.o HideFile.o

else
	KDIR ?=/lib/modules/`uname -r`/build
default:
	$(MAKE) -C $(KDIR) M=$$PWD
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
endif
