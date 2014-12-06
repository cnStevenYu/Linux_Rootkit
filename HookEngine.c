#include "HookEngine.h"

#define __CLEAR_WP__

#ifdef __CLEAR_WP__
#define X86_CR0_WP 0x00010000

static unsigned long __force_order;

static inline unsigned long readCr0(void) {

    unsigned long val;

    asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
    return val;
}

static inline void writeCr0(unsigned long val) {
    asm volatile("mov %0,%%cr0" : : "r" (val), "m" (__force_order));
}
#endif

/*address 64bits to 32bits*/
static unsigned int addr_q2l(unsigned long long quad) 
{
	return quad & 0x00000000ffffffff;
}

/*address 32bits to 64bits*/
static unsigned long long addr_l2q(unsigned int lon)
{
	return (unsigned long long)lon | 0xffffffff00000000;
}

/*
 *handler: [in]uplevel function
 *old_func: [in]function to be hooked 
 *new_func：[in]my function 
 * */
unsigned int patch_kernel_func(unsigned long long handler, unsigned long long old_func,
		unsigned long long new_func)
{
	unsigned char *p = (unsigned char *)handler;
	unsigned char buf[4] = "\x00\x00\x00\x00";
	unsigned int offset = 0;
	unsigned long long orig = 0;
	int i = 0;
#ifdef __CLEAR_WP__
	unsigned long cr0;
#endif

	printk(KERN_INFO "\n*** hook engine: start patch func at: 0x%016llx\n", old_func);

	while (1) {
		if (i > 512)
			return 0;

		if (p[0] == 0xe8) {
			printk(KERN_INFO "*** hook engine: found opcode 0x%02x\n", p[0]);
			
			printk("*** hook engine: call addr: 0x%016llx\n", 
				(unsigned long long)p);
			buf[0] = p[1];
			buf[1] = p[2];
			buf[2] = p[3];
			buf[3] = p[4];

			printk(KERN_INFO "*** hook engine: 0x%02x 0x%02x 0x%02x 0x%02x\n", 
				p[1], p[2], p[3], p[4]);

				/*the operand of call is not 64bits but 32 bits !!!!!*/
        		offset = *(unsigned int *)buf;
        		printk(KERN_INFO "*** hook engine: offset: 0x%08x\n", offset);
	
				/*current address is 32bits*/
        		printk(KERN_INFO "*** hook engine: current addr: 0x%08x\n", (unsigned int)p);

        		orig = addr_l2q(offset + (unsigned int)p + 5);
        		printk(KERN_INFO "*** hook engine: original func: 0x%016llx\n", orig);

			if (orig == old_func) {
				printk(KERN_INFO "*** hook engine: found old func at"
					" 0x%016llx\n", 
					old_func);

				printk(KERN_INFO "%d\n", i);
				break;
			}
		}
		p++;
		i++;
	}

	offset = addr_q2l(new_func)- (unsigned int)p - 5;

#ifdef __CLEAR_WP__
	cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	printk(KERN_INFO "*** hook engine: clear write protection\n");
	
	p[1] = (offset & 0x000000ff);
	p[2] = (offset & 0x0000ff00) >> 8;
	p[3] = (offset & 0x00ff0000) >> 16;
	p[4] = (offset & 0xff000000) >> 24;
	
	writeCr0(cr0);
#endif

	printk(KERN_INFO "*** hook engine: pachted new func offset.\n");

	return orig;
} 
