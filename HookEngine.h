#include <linux/module.h>
#include <linux/kernel.h>

/*
 *handler: [in]uplevel function
 *old_func: [in]function to be hooked 
 *new_func：[in]my function 
 * */
unsigned int patch_kernel_func(unsigned long long handler, unsigned long long old_func, unsigned long long new_func);

