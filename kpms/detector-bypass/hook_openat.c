#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>
#include <hook.h>
#include <log.h>
enum hook_type func_hook_type = NONE;


void inline init_hook_type(enum hook_type hook_type)
{
    func_hook_type = hook_type;
}

void hook_openat_init(enum hook_type hook_type)
{
    init_hook_type(hook_type);

}


void hook_openat(void* before_openat, void* after_openat)
{
    hook_err_t err = HOOK_NO_ERR;
    if (func_hook_type == FUNCTION_POINTER_CHAIN) {
        err = fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    }
    else if (func_hook_type == INLINE_CHAIN) {
        err = inline_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    } else {
        logke("unknown hook_type: %d\n", func_hook_type);
    }
    if (err) {
        logke("hook openat error: %d\n", err);
    }
    else {
        logkd("hook openat success\n");
    }
}

void unhook_openat(void* before_openat, void* after_openat)
{
    if (func_hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat, after_openat);
    }
    else if (func_hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    }
    else {
        logke("unhook_openat unknown hook_type: %d\n", func_hook_type);
    }
}
