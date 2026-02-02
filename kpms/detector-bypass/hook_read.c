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
static enum hook_type func_hook_type = FUNCTION_POINTER_CHAIN;

static void inline init_hook_type(enum hook_type hook_type)
{
    func_hook_type = hook_type;
}

void hook_read_init(enum hook_type hook_type)
{
    init_hook_type(hook_type);
}

void hook_read(void *before_read, void *after_read)
{
    hook_err_t err = HOOK_NO_ERR;
    if (func_hook_type == FUNCTION_POINTER_CHAIN) {
        err = fp_hook_syscalln(__NR_read, 3, before_read, after_read, 0);
    } else if (func_hook_type == INLINE_CHAIN) {
        err = inline_hook_syscalln(__NR_read, 3, before_read, after_read, 0);
    } else {
        logke("unknown hook_type: %d\n", func_hook_type);
    }
    if (err) {
        logke("hook read error: %d\n", err);
    } else {
        logkd("hook read success\n");
    }
}

void unhook_read(void *before_read, void *after_read)
{
    if (func_hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_read, before_read, after_read);
    } else if (func_hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_read, before_read, after_read);
    } else {
        logke("unhook_read unknown hook_type: %d\n", func_hook_type);
    }
}
