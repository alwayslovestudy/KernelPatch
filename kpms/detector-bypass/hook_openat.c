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
#include <config.h>
enum hook_type hook_type = NONE;
enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;

char target_process[64] = "";
//内核函数指针
pid_t (*__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = 0;
char *(*__get_task_comm)(char *to, size_t len, struct task_struct *tsk) = 0;

void init_kernel_functions()
{
    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    __get_task_comm = (typeof(__get_task_comm))kallsyms_lookup_name("__get_task_comm");
}
void init_target_process(const char *process_name)
{
    if (process_name) {
        strncpy(target_process, process_name, strlen(process_name));
        target_process[strlen(process_name)] = '\0';
    } else {
        target_process[0] = '\0';
    }
}

void before_openat(hook_fargs4_t *args, void *udata)
{
    int dfd = (int)syscall_argn(args, 0);
    const char __user *filename = (const char __user *)syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);
    char buf[1024];
    compat_strncpy_from_user(buf, filename, sizeof(buf));
    struct task_struct *task = current;
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
        if (__get_task_comm) {
            char comm[16] = {
                0,
            };
            __get_task_comm(comm, sizeof(comm), task);
            if (strstr(comm, target_process)) {
                pr_info("hook_openat task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n",
                        task, pid, tgid, dfd, buf, flag, mode);
            }

        } else {
            pr_info("hook_chain_0 no get_task_comm\n");
        }
    }
}

void after_openat(hook_fargs4_t *args, void *udata)
{
    //pr_info("hook_openat after openat");
}

void hook_openat(enum hook_type hook_type, const char *process_name)
{
    init_kernel_functions();
    init_target_process(process_name);
    hook_err_t err = HOOK_NO_ERR;
    if (hook_type == FUNCTION_POINTER_CHAIN) {
        err = fp_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    } else if (hook_type == INLINE_CHAIN) {
        err = inline_hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    } else {
        pr_warn("unknown hook_type: %d\n", hook_type);
    }

    if (err) {
        pr_err("hook openat error: %d\n", err);
    } else {
        pr_info("hook openat success\n");
    }
}

void unhook_openat()
{
    if (hook_type == INLINE_CHAIN) {
        inline_unhook_syscalln(__NR_openat, before_openat, after_openat);
    } else if (hook_type == FUNCTION_POINTER_CHAIN) {
        fp_unhook_syscalln(__NR_openat, before_openat, after_openat);
    } else {
        pr_err("unhook_openat unknown hook_type: %d\n", hook_type);
    }
}
