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
#include <hook_openat.h>

KPM_NAME("kpm-detector-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("neo");
KPM_DESCRIPTION("KernelPatch Module Detector Bypass");

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;
//内核函数指针
pid_t(*__task_pid_nr_ns)(struct task_struct* task, enum pid_type type, struct pid_namespace* ns) = 0;
char* (*__get_task_comm)(char* to, size_t len, struct task_struct* tsk) = 0;

void init_kernel_functions()
{
    __task_pid_nr_ns = (typeof(__task_pid_nr_ns))kallsyms_lookup_name("__task_pid_nr_ns");
    __get_task_comm = (typeof(__get_task_comm))kallsyms_lookup_name("__get_task_comm");
}

void before_openat(hook_fargs4_t* args, void* udata)
{
    int dfd = (int)syscall_argn(args, 0);
    const char __user* filename = (const char __user*)syscall_argn(args, 1);
    int flag = (int)syscall_argn(args, 2);
    umode_t mode = (int)syscall_argn(args, 3);
    char buf[1024];
    compat_strncpy_from_user(buf, filename, sizeof(buf));
    struct task_struct* task = current;
    pid_t pid = -1, tgid = -1;
    if (__task_pid_nr_ns) {
        pid = __task_pid_nr_ns(task, PIDTYPE_PID, 0);
        tgid = __task_pid_nr_ns(task, PIDTYPE_TGID, 0);
        if (__get_task_comm) {
            char comm[16] = { 0, };
            __get_task_comm(comm, sizeof(comm), task);
            if (strstr(comm, "sankuai.meituan")) {
                logki("hook_openat task: %llx, pid: %d, tgid: %d, openat dfd: %d, filename: %s, flag: %x, mode: %d\n",
                    task, pid, tgid, dfd, buf, flag, mode);
            }

        }
        else {
            logke("hook_openat cant find get_task_comm\n");
        }
    }
}

void after_openat(hook_fargs4_t* args, void* udata)
{
    //pr_info("hook_openat after openat");
}




static long detector_bypass_init(const char *args, const char *event, void *__user reserved)
{
    logkd("detector_bypass init ..., args: %s\n", args);
    hook_openat_init(FUNCTION_POINTER_CHAIN);
    init_kernel_functions();
    hook_openat(before_openat, after_openat);
    return 0;
}

static long detector_bypass_control0(const char *args, char *__user out_msg, int outlen)
{
    logkd("detector_bypass control, args: %s\n", args);
    return 0;
}
static long detector_bypass_exit(void *__user reserved)
{
    logkd("kpm-detector_bypass exit ...\n");
    unhook_openat(before_openat, after_openat);
    return 0;
}


KPM_INIT(detector_bypass_init);
KPM_CTL0(detector_bypass_control0);
KPM_EXIT(detector_bypass_exit);