#include <compiler.h>
#include <linux/vmalloc.h>
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
#include <hook_ioctl.h>
#include <hook_openat.h>
#include <kernel_func.h>
#include <utils.h>

//需要执行重定向的目标进程名
static char target_process[64];
typedef struct FILTER_RULE_T
{
    char ori_data[64];
    char replace_data[64];
    char drivername[64];
    int fd;
} FILTER_RULE;

typedef struct FILTER_RULE_LIST_T
{
    FILTER_RULE rules[64];
    int count;
} FILTER_RULE_LIST;

#define BINDER_WRITE_READ 3224396289

static FILTER_RULE_LIST filter_rules;

static void callback_before_openat(hook_fargs4_t *args, void *udata)
{
    //检查当前进程是否为目标进程
    args->local.data0 = false;
    char comm[16];
    memset(comm, 0, sizeof(comm));
    struct task_struct* task = current;
    get_krl_func()->__get_task_comm(comm, sizeof(comm), task);
    if (!strstr(target_process, comm)) {
        return;
    }
    const char __user *drivername = (typeof(drivername))syscall_argn(args, 1);
    args->local.data0 = true;
    args->local.data1 = (uint64_t)drivername; //保存文件路径指针
}

static void callback_after_openat(hook_fargs4_t *args, void *udata)
{
    if (args->ret > 0 && args->local.data0) {
        const char __user *filename = (const char __user *)args->local.data1;
        char buf[64];
        memset(buf, 0, sizeof(buf));
        long rc = compat_strncpy_from_user(buf, filename, sizeof(buf)); //获取打开的文件名
        if (rc <= 0) return;
        logkd("driver_filter openat filename: %s\n", buf);
        for (int i = 0; i < filter_rules.count; i++) {
            if (!strncmp(buf, filter_rules.rules[i].drivername, sizeof(buf))) {
                logkd("driver_filter find target driver:  %s open and fd: %d\n", buf, args->ret);
                filter_rules.rules[i].fd = (int)args->ret; //保存驱动的文件描述符
                break;
            }
        }
    }
}

static void callback_before_ioctl(hook_fargs4_t *args, void *udata)
{
    args->local.data0 = false;
    //检查当前进程是否为目标进程
    PKERNEL_FUNCTIONS kf = get_krl_func();
    if (kf) {
        char comm[16];
        memset(comm, 0, sizeof(comm));
        struct task_struct *task = current;
        kf->__get_task_comm(comm, sizeof(comm), task);
        if (!strstr(target_process, comm)) {
            return;
        }
    }

    const int fd = (typeof(fd))syscall_argn(args, 0);
    const unsigned int cmd = (typeof(cmd))syscall_argn(args, 1);
    const unsigned long cmd_args = (typeof(cmd))syscall_argn(args, 2);
    args->local.data0 = true;
    args->local.data1 = (uint64_t)fd;
    args->local.data2 = (uint64_t)cmd;
    args->local.data3 = (uint64_t)cmd_args;
    return;
}

static void callback_after_ioctl(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0) {
        const int fd = (int)args->local.data1;
        const unsigned int cmd = (unsigned int)args->local.data2;
        const unsigned long cmd_args = (unsigned long)args->local.data3;
        logkd("driver_filter ioctl fd: %d, cmd: %u, ret: %llu\n", fd, cmd, args->ret);
        for (int i = 0; i < filter_rules.count; i++) {
            if (filter_rules.rules[i].fd == fd && cmd == BINDER_WRITE_READ) {  //binder指令为BINDER_WRITE_READ
                logkd("driver_filter find target driver ioctl:  %s fd: %d, cmd: %u\n", filter_rules.rules[i].drivername, fd, cmd);
                break;
            }
        }
    }
}

void driver_filter_set_process(const char *proc_name) //设置目标进程名称
{
    if (proc_name) {
        strncpy(target_process, proc_name, strlen(proc_name));
        target_process[strlen(proc_name)] = '\0';
    } else {
        target_process[0] = '\0';
    }
}
void driver_filter_init(const char *proc_name)
{
    driver_filter_set_process(proc_name);
    hook_ioctl_init(FUNCTION_POINTER_CHAIN);
    hook_openat_init(FUNCTION_POINTER_CHAIN);
    logkd("driver_filter init success for process: %s\n", target_process);
}

void driver_filter_add_rule(const char *drivername, const char *ori_data, const char *replace_data)
{
    if (filter_rules.count < sizeof(filter_rules.rules) / sizeof(FILTER_RULE)) {
        FILTER_RULE *fr = &filter_rules.rules[filter_rules.count];
        strncpy(fr->drivername, drivername, strlen(drivername) + 1);
        strncpy(fr->ori_data, ori_data, strlen(ori_data) + 1);
        strncpy(fr->replace_data, replace_data, strlen(replace_data) + 1);
        fr->fd = -1;
        filter_rules.count++;
    }
}

void driver_filter_start()
{
    hook_openat(callback_before_openat, callback_after_openat);
    hook_ioctl(callback_before_ioctl, callback_after_ioctl);
}

void driver_filter_stop()
{
    unhook_ioctl(callback_before_ioctl, callback_after_ioctl);
    unhook_openat(callback_before_openat, callback_after_openat);
}