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
#include <hook_read.h>
#include <hook_openat.h>
#include <kernel_func.h>
#include <linux/vmalloc.h>
#include <utils.h>
#

//需要执行重定向的目标进程名
static char target_process[64];

typedef struct FILTER_RULE_T
{
    char ori_data[64];
    char replace_data[64];
    char filename[64];
    int fd;
} FILTER_RULE;

typedef struct FILTER_RULE_LIST_T
{
    FILTER_RULE rules[64];
    int count;
} FILTER_RULE_LIST;
FILTER_RULE_LIST filter_rules;

static void callback_before_read(hook_fargs4_t *args, void *udata)
{
    args->local.data0 = false;
    //检查当前进程是否为目标进程
    PKERNEL_FUNCTIONS kf = get_kernel_functions();
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
    const char __user *buf = (typeof(buf))syscall_argn(args, 1);
    args->local.data0 = true;
    args->local.data1 = (uint64_t)fd;
    args->local.data2 = (uint64_t)buf;

    return;
}

static void callback_after_read(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0 && args->ret > 0) {
        logkd("file_filter read fd: %llx, buf: %p, ret: %llu\n", args->local.data1, (void *)args->local.data2,
            args->ret);
            size_t read_size = (size_t)args->ret;
            for (int i = 0; i < filter_rules.count; i++) {
                if (filter_rules.rules[i].fd == (int)args->local.data1) {
                    long cplen = 0;
                    long orilen = strlen(filter_rules.rules[i].ori_data);
                    long replacelen = strlen(filter_rules.rules[i].replace_data);
                    char* buf = (char*)vmalloc(read_size + 1);
                    if (buf)
                    {
                        cplen = compat_strncpy_from_user(buf, (const char __user*)args->local.data2, read_size);
                        if (cplen > 0) {
                            buf[cplen] = '\0';
                            char* pos = strstr(buf, filter_rules.rules[i].ori_data);
                            if (pos) {
                                logkd("file_filter find ori_data:%s in read buffer, replace it with:%s\n", filter_rules.rules[i].ori_data, filter_rules.rules[i].replace_data);
                                //替换数据
                                if (str_replace_all(buf, filter_rules.rules[i].ori_data, filter_rules.rules[i].replace_data)) {
                                    //将修改后的数据写回用户空间
                                    compat_copy_to_user((void*)args->local.data2, buf, cplen);
                                    logkd("file_filter replace success\n");
                                }
                            }
                        }
                        vfree(buf);
                    }
                    break;
                }
            }
    }
}

static void callback_before_openat(hook_fargs4_t *args, void *udata)
{
    //检查当前进程是否为目标进程
    KERNEL_FUNCTIONS *kf = get_kernel_functions();
    if (kf) {
        char comm[16];
        memset(comm, 0, sizeof(comm));
        struct task_struct *task = current;
        kf->__get_task_comm(comm, sizeof(comm), task);
        if (!strstr(target_process, comm)) {
            return;
        }
    }
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    args->local.data0 = (uint64_t)filename; //保存文件路径指针
}

static void callback_after_openat(hook_fargs4_t *args, void *udata)
{
    if (args->ret > 0) {
        const char __user *filename = (const char __user *)args->local.data0;
        char buf[64];
        memset(buf, 0, sizeof(buf));
        long rc = compat_strncpy_from_user(buf, filename, sizeof(buf)); //获取打开的文件名
        if (rc <= 0) return;
        logkd("file_filter openat file: %s, ret fd: %llu\n", buf, args->ret);
        for (int i = 0; i < filter_rules.count; i++) {
            if (!strncmp(buf, filter_rules.rules[i].filename, sizeof(buf))) {
                logkd("file_filter find target file  %s open and fd: %d\n", buf, args->ret);
                filter_rules.rules[i].fd = (int)args->ret; //保存文件描述符
                break;
            }
        }

    } else {
        logkd("file_filter openat failed, ret: %llu\n", args->ret);
    }
}

void file_filter_set_process(const char *proc_name) //设置目标进程名称
{
    if (proc_name) {
        strncpy(target_process, proc_name, strlen(proc_name));
        target_process[strlen(proc_name)] = '\0';
    } else {
        target_process[0] = '\0';
    }
}
void file_filter_init(const char *proc_name)
{
    file_filter_set_process(proc_name);
    hook_read_init(FUNCTION_POINTER_CHAIN);
    hook_openat_init(FUNCTION_POINTER_CHAIN);
    logkd("file_filter init success for process: %s\n", target_process);
}

void file_filter_add_rule(const char *filename, const char *ori_data, const char *replace_data)
{
    if (filter_rules.count < sizeof(filter_rules.rules) / sizeof(FILTER_RULE)) {
        FILTER_RULE *fr = &filter_rules.rules[filter_rules.count];
        strncpy(fr->filename, filename, strlen(filename) + 1);
        strncpy(fr->ori_data, ori_data, strlen(ori_data) + 1);
        strncpy(fr->replace_data, replace_data, strlen(replace_data) + 1);
        fr->fd = -1;
        filter_rules.count++;
    }
}

void file_filter_start()
{
    hook_openat(callback_before_openat, callback_after_openat);
    hook_read(callback_before_read, callback_after_read);
}

void file_filter_stop()
{
    unhook_read(callback_before_read, callback_after_read);
    unhook_openat(callback_before_openat, callback_after_openat);
}
