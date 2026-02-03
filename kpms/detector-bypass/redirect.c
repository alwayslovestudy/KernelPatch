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
#include <kernel_func.h>

//需要执行重定向的目标进程名
static char target_process[64];

//需要重定向的文件
typedef struct REDIRECT_FILE_T
{
    char ori_filename[128];
    char new_filename[128];
} REDIRECT_FILE;

typedef struct REDIRECT_FILE_LIST_T
{
    REDIRECT_FILE files[32];
    int count;
} REDIRECT_FILE_LIST;

struct REDIRECT_FILE_LIST_T redirect_file_list;

static void callback_before_openat(hook_fargs4_t *args, void *udata)
{
    args->local.data0 = false;
    args->local.data2 = 0;
    //检查当前进程是否为目标进程
    KERNEL_FUNCTIONS *kf = get_krl_func();
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
    char buf[64];
    memset(buf, 0, sizeof(buf));
    long rc = compat_strncpy_from_user(buf, filename, sizeof(buf)); //获取打开的文件名
    if (rc <= 0) return;
    logkd("target process openat: %s\n", buf);
    for (int i = 0; i < redirect_file_list.count; i++) {
        if (!strncmp(buf, redirect_file_list.files[i].ori_filename, sizeof(buf))) {
            logkd("redirect file: %s -> %s\n", buf, redirect_file_list.files[i].new_filename);
            args->local.data0 = true; //设置重定向标志
            args->local.data1 = i; //保存重定向文件索引
            break;
        }
    }
    if (!args->local.data0) {
        return;
    }
    int cplen = 0;
    cplen = compat_copy_to_user((void *)filename, redirect_file_list.files[args->local.data1].new_filename,
                                strlen(redirect_file_list.files[args->local.data1].new_filename) + 1);
    if (cplen > 0) {
        args->local.data2 = (uint64_t)args->arg1; //保存原始的文件路径地址
        logkd("replace file path success in user space");
    } else { //缓冲区复制失败，尝试使用栈复制
        void *__user up = copy_to_user_stack(redirect_file_list.files[args->local.data1].new_filename,
                                             strlen(redirect_file_list.files[args->local.data1].new_filename) + 1);
        args->arg1 = (uint64_t)up;
        logkd("replace file path success in stack");
    }
    return;
}

static void callback_after_openat(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0 && args->local.data2) {
        const char *__user origin_path = redirect_file_list.files[args->local.data1].ori_filename;
        compat_copy_to_user((void *)args->local.data2, origin_path, strlen(origin_path) + 1);
        logkd("restore redirect file path: %s\n", origin_path);
    }
}
void redirect_set_process(const char *proc_name) //设置目标进程名称
{
    if (proc_name) {
        strncpy(target_process, proc_name, strlen(proc_name));
        target_process[strlen(proc_name)] = '\0';
    } else {
        target_process[0] = '\0';
    }
}
void redirect_init(const char *proc_name)
{
    redirect_set_process(proc_name);
    hook_openat_init(FUNCTION_POINTER_CHAIN);
    redirect_file_list.count = 0;
    logkd("redirect init success for process: %s\n", target_process);
}

void redirect_add_rule(const char *ori_filename, const char *new_filename)
{
    if (redirect_file_list.count < sizeof(redirect_file_list.files) / sizeof(REDIRECT_FILE)) {
        REDIRECT_FILE *rf = &redirect_file_list.files[redirect_file_list.count];
        strncpy(rf->ori_filename, ori_filename, strlen(ori_filename) + 1);
        strncpy(rf->new_filename, new_filename, strlen(new_filename) + 1);
        redirect_file_list.count++;
    }
}

void redirect_start()
{
    hook_openat(callback_before_openat, callback_after_openat);
}

void redirect_stop()
{
    unhook_openat(callback_before_openat, callback_after_openat);
}
