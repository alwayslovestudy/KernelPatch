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
#include <binder_def.h>

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

static FILTER_RULE_LIST filter_rules;

static void callback_before_openat(hook_fargs4_t *args, void *udata)
{
    //检查当前进程是否为目标进程
    args->local.data0 = false;
    char comm[16];
    memset(comm, 0, sizeof(comm));
    struct task_struct *task = current;
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

    const uint64_t fd = (typeof(fd))syscall_argn(args, 0);
    const uint64_t cmd = (typeof(cmd))syscall_argn(args, 1);
    const uint64_t cmd_args = (typeof(cmd_args))syscall_argn(args, 2);
    args->local.data0 = true;
    args->local.data1 = fd;
    args->local.data2 = cmd;
    args->local.data3 = cmd_args;

    return;
}

static void callback_after_ioctl(hook_fargs4_t *args, void *udata)
{
    if (args->local.data0) {
        const int fd = (int)args->local.data1;
        const unsigned int cmd = (unsigned int)args->local.data2;
        const unsigned long cmd_args = (unsigned long)args->local.data3;
        //logkd("driver_filter ioctl fd: %d, cmd: %u, ret: %llu\n", fd, cmd, args->ret);
        for (int i = 0; i < filter_rules.count; i++) {
            if (filter_rules.rules[i].fd == fd && cmd == BINDER_WRITE_READ) { //binder指令为BINDER_WRITE_READ

                binder_write_read *__user bwr = (binder_write_read *)cmd_args;
                logkd("driver_filter find target driver ioctl:  %s fd: %d, cmd: BINDER_WRITE_READ args:0x%llx\n",
                      filter_rules.rules[i].drivername, fd, bwr);
                if (bwr == NULL) {
                    logke("driver_filter ioctl bwr is NULL\n");
                    return;
                }
                binder_write_read k_bwr;
                memset(&k_bwr, 0, sizeof(binder_write_read));
                long rc = get_krl_func()->copy_from_user(&k_bwr, bwr, sizeof(binder_write_read));
                if (rc != 0) {
                    logke("driver_filter ioctl copy bwr from user failed, rc: %ld\n", rc);
                    return;
                }
                logkd("driver_filter ioctl  write_size: 0x%llx, read_size: 0x%llx\n", k_bwr.write_size,
                      k_bwr.read_size);
                logkd("driver_filter ioctl  write_consumed: 0x%llx, read_consumed: 0x%llx\n", k_bwr.write_consumed,
                      k_bwr.read_consumed);
                logkd("driver_filter ioctl  write_buffer: 0x%llx, read_buffer: 0x%llx\n", k_bwr.write_buffer,
                      k_bwr.read_buffer);

                if (k_bwr.write_size > 0) {
                    char *write_buf = get_krl_func()->vmalloc(k_bwr.write_size);
                    if (write_buf) {
                        memset(write_buf, 0, k_bwr.write_size);
                        rc = get_krl_func()->copy_from_user(write_buf, (const char __user *)k_bwr.write_buffer,
                                                            k_bwr.write_size);
                        if (rc == 0) {
                            int cmd = *((int *)(write_buf));
                            if (cmd != BC_TRANSACTION) {
                                logkd("driver_filter ioctl write buffer cmd: 0x%x is not BC_TRANSACTION\n", cmd);
                                print_hexdump(write_buf, k_bwr.write_size);

                            } else {
                                binder_transaction_data *bt_data = (binder_transaction_data *)(write_buf + 4);
                                uint32_t handle = bt_data->target.handle;
                                binder_uintptr_t cookie = bt_data->cookie;
                                uint32_t code = bt_data->code;
                                uint32_t flags = bt_data->flags;
                                pid_t sender_pid = bt_data->sender_pid;
                                uid_t sender_uid = bt_data->sender_euid;
                                logkd("driver_filter ioctl write buffer handle:0x%x cookie:0x%llx code:0x%x flags:0x%x "
                                      "sender_pid:0x%x sender_uid:0x%x\n",
                                      handle, cookie, code, flags, sender_pid, sender_uid);
                                binder_uintptr_t buffer = bt_data->data.ptr.buffer;
                                binder_size_t data_size = bt_data->data_size;
                                binder_size_t offsize = bt_data->offsets_size;
                                binder_uintptr_t offsets = bt_data->data.ptr.offsets;
                                logkd(
                                    "driver_filter ioctl write buffer  buffer:0x%llx data_size:0x%llx offsize:0x%llx offsets:0x%llx\n",
                                    buffer, data_size, offsize, offsets);
                                char *data_buf = get_krl_func()->vmalloc(data_size);
                                if (data_buf) {
                                    memset(data_buf, 0, data_size);
                                    rc = get_krl_func()->copy_from_user(data_buf, (const void *)buffer, data_size);
                                    if (rc == 0) {
                                        logkd("driver_filter ioctl write data.ptr.buffer:\n");
                                        //print hex
                                        //print_hexdump(data_buf, data_size);
                                    }
                                    get_krl_func()->vfree(data_buf);
                                }
                            }
                            get_krl_func()->vfree(write_buf);
                        }
                    }
                }

                if (k_bwr.read_consumed > 0) {
                    char *read_buf = get_krl_func()->vmalloc(k_bwr.read_consumed);
                    if (read_buf) {
                        memset(read_buf, 0, k_bwr.read_consumed);
                        rc = get_krl_func()->copy_from_user(read_buf, (const char __user *)k_bwr.read_buffer,
                                                            k_bwr.read_consumed);
                        if (rc == 0) {
                            int buf_count = 0;
                            int cmd = 0;
                            while (buf_count < k_bwr.read_consumed) {
                                cmd = *((int *)(read_buf + buf_count));
                                if (cmd == BR_REPLY)
                                    break;
                                else
                                    buf_count += 4;
                            }
                            if (buf_count < k_bwr.read_consumed && cmd == BR_REPLY) {
                                binder_transaction_data *bt_data =
                                    (binder_transaction_data *)(read_buf + buf_count + 4);
                                uint32_t handle = bt_data->target.handle;
                                binder_uintptr_t cookie = bt_data->cookie;
                                uint32_t code = bt_data->code;
                                uint32_t flags = bt_data->flags;
                                pid_t sender_pid = bt_data->sender_pid;
                                uid_t sender_uid = bt_data->sender_euid;
                                logkd("driver_filter ioctl read buffer handle:0x%x cookie:0x%llx code:0x%x flags:0x%x "
                                      "sender_pid:0x%x sender_uid:0x%x\n",
                                      handle, cookie, code, flags, sender_pid, sender_uid);
                                binder_uintptr_t buffer = bt_data->data.ptr.buffer;
                                binder_size_t data_size = bt_data->data_size;
                                binder_size_t offsize = bt_data->offsets_size;
                                binder_uintptr_t offsets = bt_data->data.ptr.offsets;
                                logkd(
                                    "driver_filter ioctl read buffer  buffer:0x%llx data_size:0x%llx offsize:0x%llx offsets:0x%llx\n",
                                    buffer, data_size, offsize, offsets);
                                uint8_t *data_buf = get_krl_func()->vmalloc(data_size);
                                if (data_buf) {
                                    memset(data_buf, 0, data_size);
                                    rc = get_krl_func()->copy_from_user(data_buf, (const void *)buffer, data_size);
                                    if (rc == 0) {
                                        logkd("driver_filter ioctl read data.ptr.buffer:\n");
                                        //print hex
                                        //print_hexdump(data_buf, data_size);
                                        uint8_t ori_ustr[] = { 0x74, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x6A, 0x00, 0x6F,
                                                               0x00, 0x68, 0x00, 0x6E, 0x00, 0x77, 0x00, 0x75, 0x00 };
                                        uint8_t rep_ustr[] = { 0x75, 0x00, 0x70, 0x00, 0x71, 0x00, 0x6b, 0x00, 0x6F,
                                                               0x00, 0x68, 0x00, 0x6E, 0x00, 0x77, 0x00, 0x75, 0x00 };
                                        uint8_t pad = 0x00;
                                        if (bin_replace_all(data_buf, data_size, ori_ustr, sizeof(ori_ustr), rep_ustr,
                                                            sizeof(rep_ustr), pad)) {
                                            logkd("read buffer data replace success");
                                            int cplen = compat_copy_to_user((void *)buffer, data_buf, data_size);
                                            if (cplen == data_size)
                                                logkd("cp_to_user success");
                                            else
                                                logke("cp_to_user failed cplen:0x%x", cplen);
                                        }
                                    }
                                    get_krl_func()->vfree(data_buf);
                                }

                                // logkd("driver_filter ioctl read buffer:\n");
                                // print_hexdump(read_buf, k_bwr.read_consumed);
                            } else {
                                logkd("unknown read buffer cmd:0x%x", cmd);
                                print_hexdump(read_buf, k_bwr.read_consumed);
                            }
                        } else
                            logke("copy_from_user error read_buffer:0x%llx ,read_consumed:0x%llx", k_bwr.read_buffer,
                                  k_bwr.read_consumed);
                        get_krl_func()->vfree(read_buf);
                    }
                }

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