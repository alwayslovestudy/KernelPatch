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
#include <hook_read.h>
#include <hook_openat.h>
#include <kernel_func.h>
#include <utils.h>

//需要进行binder过滤的目标进程名
static char target_process[64];

typedef struct FILTER_RULE_T
{
    char ori_data[64];
    size_t ori_len;
    char replace_data[64];
    size_t replace_len;

} FILTER_RULE;

typedef struct FILTER_RULE_LIST_T
{
    FILTER_RULE rules[64];
    int count;
} FILTER_RULE_LIST;

static FILTER_RULE_LIST filter_rules;


static void before_binder_alloc_copy_user_to_buffer(hook_fargs5_t* args, void* udata)
{
    PKERNEL_FUNCTIONS kf = get_krl_func();
    // char cur_comm[16 + 1];
    // if (kf) {
    //     memset(cur_comm, 0, sizeof(cur_comm));
    //     struct task_struct* task = current;
    //     kf->__get_task_comm(cur_comm, sizeof(cur_comm), task);
    //     // if (!strstr("system_server", cur_comm)) {  //过滤指定的进程
    //     //     //logkd("not target process,current proc%s", cur_comm);
    //     //     return;
    //     // }
    //     //logkd("current proc:%s", cur_comm);
    // }

    struct binder_alloc* binder_alloc_ptr = (struct binder_alloc*)args->arg0;
    struct task_struct* alloc_task = kf->pid_task(kf->find_vpid(binder_alloc_ptr->pid), PIDTYPE_PID);
    if (alloc_task) {
        char comm[16 + 1];
        memset(comm, 0, sizeof(comm));
        kf->__get_task_comm(comm, sizeof(comm), alloc_task);
        if (!strstr(target_process, comm)) {  //过滤指定的进程
            // logkd("not target process,current proc:%s", comm);
            return;
        }

        size_t buf_size = (size_t)args->arg4;
        const void __user* user_buf = (const void __user*)args->arg3;
        uint8_t* data_buf = get_krl_func()->vmalloc(buf_size);
        if (data_buf) {
            memset(data_buf, 0, buf_size);
            long rc = kf->copy_from_user(data_buf, user_buf, buf_size);
            if (rc == 0) {
                for (int i = 0;i < filter_rules.count;i++) {
                    uint8_t pad = 0x00;
                    if (bin_replace_all(data_buf, buf_size, (const uint8_t*)filter_rules.rules[i].ori_data, filter_rules.rules[i].ori_len,
                        (const uint8_t*)filter_rules.rules[i].replace_data, filter_rules.rules[i].replace_len, pad)) {
                        logkd("kernel buffer data replaced");
                        int cplen = compat_copy_to_user((void*)user_buf, data_buf, buf_size);
                        if (cplen == buf_size)
                            logkd("kernel data cp_to_user success");
                        else
                            logke("kernel data cp_to_user failed cplen:0x%x", cplen);
                    }



                }
            }
            get_krl_func()->vfree(data_buf);
        }





    }
}

static void after_binder_alloc_copy_user_to_buffer(hook_fargs5_t* args, void* udata)
{

}

static void hook_binder_alloc_copy_user_to_buffer()
{
    hook_err_t err = hook_wrap5((void*)get_krl_func()->binder_alloc_copy_user_to_buffer,
        before_binder_alloc_copy_user_to_buffer, after_binder_alloc_copy_user_to_buffer, 0);
    if (err == 0)        
        logkd("hook binder_alloc_copy_user_to_buffer success\n");
    else    
        logkd("hook binder_alloc_copy_user_to_buffer failed err: %d\n", err);

}

static void unhook_binder_alloc_copy_user_to_buffer()
{
    unhook(get_krl_func()->binder_alloc_copy_user_to_buffer);
}



void binder_filter_set_process(const char* proc_name) //设置目标进程名称
{
    if (proc_name) {
        strncpy(target_process, proc_name, strlen(proc_name));
        target_process[strlen(proc_name)] = '\0';
    }
    else {
        target_process[0] = '\0';
    }
}


void binder_filter_add_rule(const char* ori_data,size_t ori_len, const char* replace_data,size_t replace_len)
{
    if (filter_rules.count < sizeof(filter_rules.rules) / sizeof(FILTER_RULE)) {
        FILTER_RULE* fr = &filter_rules.rules[filter_rules.count];
        memcpy(fr->ori_data, ori_data, ori_len);
        fr->ori_len = ori_len;
        memcpy(fr->replace_data, replace_data, replace_len);
        fr->replace_len = replace_len;
        filter_rules.count++;
    }
}

void binder_filter_init(const char* proc_name)
{
    binder_filter_set_process(proc_name);

}

void binder_filter_start()
{
    hook_binder_alloc_copy_user_to_buffer();
}

void binder_filter_stop()
{
    unhook_binder_alloc_copy_user_to_buffer();
}

