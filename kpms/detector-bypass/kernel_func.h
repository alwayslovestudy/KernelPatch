#ifndef _KERNEL_FUNC_H_
#define _KERNEL_FUNC_H_
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

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};
struct pid_namespace;
//内核函数指针定义
typedef pid_t (*__TASK_PID_NR_NS)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns);
typedef char *(*__GET_TASK_COMM)(char *to, size_t len, struct task_struct *tsk);
typedef void *(*VMALLOC)(unsigned long size);
typedef void (*VFREE)(const void *addr);
typedef unsigned long (*COPY_FROM_USER)(void *to, const void __user *from, unsigned long n);


typedef void (*PRINT_HEX_DUMP)(const char* level,
    const char* prefix_str,
    int prefix_type,
    int rowsize,
    int groupsize,
    const void* buf,
    size_t len,
    bool ascii);

typedef struct KERNEL_FUNCTIONS_T
{
    __TASK_PID_NR_NS __task_pid_nr_ns;
    __GET_TASK_COMM __get_task_comm;
    VMALLOC vmalloc;
    VFREE vfree;
    COPY_FROM_USER copy_from_user;
    PRINT_HEX_DUMP print_hex_dump;

} KERNEL_FUNCTIONS, *PKERNEL_FUNCTIONS;

bool init_kernel_functions();
PKERNEL_FUNCTIONS get_krl_func();

#endif //_KERNEL_FUNC_H_