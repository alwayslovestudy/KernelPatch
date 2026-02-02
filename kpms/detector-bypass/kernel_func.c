#include "kernel_func.h"

KERNEL_FUNCTIONS kernel_funcs;

void init_kernel_functions()
{
    kernel_funcs.__task_pid_nr_ns = (__TASK_PID_NR_NS)kallsyms_lookup_name("__task_pid_nr_ns");
    kernel_funcs.__get_task_comm = (__GET_TASK_COMM)kallsyms_lookup_name("__get_task_comm");
}

const PKERNEL_FUNCTIONS get_kernel_functions()
{
    return &kernel_funcs;
}
