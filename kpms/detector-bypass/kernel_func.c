#include "kernel_func.h"

KERNEL_FUNCTIONS kernel_funcs;

bool init_kernel_functions()
{
    kernel_funcs.__task_pid_nr_ns = (__TASK_PID_NR_NS)kallsyms_lookup_name("__task_pid_nr_ns");
    kernel_funcs.__get_task_comm = (__GET_TASK_COMM)kallsyms_lookup_name("__get_task_comm");
    kernel_funcs.vmalloc = (VMALLOC)kallsyms_lookup_name("vmalloc");
    kernel_funcs.vfree = (VFREE)kallsyms_lookup_name("vfree");
    kernel_funcs.copy_from_user = (COPY_FROM_USER)kallsyms_lookup_name("__arch_copy_from_user");
    if (kernel_funcs.copy_from_user == NULL) {
        logke("init_kernel_functions: __arch_copy_from_user is NULL\n");
        return false;
    }

    kernel_funcs.print_hex_dump = (PRINT_HEX_DUMP)kallsyms_lookup_name("print_hex_dump");
    if (kernel_funcs.print_hex_dump == NULL) {
        logke("init_kernel_functions: print_hex_dump is NULL\n");
        return false;
    }

    kernel_funcs.binder_alloc_copy_user_to_buffer =
        (BINDER_ALLOC_COPY_USER_TO_BUFFER)kallsyms_lookup_name("binder_alloc_copy_user_to_buffer");
    if (!kernel_funcs.binder_alloc_copy_user_to_buffer) {
        logke("init_kernel_functions: binder_alloc_copy_to_buffer is NULL\n");
        return false;
    }
    
    return true;
}

const PKERNEL_FUNCTIONS get_krl_func()
{
    return &kernel_funcs;
}
