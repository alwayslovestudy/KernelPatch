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
#include <redirect.h>
#include <kernel_func.h>
#include <file_filter.h>
#include <driver_filter.h>

KPM_NAME("kpm-detector-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("neo");
KPM_DESCRIPTION("KernelPatch Module Detector Bypass");

static long detector_bypass_init(const char *args, const char *event, void *__user reserved)
{
    logkd("detector_bypass init ..., args: %s\n", args);
    if (!init_kernel_functions()) {
        logke("detector_bypass init_kernel_functions failed\n");
        return -1;
    }
    driver_filter_init(".app.huntermini");
    driver_filter_add_rule("/dev/binder", " ", " ");
    driver_filter_start();

    // file_filter_init(".app.huntermini");
    // file_filter_add_rule("/proc/cpuinfo", "Hardware", "HHHHHHHH");
    // file_filter_start();
    // redirect_init(".app.huntermini");
    // redirect_add_rule("/proc/cpuinfo", "/data/local/tmp/redirect_cpu.txt");
    // redirect_start();
    return 0;
}

static long detector_bypass_control0(const char *args, char *__user out_msg, int outlen)
{
    logkd("detector_bypass control, args: %s\n", args);
    return 0;
}
static long detector_bypass_exit(void *__user reserved)
{
    // redirect_stop();
    // file_filter_stop();
    driver_filter_stop();
    logkd("kpm-detector_bypass exit ...\n");
    return 0;
}

KPM_INIT(detector_bypass_init);
KPM_CTL0(detector_bypass_control0);
KPM_EXIT(detector_bypass_exit);