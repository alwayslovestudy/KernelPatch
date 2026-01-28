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
#include <hook_openat.h>

KPM_NAME("kpm-detector-bypass");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("neo");
KPM_DESCRIPTION("KernelPatch Module Detector Bypass");

static long detector_bypass_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("detector_bypass init ..., args: %s\n", args);
    hook_openat(FUNCTION_POINTER_CHAIN, "sankuai.meituan");
    return 0;
}

static long detector_bypass_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("detector_bypass control, args: %s\n", args);
    return 0;
}
static long detector_bypass_exit(void *__user reserved)
{
    pr_info("kpm-detector_bypass exit ...\n");
    unhook_openat();
    return 0;
}

KPM_INIT(detector_bypass_init);
KPM_CTL0(detector_bypass_control0);
KPM_EXIT(detector_bypass_exit);