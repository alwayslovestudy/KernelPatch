#ifndef HOOK_IOCTL_H
#define HOOK_IOCTL_H
void hook_ioctl_init(enum hook_type hook_type);
void hook_ioctl(void *before_ioctl, void *after_ioctl);
void unhook_ioctl(void *before_ioctl, void *after_ioctl);
#endif