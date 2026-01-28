#ifndef HOOK_OPENAT_H
#define HOOK_OPENAT_H
void hook_openat_init(enum hook_type hook_type);
void hook_openat(void* before_openat, void* after_openat);
void unhook_openat(void* before_openat, void* after_openat);
#endif // HOOK_OPENAT_H