#ifndef HOOK_OPENAT_H
#define HOOK_OPENAT_H

void hook_openat(enum hook_type hook_type,const char * target_process);
void unhook_openat();
#endif // HOOK_OPENAT_H