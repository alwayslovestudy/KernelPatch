
#ifndef HOOK_READ_H
#define HOOK_READ_H

void hook_read_init(enum hook_type hook_type);
void hook_read(void* before_read, void* after_read);
void unhook_read(void* before_read, void* after_read);

#endif // HOOK_READ_H