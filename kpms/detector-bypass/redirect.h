
#ifndef KPMS_DETECTOR_BYPASS_REDIRECT_H
#define KPMS_DETECTOR_BYPASS_REDIRECT_H

void redirect_init(const char *proc_name);
void redirect_add_path(const char *ori_filename, const char *new_filename);
void redirect_start();
void redirect_stop();
#endif
