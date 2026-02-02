#ifndef FILE_FILTER_H
#define FILE_FILTER_H
void file_filter_init(const char *proc_name);
void file_filter_start();
void file_filter_stop();
void file_filter_add_rule(const char *filename, const char *ori_data, const char *replace_data);
#endif // FILE_FILTER_H
