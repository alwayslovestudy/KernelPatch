#ifndef BINDER_FILTER_H
#define BINDER_FILTER_H
void binder_filter_init(const char* proc_name);
void binder_filter_add_rule(const char* ori_data, size_t ori_len, const char* replace_data, size_t replace_len);
void binder_filter_start();
void binder_filter_stop();


#endif // BINDER_FILTER_H
