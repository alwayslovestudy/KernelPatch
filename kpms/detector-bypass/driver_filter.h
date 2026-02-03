#ifndef DRIVER_FILTER_H
#define DRIVER_FILTER_H
void driver_filter_init(const char *proc_name);
void driver_filter_start();
void driver_filter_stop();
void driver_filter_add_rule(const char *drivername, const char *ori_data, const char *replace_data);
#endif // DRIVER_FILTER_H