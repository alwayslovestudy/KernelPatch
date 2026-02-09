#ifndef UTILS_H
#define UTILS_H
bool str_replace_all(char *buf, const char *old_str, const char *new_str);
bool u16_str_replace_all(uint16_t *buf, const uint16_t *old_str, const uint16_t *new_str);
void print_hexdump(const char *data, const size_t size);
bool bin_replace_all(uint8_t *buf, size_t buf_len, const uint8_t *old_data, size_t old_len, const uint8_t *new_data,
                     size_t new_len, uint8_t pad);
#endif // UTILS_H