#include <linux/string.h>
bool str_replace_all(char *buf, const char *old_str, const char *new_str)
{
    size_t old_len = strlen(old_str);
    size_t new_len = strlen(new_str);

    if (old_len == 0 || new_len > old_len) return false;

    char *p = buf;

    while ((p = strstr(p, old_str)) != 0) {
        /* 覆盖新内容 */
        memcpy(p, new_str, new_len);

        /* 如果 new 比 old 短，需要整体左移 */
        if (new_len < old_len) {
            memmove(p + new_len, p + old_len, strlen(p + old_len) + 1);
        }

        p += new_len;
    }

    return true;
}