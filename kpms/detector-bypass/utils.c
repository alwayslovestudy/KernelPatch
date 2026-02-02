#include <linux/string.h>
#include <log.h>
bool str_replace_all(char* buf, const char* old_str, const char* new_str)
{
    size_t old_len = strlen(old_str);
    size_t new_len = strlen(new_str);

    if (old_len == 0 || new_len > old_len) {
        logke("str_replace_all error: old_len=%zu, new_len=%zu\n",
            old_len, new_len);
        return false;
    }

    char* p = buf;
    while ((p = strstr(p, old_str)) != NULL) {
        /* 1. 拷贝新内容 */
        memcpy(p, new_str, new_len);

        /* 2. 用空格填充剩余部分 */
        if (new_len < old_len) {
            memset(p + new_len, ' ', old_len - new_len);  //长度不够时使用空格填充
        }

        /* 3. 按 old_len 前进，避免重复匹配 */
        p += old_len;
    }

    return true;
}