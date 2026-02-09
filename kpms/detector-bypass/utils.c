#include <linux/string.h>
#include <linux/kernel.h>
#include <log.h>
#include <kernel_func.h>
#define DUMP_PREFIX_NONE 0
#define DUMP_PREFIX_ADDRESS 1
#define DUMP_PREFIX_OFFSET 2

bool str_replace_all(char *buf, const char *old_str, const char *new_str)
{
    size_t old_len = strlen(old_str);
    size_t new_len = strlen(new_str);

    if (old_len == 0 || new_len > old_len) {
        logke("str_replace_all error: old_len=%zu, new_len=%zu\n", old_len, new_len);
        return false;
    }

    char *p = buf;
    while ((p = strstr(p, old_str)) != NULL) {
        /* 1. 拷贝新内容 */
        memcpy(p, new_str, new_len);

        /* 2. 用空格填充剩余部分 */
        if (new_len < old_len) {
            memset(p + new_len, ' ', old_len - new_len); //长度不够时使用空格填充
        }

        /* 3. 按 old_len 前进，避免重复匹配 */
        p += old_len;
    }

    return true;
}

static size_t u16_strlen(const uint16_t *s)
{
    const uint16_t *p = s;
    while (*p)
        p++;
    return (size_t)(p - s);
}

/* 查找子串（等价 wcsstr） */
static uint16_t *u16_strstr(uint16_t *haystack, const uint16_t *needle)
{
    if (!*needle) return haystack;

    for (; *haystack; haystack++) {
        uint16_t *h = haystack;
        const uint16_t *n = needle;

        while (*h && *n && *h == *n) {
            h++;
            n++;
        }

        if (*n == 0) return haystack;
    }
    return NULL;
}

bool u16_str_replace_all(uint16_t *buf, const uint16_t *old_str, const uint16_t *new_str)
{
    size_t old_len = u16_strlen(old_str);
    size_t new_len = u16_strlen(new_str);

    if (old_len == 0 || new_len > old_len) {
        logke("u16_str_replace_all error: old_len=%zu, new_len=%zu\n", old_len, new_len);
        return false;
    }

    uint16_t *p = buf;
    while ((p = u16_strstr(p, old_str)) != NULL) {
        /* 1. 拷贝新内容 */
        for (size_t i = 0; i < new_len; i++) {
            p[i] = new_str[i];
        }

        /* 2. 填充剩余部分（Unicode 空格 U+0020） */
        for (size_t i = new_len; i < old_len; i++) {
            p[i] = 0x0020;
        }

        /* 3. 前进，避免重复匹配 */
        p += old_len;
    }

    return true;
}
static uint8_t *bin_memmem(uint8_t *haystack, size_t hay_len, const uint8_t *needle, size_t needle_len)
{
    if (needle_len == 0 || hay_len < needle_len) return NULL;

    size_t limit = hay_len - needle_len;

    for (size_t i = 0; i <= limit; i++) {
        size_t j = 0;
        for (; j < needle_len; j++) {
            if (haystack[i + j] != needle[j]) break;
        }
        if (j == needle_len) return haystack + i;
    }
    return NULL;
}
bool bin_replace_all(uint8_t *buf, size_t buf_len, const uint8_t *old_data, size_t old_len, const uint8_t *new_data,
                     size_t new_len, uint8_t pad)
{
    if (!buf || !old_data || !new_data) return false;

    if (old_len == 0 || new_len > old_len) return false;

    uint8_t *p = buf;
    size_t remain = buf_len;

    while (1) {
        uint8_t *hit = bin_memmem(p, remain, old_data, old_len);
        if (!hit) break;

        /* 1. 拷贝新数据 */
        for (size_t i = 0; i < new_len; i++) {
            hit[i] = new_data[i];
        }

        /* 2. 填充剩余字节 */
        for (size_t i = new_len; i < old_len; i++) {
            hit[i] = pad;
        }

        /* 3. 前进 */
        size_t advance = (size_t)(hit - p) + old_len;
        p += advance;
        remain -= advance;
    }

    return true;
}

void print_hexdump(const char *data, const size_t size)
{
    get_krl_func()->print_hex_dump(KERN_INFO, "KP hexdump: ", DUMP_PREFIX_OFFSET, 16, 1, data, size, false);
}
