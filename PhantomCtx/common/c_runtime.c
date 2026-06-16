#include <stdlib.h>
#include <wchar.h>

#include "c_runtime.h"

// Translate char to wchar_t strings
wchar_t *phantom_char_to_wchar_ascii(const char *src) {
    if (!src) return NULL;

    size_t len = 0;
    while (src[len]) len++;

    wchar_t *dst = malloc((len + 1) * sizeof(wchar_t));
    if (!dst) return NULL;

    for (size_t i = 0; i < len; i++)
        dst[i] = (wchar_t)(unsigned char)src[i];  // (unsigned char) avoids sign extension for bytes > 127
    dst[len] = L'\0';

    return dst;
}

// Custom wcscmp
int phantom_wcscmp(const wchar_t *s1, const wchar_t *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (int)(*s1 - *s2);
}

// Custom lstrcmpiW
static wchar_t phantom_to_lower_w(wchar_t c)
{
    if (c >= L'A' && c <= L'Z')
        return c + (L'a' - L'A');
    return c;
}

int phantom_lstrcmpiW(const wchar_t *s1, const wchar_t *s2)
{
    if (!s1 && !s2) return 0;
    if (!s1)        return -1;
    if (!s2)        return  1;

    while (*s1 && *s2)
    {
        wchar_t c1 = phantom_to_lower_w(*s1);
        wchar_t c2 = phantom_to_lower_w(*s2);

        if (c1 != c2)
            return (c1 > c2) ? 1 : -1;

        s1++;
        s2++;
    }

    wchar_t c1 = phantom_to_lower_w(*s1);
    wchar_t c2 = phantom_to_lower_w(*s2);

    if (c1 == c2) return  0;
    return (c1 > c2) ? 1 : -1;
}