#pragma once
#include <wchar.h>

// Custom C-RunTime functions
wchar_t *phantom_char_to_wchar_ascii(
    const char *src
);

int phantom_wcscmp(
    const wchar_t *s1,
    const wchar_t *s2
);

static wchar_t phantom_to_lower_w(
    wchar_t c
);

int phantom_lstrcmpiW(
    const wchar_t *s1,
    const wchar_t *s2
);