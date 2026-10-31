/* SPDX-License-Identifier: GPL-2.0-only */
#include <stddef.h>
void *memset(void *dst, int value, size_t count) {
    volatile unsigned char *out = dst;
    for (size_t i = 0; i < count; ++i) out[i] = (unsigned char)value;
    return dst;
}
void *memcpy(void *dst, const void *src, size_t count) {
    volatile unsigned char *out = dst;
    const volatile unsigned char *in = src;
    for (size_t i = 0; i < count; ++i) out[i] = in[i];
    return dst;
}
int memcmp(const void *a, const void *b, size_t count) {
    const unsigned char *x = a, *y = b;
    for (size_t i = 0; i < count; ++i) if (x[i] != y[i]) return x[i] - y[i];
    return 0;
}
