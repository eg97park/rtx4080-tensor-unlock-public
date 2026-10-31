/* SPDX-License-Identifier: GPL-2.0-only. Freestanding additions for core only. */
#include <stddef.h>
int strcmp(const char *a,const char *b){
    while(*a && *a==*b){a++;b++;}
    return (unsigned char)*a-(unsigned char)*b;
}
size_t strlen(const char *p){const char *end=p;while(*end)end++;return (size_t)(end-p);}
void *memchr(const void *p,int c,size_t n){
    const unsigned char *s=p;for(size_t i=0;i<n;i++)if(s[i]==(unsigned char)c)return (void *)(s+i);return NULL;
}
