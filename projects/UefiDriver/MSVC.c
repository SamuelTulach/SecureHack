#include "Global.h"

#pragma intrinsic(memcpy)
void* memcpy(void* dest, const void* src, unsigned int count);

#pragma function(memcpy)
void* memcpy(void* dest, const void* src, const unsigned int count)
{
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    for (unsigned int i = 0; i < count; ++i)
    {
        d[i] = s[i];
    }
    return dest;
}