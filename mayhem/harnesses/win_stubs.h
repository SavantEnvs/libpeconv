// Linux stand-ins for the Win32 calls libpeconv makes (built against Wine's headers).
// VirtualQuery answers from a registry of live regions: the harness's copy of the input and
// every block VirtualAlloc handed out, so libpeconv's is_bad_read_ptr() probes stay inside
// real allocations instead of trusting any address.
#pragma once
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

void stub_region_add(const void *base, size_t size);
void stub_region_del(const void *base);

// Owns a mutable, registered copy of a fuzz input (libpeconv's API takes non-const BYTE*).
struct InputCopy {
    BYTE *buf;
    size_t size;
    InputCopy(const uint8_t *data, size_t n);
    ~InputCopy();
};
