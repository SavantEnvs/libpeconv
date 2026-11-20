#include "win_stubs.h"
#include <stdlib.h>
#include <string.h>
#include <map>

namespace {
std::map<ULONG_PTR, size_t> &regions() {
    static std::map<ULONG_PTR, size_t> r;
    return r;
}
}  // namespace

void stub_region_add(const void *base, size_t size) {
    if (base && size) regions()[(ULONG_PTR)base] = size;
}
void stub_region_del(const void *base) { regions().erase((ULONG_PTR)base); }

InputCopy::InputCopy(const uint8_t *data, size_t n) : buf(nullptr), size(n) {
    buf = (BYTE *)malloc(n ? n : 1);
    if (n) memcpy(buf, data, n);
    stub_region_add(buf, n);
}
InputCopy::~InputCopy() {
    stub_region_del(buf);
    free(buf);
}

extern "C" {

// Requests over 64 MiB fail, as VirtualAlloc does on a host out of commit: SizeOfImage is
// input-controlled (up to 4 GiB) and every byte is zeroed and ASan-tracked here, so larger
// allocations only run the fuzzer out of memory. libpeconv handles the failure (returns null).
static const SIZE_T kMaxAlloc = (SIZE_T)64 << 20;
LPVOID WINAPI VirtualAlloc(LPVOID, SIZE_T size, DWORD, DWORD) {
    if (size == 0 || size > kMaxAlloc) return nullptr;
    SIZE_T rounded = (size + 0xfff) & ~(SIZE_T)0xfff;
    void *p = aligned_alloc(0x1000, rounded);
    if (!p) return nullptr;
    memset(p, 0, rounded);
    stub_region_add(p, size);
    return p;
}
BOOL WINAPI VirtualFree(LPVOID p, SIZE_T, DWORD) {
    if (!p) return FALSE;
    stub_region_del(p);
    free(p);
    return TRUE;
}
SIZE_T WINAPI VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len) {
    if (!mbi || len < sizeof(*mbi)) return 0;
    memset(mbi, 0, sizeof(*mbi));
    ULONG_PTR a = (ULONG_PTR)addr;
    auto &r = regions();
    auto it = r.upper_bound(a);
    if (it == r.begin()) return 0;
    --it;
    if (a >= it->first + it->second) return 0;
    mbi->BaseAddress = (PVOID)it->first;
    mbi->AllocationBase = (PVOID)it->first;
    mbi->RegionSize = it->second;
    mbi->State = MEM_COMMIT;
    mbi->Protect = PAGE_READWRITE;
    mbi->AllocationProtect = PAGE_READWRITE;
    mbi->Type = MEM_PRIVATE;
    return sizeof(*mbi);
}
SIZE_T WINAPI VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T) { return 0; }
BOOL WINAPI VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD) { return FALSE; }
// libpeconv's is_bad_read_ptr() uses this (util.cpp defines USE_OLD_BADPTR): readable only
// when the whole range lies inside one registered region.
BOOL WINAPI IsBadReadPtr(LPCVOID p, UINT_PTR n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!n) return FALSE;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return TRUE;
    ULONG_PTR end = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    ULONG_PTR a = (ULONG_PTR)p;
    return (a + n < a || a + n > end) ? TRUE : FALSE;
}
BOOL WINAPI ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *) { return FALSE; }

// Files: reading always fails (harnesses pass buffers); writing succeeds and discards, so
// dump_pe() runs its whole conversion path without touching the filesystem.
#define FAKE_WRITE_HANDLE ((HANDLE)(ULONG_PTR)0x1234)
HANDLE WINAPI CreateFileA(LPCSTR, DWORD access, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) {
    return (access & GENERIC_WRITE) ? FAKE_WRITE_HANDLE : INVALID_HANDLE_VALUE;
}
BOOL WINAPI WriteFile(HANDLE h, LPCVOID, DWORD n, LPDWORD written, LPOVERLAPPED) {
    if (h != FAKE_WRITE_HANDLE) return FALSE;
    if (written) *written = n;
    return TRUE;
}
BOOL WINAPI CloseHandle(HANDLE) { return TRUE; }
BOOL WINAPI ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) { return FALSE; }
DWORD WINAPI GetFileSize(HANDLE, LPDWORD) { return INVALID_FILE_SIZE; }
HANDLE WINAPI CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR) { return nullptr; }
LPVOID WINAPI MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T) { return nullptr; }
BOOL WINAPI UnmapViewOfFile(LPCVOID) { return FALSE; }
DWORD WINAPI GetLastError(void) { return 0; }

// No OS loader: module/resource lookups fail.
HMODULE WINAPI GetModuleHandleA(LPCSTR) { return nullptr; }
BOOL WINAPI GetModuleHandleExW(DWORD, LPCWSTR, HMODULE *m) { if (m) *m = nullptr; return FALSE; }
FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR) { return nullptr; }
HMODULE WINAPI LoadLibraryA(LPCSTR) { return nullptr; }
HRSRC WINAPI FindResourceA(HMODULE, LPCSTR, LPCSTR) { return nullptr; }
HGLOBAL WINAPI LoadResource(HMODULE, HRSRC) { return nullptr; }
LPVOID WINAPI LockResource(HGLOBAL) { return nullptr; }
DWORD WINAPI SizeofResource(HMODULE, HRSRC) { return 0; }
BOOL WINAPI FreeResource(HGLOBAL) { return FALSE; }

}  // extern "C"
