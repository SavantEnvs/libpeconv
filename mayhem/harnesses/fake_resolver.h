#pragma once
#include <peconv.h>
// Import resolver that never loads anything: every name resolves to a fixed fake address
// derived from the name, so import walking runs without LoadLibrary/GetProcAddress.
class FakeResolver : public peconv::t_function_resolver {
public:
    FARPROC resolve_func(LPCSTR lib_name, LPCSTR func_name) override {
        ULONG_PTR h = 0x10000;
        if (lib_name) for (const char *p = lib_name; *p; ++p) h = h * 31 + (unsigned char)*p;
        if (!IS_INTRESOURCE(func_name)) for (const char *p = func_name; *p; ++p) h = h * 31 + (unsigned char)*p;
        else h += (ULONG_PTR)func_name;
        return (FARPROC)(h | 1);
    }
};
