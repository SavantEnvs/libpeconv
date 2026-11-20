// Export directory of a loaded image: ExportsMapper::add_to_lookup (ordinals, forwarders),
// get_exported_names, get_exported_func and the mapper's VA lookups.
#include <peconv.h>
#include <sstream>
#include "win_stubs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return -1;  // 0 means "unknown size" to libpeconv, see fuzz_load_pe.cpp
    InputCopy in(data, size);
    size_t v_size = 0;
    BYTE *mod = peconv::load_pe_module(in.buf, in.size, v_size, false, false);
    if (!mod) return 0;
    const ULONGLONG base = peconv::get_image_base(mod);

    peconv::ExportsMapper mapper;
    mapper.add_to_lookup("fuzz.dll", (HMODULE)mod, v_size, base);
    std::stringstream ss;
    mapper.print_va_to_func(ss);
    mapper.print_func_to_va(ss);
    mapper.get_dll_path(base);
    mapper.find_dll_base_by_func_va(base + 0x1000);

    std::vector<std::string> names;
    peconv::get_exported_names(mod, names);
    for (size_t i = 0; i < names.size() && i < 32; i++) {
        // The name must be readable memory to libpeconv's is_bad_read_ptr (a registered region).
        InputCopy name((const uint8_t *)names[i].c_str(), names[i].size() + 1);
        FARPROC f = peconv::get_exported_func(mod, (LPCSTR)name.buf);
        if (f) {
            ULONGLONG va = (ULONGLONG)(ULONG_PTR)f - (ULONGLONG)(ULONG_PTR)mod + base;
            const peconv::ExportedFunc *ef = mapper.find_export_by_va(va);
            if (ef) ef->toString();
        }
    }
    peconv::free_pe_buffer(mod, v_size);
    return 0;
}
