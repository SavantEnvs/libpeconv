// Import tables of a loaded image: has_valid_import_table, collect_thunks, collect_imports,
// load_imports and load_delayed_imports (with a resolver returning fake addresses).
#include <peconv.h>
#include "win_stubs.h"
#include "fake_resolver.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return -1;  // 0 means "unknown size" to libpeconv, see fuzz_load_pe.cpp
    InputCopy in(data, size);
    size_t v_size = 0;
    BYTE *mod = peconv::load_pe_module(in.buf, in.size, v_size, false, false);
    if (!mod) return 0;

    peconv::has_valid_import_table(mod, v_size);
    std::set<DWORD> thunks;
    peconv::collect_thunks(mod, v_size, thunks);
    {
        peconv::ImportsCollection coll;
        peconv::collect_imports(mod, v_size, coll);
    }
    FakeResolver resolver;
    peconv::load_imports(mod, &resolver);
    size_t dir_size = 0;
    peconv::get_delayed_imps(mod, v_size, dir_size);
    peconv::load_delayed_imports(mod, (ULONGLONG)(ULONG_PTR)mod, &resolver);

    peconv::free_pe_buffer(mod, v_size);
    return 0;
}
