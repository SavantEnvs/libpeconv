// Import recovery on a dumped module: peconv::fix_imports (ImportedDllCoverage,
// ImportsUneraser) against an ExportsMapper built from a second PE.
// Input: u32 little-endian length L, then L bytes of an export-provider DLL (raw PE),
// then the dumped module in virtual layout whose IAT holds VAs into the provider.
#include <peconv.h>
#include <string.h>
#include "win_stubs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return -1;
    uint32_t dll_len;
    memcpy(&dll_len, data, 4);
    data += 4;
    size -= 4;
    if (dll_len == 0 || dll_len >= size) return -1;  // both parts are sized buffers (see fuzz_load_pe.cpp)

    InputCopy dll(data, dll_len);
    InputCopy dump(data + dll_len, size - dll_len);

    peconv::ExportsMapper mapper;
    size_t dll_v = 0;
    BYTE *dll_mod = peconv::load_pe_module(dll.buf, dll.size, dll_v, false, false);
    if (dll_mod) {
        mapper.add_to_lookup("provider.dll", (HMODULE)dll_mod, dll_v, peconv::get_image_base(dll_mod));
    }
    peconv::ImpsNotCovered not_covered;
    peconv::fix_imports(dump.buf, dump.size, mapper, &not_covered);
    if (dll_mod) peconv::free_pe_buffer(dll_mod, dll_v);
    return 0;
}
