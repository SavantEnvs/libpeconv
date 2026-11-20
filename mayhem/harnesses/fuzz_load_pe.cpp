// Raw PE file -> virtual image: peconv::load_pe_module (headers, sections_raw_to_virtual,
// relocation), once relocated to the allocated base and once mapped without relocating.
#include <peconv.h>
#include "win_stubs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // load_pe_module's size is the buffer size; 0 means "unknown, probe memory" (pe_hdrs_helper),
    // which is not a sized buffer at all.
    if (size == 0) return -1;
    InputCopy in(data, size);
    for (int relocate = 1; relocate >= 0; --relocate) {
        size_t v_size = 0;
        BYTE *mod = peconv::load_pe_module(in.buf, in.size, v_size, false, relocate != 0);
        if (mod) peconv::free_pe_buffer(mod, v_size);
    }
    return 0;
}
