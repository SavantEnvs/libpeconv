// Virtual-layout memory dump -> raw PE: detect_dump_mode, pe_virtual_to_raw,
// pe_realign_raw_to_virtual, find_base_candidate and dump_pe in every mode
// (the file write is a discarding stub).
#include <peconv.h>
#include "win_stubs.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return -1;  // 0 means "unknown size" to libpeconv, see fuzz_load_pe.cpp
    InputCopy in(data, size);
    const ULONGLONG base = (ULONGLONG)(ULONG_PTR)in.buf;

    peconv::detect_dump_mode(in.buf, in.size);
    peconv::find_base_candidate(in.buf, in.size);

    size_t out_size = 0;
    BYTE *raw = peconv::pe_virtual_to_raw(in.buf, in.size, base, out_size, true);
    if (raw) peconv::free_pe_buffer(raw, out_size);
    out_size = 0;
    BYTE *realigned = peconv::pe_realign_raw_to_virtual(in.buf, in.size, base, out_size);
    if (realigned) peconv::free_pe_buffer(realigned, out_size);

    const peconv::t_pe_dump_mode modes[] = {peconv::PE_DUMP_AUTO, peconv::PE_DUMP_VIRTUAL,
                                            peconv::PE_DUMP_UNMAP, peconv::PE_DUMP_REALIGN};
    for (peconv::t_pe_dump_mode m : modes) {
        // dump_pe edits the buffer in place (header fixes), so each mode gets a fresh copy.
        InputCopy copy(data, size);
        peconv::t_pe_dump_mode mode = m;
        peconv::dump_pe("dump.bin", copy.buf, copy.size, (ULONGLONG)(ULONG_PTR)copy.buf, mode);
    }
    return 0;
}
