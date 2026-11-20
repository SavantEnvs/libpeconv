// Data directories of a loaded image: relocations, TLS callbacks, load config, resources
// and code caves. The last 8 input bytes choose the cave size and section characteristics.
#include <peconv.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "win_stubs.h"

static size_t g_res_entries;
static bool on_res_entry(BYTE *, IMAGE_RESOURCE_DIRECTORY_ENTRY *, IMAGE_RESOURCE_DATA_ENTRY *entry) {
    if (entry) g_res_entries++;
    return false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    const DWORD cave_size = fdp.ConsumeIntegral<uint32_t>();
    const DWORD charact = fdp.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> pe = fdp.ConsumeRemainingBytes<uint8_t>();
    if (pe.empty()) return -1;  // 0 means "unknown size" to libpeconv, see fuzz_load_pe.cpp
    InputCopy in(pe.data(), pe.size());
    size_t v_size = 0;
    BYTE *mod = peconv::load_pe_module(in.buf, in.size, v_size, false, false);
    if (!mod) return 0;

    if (peconv::has_valid_relocation_table(mod, v_size)) {
        std::unordered_set<ULONGLONG> relocs;
        peconv::CollectRelocs collector(mod, v_size, peconv::is64bit(mod), relocs);
        peconv::process_relocation_table(mod, v_size, &collector);
        std::vector<ULONGLONG> callbacks;
        peconv::list_tls_callbacks(mod, v_size, callbacks, &relocs);
    }
    std::vector<ULONGLONG> callbacks;
    peconv::list_tls_callbacks(mod, v_size, callbacks, nullptr);

    BYTE *ld = peconv::get_load_config_ptr(mod, v_size);
    if (ld) peconv::get_load_config_version(mod, v_size, ld);

    g_res_entries = 0;
    peconv::parse_resources(mod, on_res_entry);

    peconv::find_padding_cave(mod, v_size, cave_size & 0xffff, charact);
    peconv::find_alignment_cave(mod, v_size, cave_size, charact, true);
    peconv::find_ending_cave(mod, v_size, cave_size, charact, true);

    peconv::free_pe_buffer(mod, v_size);
    return 0;
}
