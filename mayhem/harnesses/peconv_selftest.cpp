// Known-answer probe for mayhem/test.sh: loads each PE file given on the command line with
// libpeconv and prints what the library reports about it. test.sh diffs this against the
// committed golden output, so a library that loads nothing or misparses fails the suite.
#include <peconv.h>
#include <stdio.h>
#include <vector>
#include <set>
#include <algorithm>
#include "win_stubs.h"
#include "fake_resolver.h"

static std::vector<uint8_t> read_all(const char *path) {
    std::vector<uint8_t> v;
    FILE *f = fopen(path, "rb");
    if (!f) return v;
    uint8_t b[65536];
    size_t n;
    while ((n = fread(b, 1, sizeof b, f)) > 0) v.insert(v.end(), b, b + n);
    fclose(f);
    return v;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *name = strrchr(argv[i], '/') ? strrchr(argv[i], '/') + 1 : argv[i];
        std::vector<uint8_t> data = read_all(argv[i]);
        InputCopy in(data.data(), data.size());
        printf("== %s size=%zu raw=%d\n", name, data.size(),
               data.empty() ? -1 : (int)peconv::is_pe_raw(in.buf, in.size));
        size_t v_size = 0;
        BYTE *mod = peconv::load_pe_module(in.buf, in.size, v_size, false, false);
        if (!mod) { printf("load failed\n"); continue; }
        printf("v_size=0x%zx 64bit=%d base=0x%llx ep=0x%x sections=%zu\n", v_size,
               (int)peconv::is64bit(mod), (unsigned long long)peconv::get_image_base(mod),
               (unsigned)peconv::get_entry_point_rva(mod), peconv::get_sections_count(mod, v_size));
        printf("relocs=%d imports=%d\n", (int)peconv::has_valid_relocation_table(mod, v_size),
               (int)peconv::has_valid_import_table(mod, v_size));
        std::set<DWORD> thunks;
        peconv::collect_thunks(mod, v_size, thunks);
        printf("thunks=%zu\n", thunks.size());
        std::vector<std::string> names;
        peconv::get_exported_names(mod, names);
        std::sort(names.begin(), names.end());
        printf("exports=%zu", names.size());
        for (size_t k = 0; k < names.size() && k < 3; k++) printf(" %s", names[k].c_str());
        printf("\n");
        size_t out_size = 0;
        BYTE *raw = peconv::pe_virtual_to_raw(mod, v_size, peconv::get_image_base(mod), out_size, true);
        printf("unmapped=0x%zx\n", raw ? out_size : 0);
        if (raw) peconv::free_pe_buffer(raw, out_size);
        peconv::free_pe_buffer(mod, v_size);
    }
    return 0;
}
