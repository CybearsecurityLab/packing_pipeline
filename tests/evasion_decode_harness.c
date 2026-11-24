#include "paper_trace.c"

static int emit_samples(void)
{
    ThreadContext context = {.source_pid = 7, .tid = 9};
    EvasionOrigin sample = {.origin = ORIGIN_SAMPLE, .module = "pa\"ck\\ed.exe"};
    EvasionOrigin dynamic = {.origin = ORIGIN_DYNAMIC};
    g_autoptr(GString) detail = g_string_new(NULL);
    g_autoptr(GString) empty = g_string_new(NULL);

    trace_file = stdout;
    evasion_initialize();
    evasion_append_json_string(detail, "path", "\\Registry\\\"VBOX\"\x01");
    evasion_append_hex(detail, "caller", UINT64_C(0x7ff612340000));
    evasion_append_origin(detail, "caller_", &sample);
    evasion_emit(&context, UINT64_C(0x401000), EVK_SYSCALL, &sample, detail);
    evasion_emit(&context, UINT64_C(0x402000), EVK_INT3, &dynamic, empty);
    for (unsigned int round = 0; round < 6; round++) {
        printf("{\"allow\":%s}\n",
               evasion_allow(EVK_CPUID, 0x401000, 1, 0, EVASION_DETAIL_LIMIT)
                   ? "true"
                   : "false");
    }
    g_string_truncate(empty, 0);
    evasion_append_json_string(
        empty, "match",
        evasion_match("\\REGISTRY\\MACHINE\\HARDWARE\\Description\\System",
                      evasion_registry_terms,
                      G_N_ELEMENTS(evasion_registry_terms)));
    printf("{%s}\n", empty->str + 1);
    printf("{\"no_match\":%s}\n",
           evasion_match("\\Registry\\Machine\\Software\\Microsoft\\Provider",
                         evasion_registry_terms,
                         G_N_ELEMENTS(evasion_registry_terms))
               ? "false"
               : "true");
    evasion_syscall_counts[evasion_syscall_index[0x12]] = 3;
    evasion_op_counts[EVOP_CPUID] = 5;
    fputc('{', stdout);
    fputs("\"event\":\"summary\"", stdout);
    evasion_emit_summary();
    fputs("}\n", stdout);
    evasion_destroy();
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--emit") == 0) {
        return emit_samples();
    }
    for (int arg = 1; arg < argc; arg++) {
        uint8_t bytes[16] = {0};
        size_t size = strlen(argv[arg]) / 2;
        EvasionInsn insn = {0};
        uint8_t op;

        if (size > sizeof(bytes)) {
            return 2;
        }
        for (size_t index = 0; index < size; index++) {
            unsigned int value;
            if (sscanf(argv[arg] + 2 * index, "%2x", &value) != 1) {
                return 2;
            }
            bytes[index] = (uint8_t)value;
        }
        op = evasion_decode(bytes, size, size, &insn);
        printf("%s %s %u %u %d\n", argv[arg], evasion_op_names[op], insn.width,
               insn.port, insn.port_immediate);
    }
    return 0;
}
