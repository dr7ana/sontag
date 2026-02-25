#include "utils.hpp"

namespace sontag::test {

    TEST_CASE("011: mca register-file parser extracts integer and fp mapping highs", "[011][metrics][parser]") {
        auto mca_text = R"(Iterations:        100
Instructions:      200

Register File statistics:
Total number of mappings created:    0
Max number of mappings used:         0

*  Register File #1 -- Zn4FpPRF:
   Number of physical registers:     192
   Total number of mappings created: 0
   Max number of mappings used:      7

*  Register File #2 -- Zn4IntegerPRF:
   Number of physical registers:     224
   Total number of mappings created: 0
   Max number of mappings used:      155
)";

        auto parsed = metrics::parse_mca_register_file_metrics(mca_text);
        REQUIRE(parsed.fp_max_mappings.has_value());
        REQUIRE(parsed.integer_max_mappings.has_value());
        CHECK(*parsed.fp_max_mappings == 7.0);
        CHECK(*parsed.integer_max_mappings == 155.0);
    }

    TEST_CASE(
            "011: objdump symbol span parser computes byte span from instruction encodings", "[011][metrics][parser]") {
        auto disassembly = R"(0000000000000000 <main()>:
   0: 55                            push    rbp
   1: 48 89 e5                      mov     rbp, rsp
   4: c3                            ret
)";

        auto span = metrics::parse_objdump_symbol_span(disassembly);
        REQUIRE(span.has_value());
        CHECK(span->start == 0U);
        CHECK(span->end == 5U);
        CHECK(span->end - span->start == 5U);
    }

    TEST_CASE(
            "011: asm profile heuristic captures stack frame, spill-fill, and instruction classes",
            "[011][metrics][heuristic]") {
        auto operations = std::vector<delta_operation>{
                delta_operation{.ordinal = 0U, .opcode_uid = 1U, .opcode = "push", .triplet = "push rbp"},
                delta_operation{.ordinal = 1U, .opcode_uid = 2U, .opcode = "mov", .triplet = "mov rbp, rsp"},
                delta_operation{.ordinal = 2U, .opcode_uid = 3U, .opcode = "sub", .triplet = "sub rsp, 0x20"},
                delta_operation{
                        .ordinal = 3U, .opcode_uid = 2U, .opcode = "mov", .triplet = "mov dword [rbp - 0x4], eax"},
                delta_operation{
                        .ordinal = 4U, .opcode_uid = 2U, .opcode = "mov", .triplet = "mov eax, dword [rbp - 0x4]"},
                delta_operation{.ordinal = 5U, .opcode_uid = 4U, .opcode = "call", .triplet = "call <l0>"},
                delta_operation{.ordinal = 6U, .opcode_uid = 5U, .opcode = "ret", .triplet = "ret"}};

        auto disassembly = R"(0000000000000000 <main()>:
   0: 55                            push    rbp
loop_head:
   1: 48 89 e5                      mov     rbp, rsp
   4: c3                            ret
)";

        auto profile = metrics::build_asm_operation_profile(operations, disassembly);
        CHECK(profile.instruction_count == operations.size());
        CHECK(profile.store_count >= 1U);
        CHECK(profile.load_count >= 1U);
        CHECK(profile.call_count == 1U);
        CHECK(profile.branch_count >= 1U);
        CHECK(profile.stack_frame_bytes == 0x20U);
        CHECK(profile.spill_fill_count >= 2U);
        CHECK(profile.basic_block_count >= 2U);
    }

}  // namespace sontag::test
