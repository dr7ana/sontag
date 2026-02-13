#include "utils.hpp"

namespace sontag::test {

    TEST_CASE("009: opcode parser handles complex disassembly fixture", "[009][opcode]") {
        auto disassembly = R"(
0000000000000000 <__sontag_main()>:
       0: 55                            push    rbp
       1: 48 89 e5                      mov     rbp, rsp
       4: 48 83 ec 10                   sub     rsp, 0x10
       8: 8a 05 00 00 00 00             mov     al, byte ptr  <__sontag_main()+0xe>
       e: 88 45 ff                      mov     byte ptr [rbp - 0x1], al
      11: 8b 05 00 00 00 00             mov     eax, dword ptr  <__sontag_main()+0x17>
      17: d1 e0                         shl     eax
      19: 89 45 f8                      mov     dword ptr [rbp - 0x8], eax
      1c: 8b 05 00 00 00 00             mov     eax, dword ptr  <__sontag_main()+0x22>
      22: 89 05 00 00 00 00             mov     dword ptr , eax <__sontag_main()+0x28>
      28: 8b 45 f8                      mov     eax, dword ptr [rbp - 0x8]
      2b: 89 05 00 00 00 00             mov     dword ptr , eax <__sontag_main()+0x31>
      31: 8b 3d 00 00 00 00             mov     edi, dword ptr  <__sontag_main()+0x37>
      37: 8b 35 00 00 00 00             mov     esi, dword ptr  <__sontag_main()+0x3d>
      3d: e8 00 00 00 00                call     <L0>
<L0>:
      42: 89 05 00 00 00 00             mov     dword ptr , eax <__sontag_main()+0x48>
      48: 8b 3d 00 00 00 00             mov     edi, dword ptr  <__sontag_main()+0x4e>
      4e: 8b 35 00 00 00 00             mov     esi, dword ptr  <__sontag_main()+0x54>
      54: ba 03 00 00 00                mov     edx, 0x3
      59: e8 00 00 00 00                call     <L1>
<L1>:
      5e: 89 05 00 00 00 00             mov     dword ptr , eax <__sontag_main()+0x64>
      64: 31 c0                         xor     eax, eax
      66: 48 83 c4 10                   add     rsp, 0x10
      6a: 5d                            pop     rbp
      6b: c3                            ret

Disassembly of section .text._Z3addii:

0000000000000000 <add(int, int)>:
       0: 55                            push    rbp
       1: 48 89 e5                      mov     rbp, rsp
       4: 89 7d fc                      mov     dword ptr [rbp - 0x4], edi
       7: 89 75 f8                      mov     dword ptr [rbp - 0x8], esi
       a: 8b 45 fc                      mov     eax, dword ptr [rbp - 0x4]
       d: 03 45 f8                      add     eax, dword ptr [rbp - 0x8]
      10: 5d                            pop     rbp
      11: c3                            ret

Disassembly of section .text._Z4foldiii:

0000000000000000 <fold(int, int, int)>:
       0: 55                            push    rbp
       1: 48 89 e5                      mov     rbp, rsp
       4: 48 83 ec 20                   sub     rsp, 0x20
       8: 89 7d f8                      mov     dword ptr [rbp - 0x8], edi
       b: 89 75 f4                      mov     dword ptr [rbp - 0xc], esi
       e: 89 55 f0                      mov     dword ptr [rbp - 0x10], edx
      11: 8b 45 f0                      mov     eax, dword ptr [rbp - 0x10]
      14: 83 c0 ff                      add     eax, -0x1
      17: 89 45 f0                      mov     dword ptr [rbp - 0x10], eax
      1a: 83 f8 00                      cmp     eax, 0x0
      1d: 7e 23                         jle      <L2>
      1f: 8b 45 f8                      mov     eax, dword ptr [rbp - 0x8]
      22: 89 45 ec                      mov     dword ptr [rbp - 0x14], eax
      25: 8b 7d f8                      mov     edi, dword ptr [rbp - 0x8]
      28: 8b 75 f4                      mov     esi, dword ptr [rbp - 0xc]
      2b: e8 00 00 00 00                call     <L0>
<L0>:
      30: 8b 7d ec                      mov     edi, dword ptr [rbp - 0x14]
      33: 89 c6                         mov     esi, eax
      35: 8b 55 f0                      mov     edx, dword ptr [rbp - 0x10]
      38: e8 00 00 00 00                call     <L1>
<L1>:
      3d: 89 45 fc                      mov     dword ptr [rbp - 0x4], eax
      40: eb 0e                         jmp      <L4>
<L2>:
      42: 8b 7d f8                      mov     edi, dword ptr [rbp - 0x8]
      45: 8b 75 f4                      mov     esi, dword ptr [rbp - 0xc]
      48: e8 00 00 00 00                call     <L3>
<L3>:
      4d: 89 45 fc                      mov     dword ptr [rbp - 0x4], eax
<L4>:
      50: 8b 45 fc                      mov     eax, dword ptr [rbp - 0x4]
      53: 48 83 c4 20                   add     rsp, 0x20
      57: 5d                            pop     rbp
      58: c3                            ret
)";

        opcode::opcode_interner interner{};
        auto operations = opcode::parse_operations(disassembly, interner);

        REQUIRE(operations.size() == 63U);
        CHECK(interner.size() == 12U);
        CHECK(interner.next_opcode_uid() == interner.size() + 1U);

        auto has_mnemonic = [&](std::string_view needle) {
            return std::ranges::any_of(
                    operations, [&](const opcode::operation_node& op) { return op.mnemonic == needle; });
        };

        CHECK(has_mnemonic("push"));
        CHECK(has_mnemonic("mov"));
        CHECK(has_mnemonic("sub"));
        CHECK(has_mnemonic("shl"));
        CHECK(has_mnemonic("call"));
        CHECK(has_mnemonic("xor"));
        CHECK(has_mnemonic("add"));
        CHECK(has_mnemonic("pop"));
        CHECK(has_mnemonic("ret"));
        CHECK(has_mnemonic("cmp"));
        CHECK(has_mnemonic("jle"));
        CHECK(has_mnemonic("jmp"));

        CHECK(operations.front().ordinal == 0U);
        CHECK(operations.front().mnemonic == "push");
        CHECK(operations.front().opcode == 1U);
        CHECK(operations.back().ordinal == 62U);
        CHECK(operations.back().mnemonic == "ret");
        CHECK(operations.back().opcode == 9U);

        CHECK(interner.mnemonic_for(1U).value_or(""sv) == "push");
        CHECK(interner.mnemonic_for(2U).value_or(""sv) == "mov");
        CHECK(interner.mnemonic_for(3U).value_or(""sv) == "sub");
        CHECK(interner.mnemonic_for(4U).value_or(""sv) == "shl");
        CHECK(interner.mnemonic_for(5U).value_or(""sv) == "call");
        CHECK(interner.mnemonic_for(6U).value_or(""sv) == "xor");
        CHECK(interner.mnemonic_for(7U).value_or(""sv) == "add");
        CHECK(interner.mnemonic_for(8U).value_or(""sv) == "pop");
        CHECK(interner.mnemonic_for(9U).value_or(""sv) == "ret");
        CHECK(interner.mnemonic_for(10U).value_or(""sv) == "cmp");
        CHECK(interner.mnemonic_for(11U).value_or(""sv) == "jle");
        CHECK(interner.mnemonic_for(12U).value_or(""sv) == "jmp");
    }

    TEST_CASE("009: opcode parser interns objdump mnemonics in first-seen order", "[009][opcode]") {
        auto disassembly = R"(0000000000000000 <__sontag_main>:
   0:   55                      push   rbp
   1:   48 89 e5                mov    rbp, rsp
   4:   31 c0                   xor    eax, eax
   6:   c3                      ret
)";

        opcode::opcode_interner interner{};
        auto operations = opcode::parse_operations(disassembly, interner);

        REQUIRE(operations.size() == 4U);
        CHECK(interner.size() == 4U);
        CHECK(interner.next_opcode_uid() == 5U);

        CHECK(operations[0].ordinal == 0U);
        CHECK(operations[0].mnemonic == "push");
        CHECK(operations[0].opcode == 1U);

        CHECK(operations[1].ordinal == 1U);
        CHECK(operations[1].mnemonic == "mov");
        CHECK(operations[1].opcode == 2U);

        CHECK(operations[2].ordinal == 2U);
        CHECK(operations[2].mnemonic == "xor");
        CHECK(operations[2].opcode == 3U);

        CHECK(operations[3].ordinal == 3U);
        CHECK(operations[3].mnemonic == "ret");
        CHECK(operations[3].opcode == 4U);

        auto entries = interner.opcode_entries();
        REQUIRE(entries.size() == 4U);
        CHECK(entries[0].mnemonic == "push");
        CHECK(entries[1].mnemonic == "mov");
        CHECK(entries[2].mnemonic == "xor");
        CHECK(entries[3].mnemonic == "ret");
    }

    TEST_CASE("009: opcode parser reuses uid for repeated mnemonics", "[009][opcode]") {
        auto disassembly = R"(xor eax, eax
add eax, 1
xor eax, eax
ret
)";

        opcode::opcode_interner interner{};
        auto operations = opcode::parse_operations(disassembly, interner);

        REQUIRE(operations.size() == 4U);
        CHECK(interner.size() == 3U);

        CHECK(operations[0].mnemonic == "xor");
        CHECK(operations[0].opcode == 1U);
        CHECK(operations[1].mnemonic == "add");
        CHECK(operations[1].opcode == 2U);
        CHECK(operations[2].mnemonic == "xor");
        CHECK(operations[0].opcode == operations[2].opcode);
        CHECK(operations[3].mnemonic == "ret");
        CHECK(operations[3].opcode == 3U);

        CHECK(interner.mnemonic_for(1U).value_or(""sv) == "xor");
        CHECK(interner.mnemonic_for(2U).value_or(""sv) == "add");
        CHECK(interner.mnemonic_for(3U).value_or(""sv) == "ret");
    }

    TEST_CASE("009: opcode parser handles prefixed and blob-encoded lines", "[009][opcode]") {
        auto disassembly = R"(0000000000000000 <foo>:
   0:   f30f1efa                endbr64
   4:   f0 01 00                lock add DWORD PTR [rax], eax
   7:   c3                      ret
)";

        opcode::opcode_interner interner{};
        auto operations = opcode::parse_operations(disassembly, interner);

        REQUIRE(operations.size() == 3U);
        CHECK(operations[0].mnemonic == "endbr64");
        CHECK(operations[0].opcode == 1U);
        CHECK(operations[1].mnemonic == "add");
        CHECK(operations[1].opcode == 2U);
        CHECK(operations[2].mnemonic == "ret");
        CHECK(operations[2].opcode == 3U);

        CHECK(interner.size() == 3U);
        CHECK(interner.mnemonic_for(1U).value_or(""sv) == "endbr64");
        CHECK(interner.mnemonic_for(2U).value_or(""sv) == "add");
        CHECK(interner.mnemonic_for(3U).value_or(""sv) == "ret");
    }

    TEST_CASE("009: opcode triplet normalization ignores ptr token", "[009][opcode]") {
        auto disassembly = R"(0000000000000000 <foo>:
   0:   8b 05 00 00 00 00       mov     eax, dword ptr [rip + 0x0]
   6:   89 45 f8                mov     dword ptr [rbp - 0x8], eax
)";

        opcode::opcode_interner interner{};
        auto operations = opcode::parse_operations(disassembly, interner);

        REQUIRE(operations.size() == 2U);
        CHECK(operations[0].mnemonic == "mov");
        CHECK(operations[1].mnemonic == "mov");
        CHECK(operations[0].signature == "mov eax, dword [rip + 0x0]");
        CHECK(operations[1].signature == "mov dword [rbp - 0x8], eax");
    }

    TEST_CASE("009: opcode uid assignment is deterministic for identical input", "[009][opcode]") {
        auto disassembly = R"(0000000000000000 <foo>:
   0:   31 c0                   xor    eax, eax
   2:   83 c0 01                add    eax, 1
   5:   31 c0                   xor    eax, eax
   7:   c3                      ret
)";

        opcode::opcode_interner intern_a{};
        opcode::opcode_interner intern_b{};

        auto ops_a = opcode::parse_operations(disassembly, intern_a);
        auto ops_b = opcode::parse_operations(disassembly, intern_b);

        REQUIRE(ops_a.size() == 4U);
        REQUIRE(intern_a.opcode_entries().size() == 3U);
        CHECK(ops_a[0].opcode == 1U);
        CHECK(ops_a[1].opcode == 2U);
        CHECK(ops_a[2].opcode == 1U);
        CHECK(ops_a[3].opcode == 3U);

        REQUIRE(ops_a.size() == ops_b.size());
        for (size_t i = 0U; i < ops_a.size(); ++i) {
            CHECK(ops_a[i].ordinal == ops_b[i].ordinal);
            CHECK(ops_a[i].opcode == ops_b[i].opcode);
            CHECK(ops_a[i].mnemonic == ops_b[i].mnemonic);
        }
        CHECK(intern_a.opcode_entries().size() == intern_b.opcode_entries().size());
    }

    TEST_CASE("009: opcode mapper shares uid table across streams in scan order", "[009][opcode]") {
        auto baseline = R"(0000000000000000 <foo>:
   0:   31 c0                   xor    eax, eax
   2:   c3                      ret
)";
        auto target = R"(0000000000000000 <foo>:
   0:   31 c0                   xor    eax, eax
   2:   83 c0 01                add    eax, 1
   5:   c3                      ret
)";

        std::vector<opcode::operation_stream_input> streams{};
        streams.push_back(opcode::operation_stream_input{.name = "baseline", .disassembly = baseline});
        streams.push_back(opcode::operation_stream_input{.name = "target", .disassembly = target});

        auto mapped = opcode::map_operation_streams(streams);
        REQUIRE(mapped.streams.size() == 2U);
        REQUIRE(mapped.opcode_table.size() == 3U);

        CHECK(mapped.opcode_table[0].mnemonic == "xor");
        CHECK(mapped.opcode_table[0].uid == 1U);
        CHECK(mapped.opcode_table[1].mnemonic == "ret");
        CHECK(mapped.opcode_table[1].uid == 2U);
        CHECK(mapped.opcode_table[2].mnemonic == "add");
        CHECK(mapped.opcode_table[2].uid == 3U);

        REQUIRE(mapped.streams[0].operations.size() == 2U);
        CHECK(mapped.streams[0].operations[0].opcode == 1U);
        CHECK(mapped.streams[0].operations[1].opcode == 2U);

        REQUIRE(mapped.streams[1].operations.size() == 3U);
        CHECK(mapped.streams[1].operations[0].opcode == 1U);
        CHECK(mapped.streams[1].operations[1].opcode == 3U);
        CHECK(mapped.streams[1].operations[2].opcode == 2U);
    }

}  // namespace sontag::test
