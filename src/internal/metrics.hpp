#pragma once

#include "delta.hpp"
#include "opcode.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <vector>

namespace sontag::metrics {

    using namespace std::string_view_literals;

    struct mca_register_file_metrics {
        std::optional<double> integer_max_mappings{};
        std::optional<double> fp_max_mappings{};
    };

    struct objdump_symbol_span {
        uint64_t start{};
        uint64_t end{};
    };

    enum class asm_operand_kind { none, reg, mem, imm, other };

    struct asm_operation_profile {
        size_t instruction_count{};
        size_t load_count{};
        size_t store_count{};
        size_t call_count{};
        size_t branch_count{};
        size_t basic_block_count{};
        size_t stack_frame_bytes{};
        size_t spill_fill_count{};
    };

    inline std::optional<double> parse_number_after_colon(std::string_view line) {
        auto colon = line.find(':');
        if (colon == std::string_view::npos || colon + 1U >= line.size()) {
            return std::nullopt;
        }
        std::string value{opcode::trim_ascii(line.substr(colon + 1U))};
        if (value.empty()) {
            return std::nullopt;
        }
        auto* end = static_cast<char*>(nullptr);
        auto parsed = std::strtod(value.c_str(), &end);
        if (end == value.c_str()) {
            return std::nullopt;
        }
        return parsed;
    }

    inline std::optional<uint64_t> parse_hex_u64(std::string_view token) {
        token = opcode::trim_ascii(token);
        if (token.empty()) {
            return std::nullopt;
        }

        while (!token.empty() && (token.front() == '+' || token.front() == '-')) {
            if (token.front() == '-') {
                return std::nullopt;
            }
            token.remove_prefix(1U);
        }

        if (token.size() > 2U && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
            token.remove_prefix(2U);
        }

        auto value = uint64_t{};
        auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size()) {
            return std::nullopt;
        }
        return value;
    }

    inline std::optional<uint64_t> parse_unsigned_immediate(std::string_view token) {
        token = opcode::trim_ascii(token);
        if (token.empty()) {
            return std::nullopt;
        }
        while (!token.empty() && (token.back() == ',' || token.back() == ')' || token.back() == ']')) {
            token.remove_suffix(1U);
        }
        while (!token.empty() && (token.front() == '(' || token.front() == '[')) {
            token.remove_prefix(1U);
        }
        if (token.empty()) {
            return std::nullopt;
        }

        auto base = 10;
        if (token.size() > 2U && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
            base = 16;
            token.remove_prefix(2U);
        }
        if (token.empty() || token.front() == '-') {
            return std::nullopt;
        }

        auto value = uint64_t{};
        auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, base);
        if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size()) {
            return std::nullopt;
        }
        return value;
    }

    inline std::optional<objdump_symbol_span> parse_objdump_symbol_span(std::string_view disassembly) {
        auto have_span = false;
        auto min_address = uint64_t{};
        auto max_end = uint64_t{};

        size_t begin = 0U;
        while (begin <= disassembly.size()) {
            auto end = disassembly.find('\n', begin);
            if (end == std::string_view::npos) {
                end = disassembly.size();
            }

            auto line = opcode::trim_ascii(disassembly.substr(begin, end - begin));
            if (!line.empty()) {
                auto colon = line.find(':');
                if (colon != std::string_view::npos) {
                    auto address_token = opcode::trim_ascii(line.substr(0U, colon));
                    if (!address_token.empty() &&
                        std::ranges::all_of(address_token, [](char c) { return opcode::ascii_is_hex_digit(c); })) {
                        if (auto address = parse_hex_u64(address_token)) {
                            auto after_colon = opcode::trim_ascii(line.substr(colon + 1U));
                            auto encoded_size = uint64_t{};
                            while (!after_colon.empty()) {
                                auto token = opcode::first_token(after_colon);
                                if (token.empty() || !opcode::is_hex_blob_token(token)) {
                                    break;
                                }
                                encoded_size += static_cast<uint64_t>(token.size() / 2U);
                                after_colon = opcode::trim_ascii(after_colon.substr(token.size()));
                            }

                            if (encoded_size != 0U) {
                                auto line_end = *address + encoded_size;
                                if (!have_span) {
                                    min_address = *address;
                                    max_end = line_end;
                                    have_span = true;
                                }
                                else {
                                    min_address = std::min(min_address, *address);
                                    max_end = std::max(max_end, line_end);
                                }
                            }
                        }
                    }
                }
            }

            if (end == disassembly.size()) {
                break;
            }
            begin = end + 1U;
        }

        if (!have_span || max_end < min_address) {
            return std::nullopt;
        }
        return objdump_symbol_span{.start = min_address, .end = max_end};
    }

    inline asm_operand_kind classify_operand_kind(std::string_view operand) {
        auto trimmed = opcode::trim_ascii(operand);
        if (trimmed.empty()) {
            return asm_operand_kind::none;
        }
        if (trimmed.find('[') != std::string_view::npos && trimmed.find(']') != std::string_view::npos) {
            return asm_operand_kind::mem;
        }

        auto token = opcode::first_token(trimmed);
        auto lowered = opcode::normalize_opcode(token);
        if (lowered.empty()) {
            lowered.assign(token.begin(), token.end());
            std::ranges::transform(lowered, lowered.begin(), opcode::ascii_tolower);
        }

        static constexpr auto memory_prefixes =
                std::array{"byte"sv, "word"sv, "dword"sv, "qword"sv, "xmmword"sv, "ymmword"sv, "zmmword"sv, "ptr"sv};
        if (std::ranges::find(memory_prefixes, lowered) != memory_prefixes.end()) {
            return asm_operand_kind::mem;
        }

        if (parse_unsigned_immediate(trimmed).has_value()) {
            return asm_operand_kind::imm;
        }

        if (!lowered.empty() && std::isalpha(static_cast<unsigned char>(lowered.front())) != 0) {
            return asm_operand_kind::reg;
        }
        return asm_operand_kind::other;
    }

    inline bool is_branch_mnemonic(std::string_view mnemonic) {
        if (mnemonic.empty()) {
            return false;
        }
        return mnemonic.starts_with('j') || mnemonic == "ret"sv || mnemonic.starts_with("loop"sv);
    }

    inline bool is_stack_memory_triplet(std::string_view triplet) {
        return triplet.find("[rbp"sv) != std::string_view::npos || triplet.find("[rsp"sv) != std::string_view::npos ||
               triplet.find("[ebp"sv) != std::string_view::npos || triplet.find("[esp"sv) != std::string_view::npos;
    }

    inline asm_operation_profile build_asm_operation_profile(
            const std::vector<delta_operation>& operations, std::string_view disassembly) {
        auto profile = asm_operation_profile{};
        profile.instruction_count = operations.size();

        for (const auto& operation : operations) {
            auto triplet = operation.triplet.empty() ? std::string_view{operation.opcode}
                                                     : std::string_view{operation.triplet};
            auto mnemonic = opcode::first_token(triplet);
            auto lowered_mnemonic = opcode::normalize_opcode(mnemonic);
            if (lowered_mnemonic.empty()) {
                lowered_mnemonic = operation.opcode;
            }

            auto operands = opcode::trim_ascii(triplet.substr(mnemonic.size()));
            auto comma = operands.find(',');
            auto lhs = comma == std::string_view::npos ? operands : operands.substr(0U, comma);
            auto rhs = comma == std::string_view::npos ? std::string_view{} : operands.substr(comma + 1U);

            auto lhs_kind = classify_operand_kind(lhs);
            auto rhs_kind = classify_operand_kind(rhs);
            if (lhs_kind == asm_operand_kind::mem) {
                ++profile.store_count;
            }
            if (rhs_kind == asm_operand_kind::mem) {
                ++profile.load_count;
            }

            if (lowered_mnemonic.starts_with("call"sv)) {
                ++profile.call_count;
            }
            if (is_branch_mnemonic(lowered_mnemonic)) {
                ++profile.branch_count;
            }
            if (is_stack_memory_triplet(triplet)) {
                ++profile.spill_fill_count;
            }

            if ((lowered_mnemonic == "sub"sv || lowered_mnemonic == "add"sv) &&
                (opcode::trim_ascii(lhs) == "rsp"sv || opcode::trim_ascii(lhs) == "esp"sv)) {
                if (auto immediate = parse_unsigned_immediate(rhs)) {
                    profile.stack_frame_bytes = std::max(profile.stack_frame_bytes, static_cast<size_t>(*immediate));
                }
            }
        }

        size_t begin = 0U;
        while (begin <= disassembly.size()) {
            auto end = disassembly.find('\n', begin);
            if (end == std::string_view::npos) {
                end = disassembly.size();
            }

            auto line = disassembly.substr(begin, end - begin);
            if (opcode::is_label_line(line)) {
                ++profile.basic_block_count;
            }

            if (end == disassembly.size()) {
                break;
            }
            begin = end + 1U;
        }

        if (profile.basic_block_count == 0U && profile.instruction_count > 0U) {
            profile.basic_block_count = 1U;
        }

        return profile;
    }

    inline mca_register_file_metrics parse_mca_register_file_metrics(std::string_view mca_text) {
        auto metrics = mca_register_file_metrics{};

        enum class active_register_file { none, integer, fp };
        auto active = active_register_file::none;

        size_t begin = 0U;
        while (begin <= mca_text.size()) {
            auto end = mca_text.find('\n', begin);
            if (end == std::string_view::npos) {
                end = mca_text.size();
            }

            auto trimmed = opcode::trim_ascii(mca_text.substr(begin, end - begin));
            if (!trimmed.empty()) {
                if (trimmed.starts_with("*"sv) && trimmed.find("Register File"sv) != std::string_view::npos) {
                    auto lower = std::string{trimmed};
                    std::ranges::transform(lower, lower.begin(), opcode::ascii_tolower);
                    if (lower.find("integer"sv) != std::string::npos) {
                        active = active_register_file::integer;
                    }
                    else if (lower.find("fp"sv) != std::string::npos) {
                        active = active_register_file::fp;
                    }
                    else {
                        active = active_register_file::none;
                    }
                }
                else if (trimmed.starts_with("Max number of mappings used:"sv)) {
                    if (auto parsed = parse_number_after_colon(trimmed)) {
                        switch (active) {
                            case active_register_file::integer:
                                metrics.integer_max_mappings = *parsed;
                                break;
                            case active_register_file::fp:
                                metrics.fp_max_mappings = *parsed;
                                break;
                            case active_register_file::none:
                                break;
                        }
                    }
                }
            }

            if (end == mca_text.size()) {
                break;
            }
            begin = end + 1U;
        }

        return metrics;
    }

}  // namespace sontag::metrics
