#pragma once

#include <glaze/glaze.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sontag::internal {

    enum class cell_kind : uint8_t { decl, exec };
    enum class transaction_kind : uint8_t { exec, decl, file, declfile };

    struct cell_record {
        uint64_t cell_id{};
        cell_kind kind{cell_kind::exec};
        std::string text{};
    };

    struct mutation_transaction {
        uint64_t tx_id{};
        transaction_kind kind{transaction_kind::exec};
        std::optional<std::string> source_key{};
        std::vector<uint64_t> cell_ids{};
    };

    struct persisted_config {
        int schema_version{1};
        std::string clang{};
        std::string cxx_standard{};
        std::string opt_level{};
        std::optional<std::string> target{};
        std::optional<std::string> cpu{};
        std::optional<std::string> mca_cpu{};
        std::string mca_path{"llvm-mca"};
        std::string nm_path{"nm"};
        std::string cache_dir{};
        std::string history_file{".sontag/history"};
        std::string output{};
        std::string color{};
        std::string color_scheme{"vaporwave"};
        std::optional<std::string> editor{};
        std::string formatter{"clang-format"};
    };

    struct snapshot_record {
        std::string name{};
        size_t cell_count{};
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
    };

    struct persisted_snapshots {
        int schema_version{1};
        std::string active_snapshot{"current"};
        std::vector<snapshot_record> snapshots{{snapshot_record{"current", 0U}}};
    };

    struct persisted_cells {
        int schema_version{1};
        uint64_t next_cell_id{1U};
        uint64_t next_tx_id{1U};
        std::vector<cell_record> cells{};
        std::vector<mutation_transaction> transactions{};
        std::vector<std::string> decl_cells{};
        std::vector<std::string> exec_cells{};
    };

}  // namespace sontag::internal

namespace glz {

    template <>
    struct meta<sontag::internal::persisted_config> {
        using T = sontag::internal::persisted_config;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "clang",
                       &T::clang,
                       "cxx_standard",
                       &T::cxx_standard,
                       "opt_level",
                       &T::opt_level,
                       "target",
                       &T::target,
                       "cpu",
                       &T::cpu,
                       "mca_cpu",
                       &T::mca_cpu,
                       "mca_path",
                       &T::mca_path,
                       "nm_path",
                       &T::nm_path,
                       "cache_dir",
                       &T::cache_dir,
                       "history_file",
                       &T::history_file,
                       "output",
                       &T::output,
                       "color",
                       &T::color,
                       "color_scheme",
                       &T::color_scheme,
                       "editor",
                       &T::editor,
                       "formatter",
                       &T::formatter);
    };

    template <>
    struct meta<sontag::internal::snapshot_record> {
        using T = sontag::internal::snapshot_record;
        static constexpr auto value =
                object("name",
                       &T::name,
                       "cell_count",
                       &T::cell_count,
                       "decl_cells",
                       &T::decl_cells,
                       "exec_cells",
                       &T::exec_cells);
    };

    template <>
    struct meta<sontag::internal::persisted_snapshots> {
        using T = sontag::internal::persisted_snapshots;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "active_snapshot",
                       &T::active_snapshot,
                       "snapshots",
                       &T::snapshots);
    };

    template <>
    struct meta<sontag::internal::cell_record> {
        using T = sontag::internal::cell_record;
        static constexpr auto value = object("cell_id", &T::cell_id, "kind", &T::kind, "text", &T::text);
    };

    template <>
    struct meta<sontag::internal::mutation_transaction> {
        using T = sontag::internal::mutation_transaction;
        static constexpr auto value =
                object("tx_id", &T::tx_id, "kind", &T::kind, "source_key", &T::source_key, "cell_ids", &T::cell_ids);
    };

    template <>
    struct meta<sontag::internal::persisted_cells> {
        using T = sontag::internal::persisted_cells;
        static constexpr auto value =
                object("schema_version",
                       &T::schema_version,
                       "next_cell_id",
                       &T::next_cell_id,
                       "next_tx_id",
                       &T::next_tx_id,
                       "cells",
                       &T::cells,
                       "transactions",
                       &T::transactions,
                       "decl_cells",
                       &T::decl_cells,
                       "exec_cells",
                       &T::exec_cells);
    };

}  // namespace glz
