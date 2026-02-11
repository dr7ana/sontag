#include "cli.hpp"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        sontag::startup_config cfg{};
        if (auto cli_result = sontag::cli::parse_cli(argc, argv, cfg)) {
            return *cli_result;
        }

        sontag::cli::run_repl(cfg);
        return 0;
    } catch (std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "fatal: unknown exception\n";
        return 1;
    }
}
