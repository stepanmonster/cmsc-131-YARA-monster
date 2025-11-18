#define NOMINMAX

#include "traverse.hpp"
#include "yara_scan.hpp"
#include "log.hpp"
#include "report.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>


struct Args {
    std::string rules = "rules/all.yar";
    std::string root = ".";
    std::string exts;                 // comma-separated, optional
    int timeout_ms = 10000;           // per-file
    std::string report_dir = "reports";
    std::string report_base = "scan";
    std::string log_path = "logs/scan.log";
    bool quiet = false;
    bool help = false;
};

static void print_usage(const char* prog){
    std::cout <<
        "Usage: " << prog << " [--rules PATH] [--root DIR] [--ext .exe,.dll] [--timeout-ms N]\n"
        "                  [--report-dir DIR] [--report-base NAME] [--log PATH] [--quiet]\n"
        "                  [--help]\n";
}

static bool has_prefix(const std::string& s, const std::string& p){ return s.rfind(p,0)==0; }

static std::string parse_flag(int argc, char** argv, const std::string& name, const std::string& defval) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (has_prefix(arg, name + "=")) return arg.substr(name.size() + 1);
        if (arg == name && i + 1 < argc) return std::string(argv[i + 1]);
    }
    return defval;
}

static bool has_flag(int argc, char** argv, const std::string& name) {
    for (int i = 1; i < argc; ++i) if (std::string(argv[i]) == name) return true;
    return false;
}

static std::vector<std::string> split_exts(const std::string& s) {
    std::vector<std::string> out;
    if (s.empty()) return out;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t comma = s.find(',', pos);
        std::string tok = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        // trim
        auto l = tok.find_first_not_of(" \t");
        auto r = tok.find_last_not_of(" \t");
        if (l != std::string::npos) tok = tok.substr(l, r - l + 1); else tok.clear();
        if (!tok.empty()) {
            if (tok.front() != '.') tok.insert(tok.begin(), '.');
            std::transform(tok.begin(), tok.end(), tok.begin(), [](unsigned char c){ return std::tolower(c); });
            out.push_back(tok);
        }
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return out;
}

int main(int argc, char** argv) {
    Args args;
    args.help = has_flag(argc, argv, "--help");
    if (args.help) { print_usage(argv[0]); return 0; }

    args.rules = parse_flag(argc, argv, "--rules", args.rules);
    args.root = parse_flag(argc, argv, "--root", args.root);
    args.exts = parse_flag(argc, argv, "--ext", "");
    {
        std::string raw = parse_flag(argc, argv, "--timeout-ms", std::to_string(args.timeout_ms));
        try {
            size_t idx = 0;
            long long v = std::stoll(raw, &idx);
            if (idx != raw.size()) throw std::invalid_argument("trailing");
            if (v < 0) v = 0;
            if (v > 600000) v = 600000; // cap to 10 minutes
            args.timeout_ms = static_cast<int>(v);
        } catch (...) {
            // keep default on parse error
        }
    }
    args.report_base = parse_flag(argc, argv, "--report-base", args.report_base);
    args.log_path = parse_flag(argc, argv, "--log", args.log_path);
    args.quiet = has_flag(argc, argv, "--quiet");

    // Initialize logging
    logging::global().to_console = !args.quiet;
    logging::global().open(args.log_path);
    logging::info(std::string("start rules=") + args.rules + " root=" + args.root);

    // Validate inputs
    namespace fs = std::filesystem;
    if (!fs::exists(args.rules)) {
        logging::error("rules not found: " + args.rules);
        std::cerr << "Error: rules not found: " << args.rules << "\n";
        return 2;
    }
    if (!fs::exists(args.root) || !fs::is_directory(args.root)) {
        logging::error("root directory invalid: " + args.root);
        std::cerr << "Error: root directory invalid: " << args.root << "\n";
        return 3;
    }
    if (args.timeout_ms > 600000) { // clamp to 10 minutes
        logging::warn("timeout too large, clamped to 600000");
        args.timeout_ms = 600000;
    }

    auto exts = split_exts(args.exts);
    Report report;
    report.rule_path = args.rules;
    report.root_dir = args.root;

    try {
        YaraEngine ye;
        ye.compile_file(args.rules);

        auto t0 = std::chrono::steady_clock::now();
        auto files = traverse::list_files(args.root, exts);

        for (const auto& f : files) {
            std::vector<YaraMatch> matches;
            ye.scan_file(f.string(), matches, 0, args.timeout_ms);

            report.stats.files_scanned++;
            if (matches.empty()) continue;

            for (const auto& m : matches) {
                report.matches.push_back({ m.rule, f.string() });
                report.stats.matches++;
                if (!args.quiet) {
                    std::cout << "[MATCH] rule=" << m.rule << " file=" << f.string() << "\n";
                }
                logging::info(std::string("match rule=") + m.rule + " file=" + f.string());
            }
        }

        auto t1 = std::chrono::steady_clock::now();
        report.stats.duration_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

        // Write reports
        Report::write_all(report, args.report_dir, args.report_base);
        logging::info("done files_scanned=" + std::to_string(report.stats.files_scanned) +
                      " matches=" + std::to_string(report.stats.matches) +
                      " duration_ms=" + std::to_string(report.stats.duration_ms));

        // Final human summary
        if (!args.quiet) {
            std::cout << "Files scanned: " << report.stats.files_scanned << "\n";
            std::cout << "Matches: " << report.stats.matches << "\n";
            std::cout << "Reports: " << (std::filesystem::path(args.report_dir) / (args.report_base + ".json")).string()
                      << " and .csv\n";
        }

        return report.stats.matches > 0 ? 0 : 0;
    } catch (const std::exception& e) {
        logging::error(std::string("fatal: ") + e.what());
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
