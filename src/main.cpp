#include "traverse.hpp"
#include "yara_scan.hpp"
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <rules.yar> <folder_to_scan> [--ext=.exe,.dll]\n";
        return 1;
    }

    std::string rules = argv[1];
    std::filesystem::path root = argv[2];

    std::vector<std::string> exts;
    if (argc >= 4) {
        std::string arg = argv[3];
        const std::string prefix = "--ext=";
        if (arg.rfind(prefix, 0) == 0) {
            arg = arg.substr(prefix.size());
            size_t pos = 0;
            while (pos < arg.size()) {
                auto comma = arg.find(',', pos);
                exts.push_back(arg.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos));
                if (comma == std::string::npos) break;
                pos = comma + 1;
            }
        }
    }

    try {
        YaraEngine ye;
        ye.compile_file(rules);

        auto files = traverse::list_files(root, exts);
        std::vector<YaraMatch> matches;

        for (auto& f : files) {
            ye.scan_file(f.string(), matches, 0 /* flags */, 0 /* timeout */);
        }

        std::cout << "Files scanned: " << files.size() << "\n";
        for (auto& m : matches) {
            std::cout << "[MATCH] rule=" << m.rule << " file=" << m.file << "\n";
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 2;
    }
}
