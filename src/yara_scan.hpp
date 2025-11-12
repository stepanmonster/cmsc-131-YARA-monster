#pragma once
#include <yara.h>
#include <string>
#include <vector>

struct YaraMatch {
    std::string rule;
    std::string file;
};

class YaraEngine {
public:
    YaraEngine();
    ~YaraEngine();

    // Compile rules from a .yar file path; throws on error.
    void compile_file(const std::string& rule_path);

    // Scan a file path; appends any matches into results.
    void scan_file(const std::string& file_path, std::vector<YaraMatch>& results, int flags = 0, int timeout = 0) const;

private:
    YR_COMPILER* compiler_ = nullptr;
    YR_RULES* rules_ = nullptr;
};
