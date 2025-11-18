#pragma once
#include <yara.h>
#ifdef ERROR
#undef ERROR
#endif
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

    void compile_file(const std::string& rule_path);
    void scan_file(const std::string& file_path, std::vector<YaraMatch>& results, int flags = 0, int timeout = 0) const;

private:
    YR_COMPILER* compiler_ = nullptr;
    YR_RULES* rules_ = nullptr;
};
