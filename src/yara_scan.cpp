#include "yara_scan.hpp"
#include "log.hpp"
#include <cstdio>
#include <utility>

namespace {

static int callback_fn(YR_SCAN_CONTEXT* /*ctx*/, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* rule = static_cast<YR_RULE*>(message_data);
        auto* out = static_cast<std::pair<std::vector<YaraMatch>*, const char*>*>(user_data);
        out->first->push_back({ rule->identifier, std::string(out->second) });
    }
    return CALLBACK_CONTINUE;
}

} // namespace

YaraEngine::YaraEngine() {
    int rc = yr_initialize();
    if (rc != ERROR_SUCCESS) throw std::runtime_error("yr_initialize failed");
}

YaraEngine::~YaraEngine() {
    if (rules_) yr_rules_destroy(rules_);
    if (compiler_) yr_compiler_destroy(compiler_);
    yr_finalize();
}

void YaraEngine::compile_file(const std::string& rule_path) {
    if (yr_compiler_create(&compiler_) != ERROR_SUCCESS)
        throw std::runtime_error("yr_compiler_create failed");

    FILE* f = std::fopen(rule_path.c_str(), "rb");
    if (!f) throw std::runtime_error("cannot open rules: " + rule_path);

    int add_res = yr_compiler_add_file(compiler_, f, nullptr, rule_path.c_str());
    std::fclose(f);
    if (add_res != 0) throw std::runtime_error("yara rule compilation failed");

    if (yr_compiler_get_rules(compiler_, &rules_) != ERROR_SUCCESS || !rules_)
        throw std::runtime_error("yr_compiler_get_rules failed");
}

void YaraEngine::scan_file(const std::string& file_path, std::vector<YaraMatch>& results, int flags, int timeout) const {
    if (!rules_) throw std::runtime_error("rules not compiled");

    std::pair<std::vector<YaraMatch>*, const char*> ctx = { &results, file_path.c_str() };
    int rc = yr_rules_scan_file(rules_, file_path.c_str(), flags, callback_fn, &ctx, timeout);
    if (rc != ERROR_SUCCESS) {
        logging::warn(std::string("scan error rc=") + std::to_string(rc) + " file=" + file_path);
        // Non-fatal: unreadable files or timeouts are skipped.
    }
}
