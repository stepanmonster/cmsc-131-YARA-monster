#include "traverse.hpp"
#include <system_error>

namespace fs = std::filesystem;

static bool match_ext(const fs::path& p, const std::vector<std::string>& exts) {
    if (exts.empty()) return true;
    auto e = p.extension().string();
#ifdef _WIN32
    auto ieq = [](char a, char b){ return tolower((unsigned char)a)==tolower((unsigned char)b); };
    for (auto& x : exts) {
        if (e.size()==x.size() && std::equal(e.begin(), e.end(), x.begin(), ieq)) return true;
    }
#else
    for (auto& x : exts) if (e == x) return true;
#endif
    return false;
}

std::vector<fs::path> traverse::list_files(const fs::path& root,
                                           const std::vector<std::string>& exts) {
    std::vector<fs::path> out;
    std::error_code ec;
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
    for (; it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        const auto& de = *it;
        if (!de.is_regular_file(ec)) { if (ec) ec.clear(); continue; }
        if (!match_ext(de.path(), exts)) continue;
        out.push_back(de.path());
    }
    return out;
}
