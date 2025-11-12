#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace traverse {
    // Recursively collect regular files under root; if exts is empty, take all.
    std::vector<std::filesystem::path>
    list_files(const std::filesystem::path& root,
               const std::vector<std::string>& exts = {});
}
