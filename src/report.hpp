#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <cstdio>
#include <cstdint>
#include <sstream>

struct ScanMatch {
    std::string rule;
    std::string file;
};

struct ScanStats {
    uint64_t files_scanned = 0;
    uint64_t matches = 0;
    uint64_t errors = 0;
    uint64_t skipped = 0;
    uint64_t duration_ms = 0;
};

struct Report {
    std::vector<ScanMatch> matches;
    ScanStats stats;
    std::string rule_path;
    std::string root_dir;

    static void write_all(const Report& r, const std::filesystem::path& out_dir, const std::string& base) {
        std::filesystem::create_directories(out_dir);
        write_json(r, out_dir / (base + ".json"));
        write_csv(r, out_dir / (base + ".csv"));
    }

    static void write_json(const Report& r, const std::filesystem::path& p) {
        FILE* f = std::fopen(p.string().c_str(), "wb");
        if (!f) return;
        std::fprintf(f, "{\n");
        std::fprintf(f, "  \"rule_path\": \"%s\",\n", escape(r.rule_path).c_str());
        std::fprintf(f, "  \"root_dir\": \"%s\",\n", escape(r.root_dir).c_str());
        std::fprintf(f, "  \"stats\": {\"files_scanned\": %llu, \"matches\": %llu, \"errors\": %llu, \"skipped\": %llu, \"duration_ms\": %llu},\n",
            (unsigned long long)r.stats.files_scanned, (unsigned long long)r.stats.matches, (unsigned long long)r.stats.errors,
            (unsigned long long)r.stats.skipped, (unsigned long long)r.stats.duration_ms);
        std::fprintf(f, "  \"matches\": [\n");
        for (size_t i = 0; i < r.matches.size(); ++i) {
            const auto& m = r.matches[i];
            std::fprintf(f, "    {\"rule\": \"%s\", \"file\": \"%s\"}%s\n",
                escape(m.rule).c_str(), escape(m.file).c_str(), (i + 1 == r.matches.size()) ? "" : ",");
        }
        std::fprintf(f, "  ]\n}\n");
        std::fclose(f);
    }

    static void write_csv(const Report& r, const std::filesystem::path& p) {
        FILE* f = std::fopen(p.string().c_str(), "wb");
        if (!f) return;
        std::fprintf(f, "rule,file\n");
        for (const auto& m : r.matches) {
            std::fprintf(f, "\"%s\",\"%s\"\n", escape(m.rule).c_str(), escape(m.file).c_str());
        }
        std::fclose(f);
    }

  private:
    static std::string escape(const std::string& s) {
        std::ostringstream o;
        for (unsigned char c : s) {
            switch (c) {
                case '\\': o << "\\\\"; break;
                case '\"': o << "\\\""; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default: o << c; break;
            }
        }
        return o.str();
    }
};
