// src/log.hpp
#pragma once
#include <cstdio>
#include <ctime>
#include <string>
#include <mutex>
#include <filesystem>

namespace logging {

enum class Level { Info, Warn, Error };

struct Logger {
    std::mutex mtx;
    FILE* file = nullptr;
    bool to_console = true;

    void open(const std::filesystem::path& path) {
        std::lock_guard<std::mutex> lk(mtx);
        std::filesystem::create_directories(path.parent_path());
        file = std::fopen(path.string().c_str(), "a");
    }

    static const char* level_str(Level lv) {
        switch (lv) { case Level::Info: return "INFO"; case Level::Warn: return "WARN"; default: return "ERROR"; }
    }

    static std::string now_iso8601();

    void log(Level lv, const std::string& msg);

    ~Logger() { if (file) std::fclose(file); }
};

inline std::string Logger::now_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return std::string(buf);
}

inline void Logger::log(Level lv, const std::string& msg) {
    std::lock_guard<std::mutex> lk(mtx);
    std::string line = now_iso8601() + " [" + level_str(lv) + "] " + msg + "\n";
    if (to_console) std::fwrite(line.data(), 1, line.size(), stdout);
    if (file) std::fwrite(line.data(), 1, line.size(), file);
}

inline Logger& global() { static Logger L; return L; }

inline void info(const std::string& m){ global().log(Level::Info, m); }
inline void warn(const std::string& m){ global().log(Level::Warn, m); }
inline void error(const std::string& m){ global().log(Level::Error, m); }

} // namespace logging
