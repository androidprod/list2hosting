#pragma once
#include <mutex>
#include <chrono>
#include <ctime>
#include <cstdarg>
#include <cstdio>
#include <atomic>
#ifdef _WIN32
#include <windows.h>
#endif
// Ensure common short names are not pre-defined by platform headers
#ifdef DBG
#undef DBG
#endif
#ifdef INF
#undef INF
#endif
#ifdef WARN
#undef WARN
#endif
#ifdef ERR
#undef ERR
#endif
// Simple log level constants used across the codebase
enum { DBG = 0, INF = 1, WARN = 2, ERR = 3 };
inline std::mutex log_mtx;
// When true, logger will reprint the interactive prompt after emitting a log line.
inline std::atomic<bool> interactive_mode{false};
inline void logf(int level, const char* fmt, ...){
	std::lock_guard<std::mutex> lk(log_mtx);
	auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); std::tm tm;
#ifdef _WIN32
	localtime_s(&tm, &t);
#else
	localtime_r(&t, &tm);
#endif
	char tb[20]; std::strftime(tb, sizeof(tb), "%F %T", &tm);
	va_list ap; va_start(ap, fmt); char b[2048]; vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);

	// Initialize console to UTF-8 / enable ANSI VT sequences on Windows (once)
	#ifdef _WIN32
	static bool _logger_init = false;
	if (!_logger_init) {
		_logger_init = true;
		SetConsoleOutputCP(CP_UTF8);
		SetConsoleCP(CP_UTF8);
		HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD m = 0;
		if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &m)) SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}
	#endif

	const char* level_name = "";
	const char* color = "0"; // default
	switch (level) {
	case 0: level_name = "DBG"; color = "90"; break; // bright black / gray
	case 1: level_name = "INF"; color = "32"; break; // green
	case 2: level_name = "WARN"; color = "33"; break; // yellow
	case 3: level_name = "ERR"; color = "31"; break; // red
	default: level_name = "LOG"; color = "0"; break;
	}

	// Print timestamp, colored level tag, then message
	std::printf("[%s] \x1b[%sm%s\x1b[0m %s\n", tb, color, level_name, b);

	// If interactive mode is active, reprint the prompt so user can continue typing.
	if (interactive_mode.load()) {
		std::fflush(stdout);
		std::fputs("list2hosting> ", stdout);
		std::fflush(stdout);
	}
}