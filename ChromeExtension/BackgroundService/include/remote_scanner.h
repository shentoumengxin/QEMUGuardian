// remote_scanner.h

#ifndef REMOTE_SCANNER_H
#define REMOTE_SCANNER_H

#include <string>
#include "common.h"
// Global map to store pending file details for user decisions
// This should still be in main.cpp if main.cpp is the central orchestrator
// But if remote_scanner needs to read/write to it, it needs to be accessible
// For now, let's keep it in main.cpp and pass necessary data.
// Or, for clarity, if only remote_scanner updates/reads, it can be here.
// Let's assume it's still managed by main.cpp's context, but we will adjust
// perform_remote_scan_and_notify to pass relevant data.

// Function declarations
void initialize_remote_scanner();
void cleanup_remote_scanner();

std::string save_report_to_Log(const std::string &full_text_report, const std::string &isolated_file_path);

// The main function to perform remote scan and notify the browser
void perform_remote_scan_and_notify(const PendingFileDetails &pendingFileDetail);


struct ParsedScanResult {
    std::string status;       // "clean", "malicious", "suspicious", "pending", "error"
    std::string details;      // Detailed message for the browser
    bool completed = false;   // True if analysis is definitively complete (even if error)
};

ParsedScanResult parse_analysis_report(const std::string& full_text_report, const std::string& filename, const std::string& job_id);

#endif // REMOTE_SCANNER_H