#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <map>
#include <iostream>
#include <mutex>
#include <filesystem> // C++17 for file system operations
#include <fstream>

#include <thread>
#include <vector>     // For reading file into buffer
#include <iomanip>    // For std::hex, std::setfill, std::setw
#include <sstream>    // For std::stringstream
#include <random>     // NEW: For random number generation

#include "json.hpp"

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#else
// For non-Windows, you'd typically use OpenSSL for crypto functions or another library like CommonCrypto on macOS.
// For this example, we'll provide a placeholder. In a real application, implement this properly.
#endif



// Define the Native Host Name - MUST match your Chrome Extension's manifest.json
const std::string NATIVE_HOST_NAME = "com.nus_dada_group.guardian";

// Using enum class for strong typing
enum class MessageType {
    INITIATE_FILE_ISOLATION,   // Changed from ISOLATE_AND_SCAN_FILE
    FILE_ACTION_DECISION,      // New: User decision after remote scan (Delete, Isolate, Restore)
    UPDATE_ISOLATION_PATH,
    UNKNOWN
};

// --- Function to convert string to MessageType enum ---
static const std::map<std::string, MessageType> MESSAGE_TYPE_MAP = {
    {"INITIATE_FILE_ISOLATION", MessageType::INITIATE_FILE_ISOLATION},
    {"FILE_ACTION_DECISION", MessageType::FILE_ACTION_DECISION},
    {"UPDATE_ISOLATION_PATH", MessageType::UPDATE_ISOLATION_PATH}
};

MessageType stringToMessageType(const std::string &type_str);

bool validateAndCheckWritePermission(const std::filesystem::path &target_path, std::string &errorMessage);

std::filesystem::path normalizeIsolationPath(const std::string &user_path_str);

bool move_directory_contents(const std::filesystem::path &source_dir, const std::filesystem::path &dest_dir, std::string &details, int &moved_count);

struct PendingFileDetails {
    std::string originalDownloadPath;
    std::string isolatedFilePath; // The path where it was moved for isolation
    std::string filename;
    std::string notificationId; // Store the notification ID for context
};

extern std::map<std::string, PendingFileDetails> g_pendingFileDetails;
extern std::mutex g_pendingFileDetails_mutex; 


#endif // COMMON_H