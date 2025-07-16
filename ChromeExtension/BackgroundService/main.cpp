#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <stdexcept>
#include <filesystem> // C++17 for file system operations
#include <algorithm>

#include "common.h"
#include "native_messaging.h"
#include "remote_scanner.h"

std::map<std::string, PendingFileDetails> g_pendingFileDetails;

// Function to get the directory of the current executable
std::filesystem::path get_executable_directory() {
    char buffer[MAX_PATH]; // MAX_PATH is a Windows macro. For Linux/macOS, consider PATH_MAX or platform-specific APIs.
    #ifdef _WIN32
        GetModuleFileName(NULL, buffer, MAX_PATH);
    #else
        // For Linux, readlink("/proc/self/exe", ...) or for macOS, _NSGetExecutablePath.
        // For this cross-platform example, we'll simplify and assume current_path() for non-Windows,
        // but in a production app, you'd use proper platform-specific API.
        return std::filesystem::current_path();
    #endif
    return std::filesystem::path(buffer).parent_path();
}

// Handler for messages received from the browser via Native Messaging
void handle_browser_message(const nlohmann::json& message) {
    std::cerr << "--- RECEIVED MESSAGE FROM BROWSER ---" << std::endl;
    std::cerr << "Message type: " << message.value("type", "N/A") << std::endl;
    std::cerr << "Full message content (dumped):" << std::endl;
    std::cerr << message.dump(4) << std::endl;

    std::string message_type_str = message.value("type", "");
    MessageType message_type = stringToMessageType(message_type_str); // Convert string to enum

    // --- Using switch statement with enum ---
    switch (message_type) {
        case MessageType::INITIATE_FILE_ISOLATION: {
            std::string downloaded_file_full_path_str = message.value("filename", "unknown"); 
            
            // Convert string paths to std::filesystem::path for easier manipulation
            std::filesystem::path downloaded_file_path(downloaded_file_full_path_str);

            std::string filename = downloaded_file_path.filename().string();

            std::string custom_isolation_path_str = message.value("isolationPath", ""); 
            std::string notificationId = message.value("notificationId", ""); // Get notification ID from browser
 
            std::cerr << "Received download completion for: " << filename << std::endl;
            std::cerr << "Original download path: " << downloaded_file_full_path_str << std::endl;

            if (!custom_isolation_path_str.empty()) {
                std::cerr << "Custom isolation path requested: " << custom_isolation_path_str << std::endl;
            }
            
            std::filesystem::path actual_isolated_dir;
            if (custom_isolation_path_str.empty()) {
                actual_isolated_dir = get_executable_directory() / ".isolated";
                std::cerr << "Using default isolation directory: " << actual_isolated_dir << std::endl;
            } else {
                actual_isolated_dir = custom_isolation_path_str;
                std::cerr << "Using custom isolation directory: " << actual_isolated_dir << std::endl;
            }
            
            std::filesystem::path isolated_file_path = actual_isolated_dir / downloaded_file_path.filename(); 
            
            nlohmann::json response_to_browser;
            response_to_browser["type"] = "ISOLATION_STATUS";
            response_to_browser["filename"] = filename;
            response_to_browser["originalDownloadPath"] = downloaded_file_full_path_str;
            response_to_browser["isolatedPath"] = isolated_file_path.string();
            response_to_browser["requestedIsolationPath"] = custom_isolation_path_str;
            response_to_browser["notificationId"] = notificationId;

            std::string path_validation_error;
            if (!validateAndCheckWritePermission(actual_isolated_dir, path_validation_error)) {
                std::cerr << "ERROR: Isolation path re-validation failed during ISOLATE_AND_SCAN_FILE: " << path_validation_error << std::endl;
                response_to_browser["status"] = "failed";
                response_to_browser["details"] = "Isolation path invalid or no permissions: " + path_validation_error;
                send_message_to_browser(response_to_browser);
                break;
            }

            // Move the original downloaded file to the .isolated directory
            try {
                if (std::filesystem::exists(isolated_file_path)) {
                    std::cerr << "Removing pre-existing file in isolation: " << isolated_file_path << std::endl;
                    std::filesystem::remove(isolated_file_path);
                }

                std::cerr << "Attempting to move original file from " << downloaded_file_path << " to " << isolated_file_path << std::endl;
                std::filesystem::rename(downloaded_file_path, isolated_file_path);
                std::cerr << "SUCCESS: Original file moved to isolation." << std::endl;
                response_to_browser["status"] = "successful";
                response_to_browser["details"] = "File successfully moved to isolation.";

                // We pass a copy of the strings to the thread to avoid lifetime issues.

                PendingFileDetails pendingFileDetail;
                pendingFileDetail.originalDownloadPath = downloaded_file_full_path_str;
                pendingFileDetail.isolatedFilePath = isolated_file_path.string();
                pendingFileDetail.filename = filename;
                pendingFileDetail.notificationId = notificationId;

                g_pendingFileDetails[notificationId] = pendingFileDetail;

                std::thread scan_thread(perform_remote_scan_and_notify, 
                                        pendingFileDetail);
                scan_thread.detach();


            } catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "ERROR: Failed to move original file to isolation: " << e.what() << std::endl;
                response_to_browser["status"] = "failed";
                response_to_browser["details"] = "Failed to move original file to isolation: " + std::string(e.what());
            } catch (const std::exception& e) {
                std::cerr << "GENERAL ERROR during file move: " << e.what() << std::endl;
                response_to_browser["status"] = "failed";
                response_to_browser["details"] = "General error during file move: " + std::string(e.what());
            }

            send_message_to_browser(response_to_browser);
            break;
        }

        case MessageType::FILE_ACTION_DECISION: {
            std::string action = message.value("action", ""); // "delete", "isolate", "restore"
            std::string notificationId = message.value("notificationId", "");

            nlohmann::json response_to_browser;
            response_to_browser["type"] = "ACTION_DECISION_STATUS";
            response_to_browser["notificationId"] = notificationId;
            response_to_browser["actionPerformed"] = action;

            auto it = g_pendingFileDetails.find(notificationId);

            if (it == g_pendingFileDetails.end()) {
                std::cerr << "ERROR: No pending file details found for notificationId: " << notificationId << std::endl;
                response_to_browser["status"] = "failed";
                response_to_browser["details"] = "No pending file details found for this decision.";
                send_message_to_browser(response_to_browser);
                break;
            }

            PendingFileDetails fileDetails = it->second; // Get a copy
            g_pendingFileDetails.erase(it); // Remove from pending after action

            std::filesystem::path isolated_file_path(fileDetails.isolatedFilePath);
            std::filesystem::path original_download_path(fileDetails.originalDownloadPath);
            std::filesystem::path original_file_name_path = original_download_path.filename(); // Just the filename

            try {
                if (action == "delete") {
                    if (std::filesystem::exists(isolated_file_path)) {
                        std::filesystem::remove(isolated_file_path);
                        std::cerr << "File deleted: " << isolated_file_path << std::endl;
                        response_to_browser["status"] = "success";
                        response_to_browser["details"] = "File successfully deleted from isolation.";
                    } else {
                        response_to_browser["status"] = "failed";
                        response_to_browser["details"] = "File not found in isolation for deletion.";
                    }
                } else if (action == "isolate") {
                    // File is already in isolated path, confirm this.
                    if (std::filesystem::exists(isolated_file_path)) {
                        std::cerr << "File confirmed to remain in isolation: " << isolated_file_path << std::endl;
                        response_to_browser["status"] = "success";
                        response_to_browser["details"] = "File remains in isolation as requested.";
                    } else {
                        response_to_browser["status"] = "failed";
                        response_to_browser["details"] = "File not found in isolation to confirm.";
                    }
                } else if (action == "restore") {
                    // Reconstruct the full original path including filename
                    std::filesystem::path final_original_path = original_download_path;

                    // Ensure target directory for restoration exists and is writable
                    std::string restore_validation_error;
                    if (!validateAndCheckWritePermission(final_original_path.parent_path(), restore_validation_error)) {
                        response_to_browser["status"] = "failed";
                        response_to_browser["details"] = "Cannot restore: target directory invalid or not writable: " + restore_validation_error;
                        send_message_to_browser(response_to_browser);
                        break;
                    }

                    if (std::filesystem::exists(final_original_path)) {
                        std::cerr << "Removing existing file at original download location: " << final_original_path << std::endl;
                        std::filesystem::remove(final_original_path);
                    }

                    if (std::filesystem::exists(isolated_file_path)) {
                        std::filesystem::rename(isolated_file_path, final_original_path);
                        std::cerr << "File restored to original location: " << final_original_path << std::endl;
                        response_to_browser["status"] = "success";
                        response_to_browser["details"] = "File successfully restored to original download location.";
                        response_to_browser["restoredPath"] = final_original_path.string();
                    } else {
                        response_to_browser["status"] = "failed";
                        response_to_browser["details"] = "File not found in isolation to restore.";
                    }
                } else {
                    response_to_browser["status"] = "failed";
                    response_to_browser["details"] = "Unknown action requested: " + action;
                }
            } catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "Filesystem error during action '" << action << "': " << e.what() << std::endl;
                response_to_browser["status"] = "failed";
                response_to_browser["details"] = "Filesystem error during action: " + std::string(e.what());
            } catch (const std::exception& e) {
                std::cerr << "General error during action '" << action << "': " << e.what() << std::endl;
                response_to_browser["status"] = "failed";
                response_to_browser["details"] = "General error during action: " + std::string(e.what());
            }
            send_message_to_browser(response_to_browser);
            break;
        }


        case MessageType::UPDATE_ISOLATION_PATH: {
            std::string old_path_str = message.value("oldPath", ""); // Get old path
            std::string new_path_str = message.value("newPath", "");
            nlohmann::json response_to_browser;
            response_to_browser["type"] = "UPDATE_ISOLATION_PATH_STATUS";
            response_to_browser["requestedOldPath"] = old_path_str;
            response_to_browser["requestedNewPath"] = new_path_str;

            std::filesystem::path new_path_fs = normalizeIsolationPath(new_path_str);
            std::filesystem::path old_path_fs = normalizeIsolationPath(old_path_str);

            // Determine the actual old default path if old_path_str was empty (meaning default was used)
            if (old_path_str.empty()) {
                old_path_fs = get_executable_directory() / ".isolated";
                response_to_browser["resolvedOldPath"] = old_path_fs.string();
            }

            // Determine the actual new default path if new_path_str is empty
            std::filesystem::path actual_new_path_fs = new_path_fs;
            if (new_path_str.empty()) {
                actual_new_path_fs = get_executable_directory() / ".isolated";
                response_to_browser["resolvedNewPath"] = actual_new_path_fs.string();
            }
            
            std::string validation_error_message;
            int moved_file_count = 0;
            std::string move_details;

            // 1. Validate and check permission for the new path
            if (!validateAndCheckWritePermission(actual_new_path_fs, validation_error_message)) {
                std::cerr << "New isolation path '" << new_path_str << "' validation failed: " << validation_error_message << std::endl;
                response_to_browser["status"] = "failed";
                response_to_browser["details"] = "New path validation failed: " + validation_error_message;
                send_message_to_browser(response_to_browser);
                break;
            }

            // 2. If new path is valid, attempt to move contents from old path (if different and exists)
            if (!old_path_str.empty() || std::filesystem::exists(old_path_fs)) { // Only proceed if old path was set or its resolved default exists
                // Crucial check: Don't move if paths are the same or new path is a sub-directory of old
                if (std::filesystem::equivalent(old_path_fs, actual_new_path_fs)) {
                    response_to_browser["status"] = "success";
                    response_to_browser["details"] = "New path is same as old path. No move needed. Path validated successfully.";
                } else if (actual_new_path_fs.string().rfind(old_path_fs.string(), 0) == 0 && actual_new_path_fs.string().length() > old_path_fs.string().length()) {
                    // new path starts with old path and is longer (i.e., new path is a sub-directory of old)
                    // This is generally unsafe for moving, as it can lead to infinite recursion or data loss.
                    response_to_browser["status"] = "failed";
                    response_to_browser["details"] = "New isolation path is a subdirectory of the old path. Move operation aborted to prevent data loss or infinite recursion.";
                } else {
                    std::cerr << "Attempting to move contents from " << old_path_fs << " to " << actual_new_path_fs << std::endl;
                    if (move_directory_contents(old_path_fs, actual_new_path_fs, move_details, moved_file_count)) {
                        response_to_browser["status"] = "success";
                        response_to_browser["details"] = "Isolation path updated. " + move_details + " Moved " + std::to_string(moved_file_count) + " items.";
                        response_to_browser["movedCount"] = moved_file_count;
                    } else {
                        response_to_browser["status"] = "failed";
                        response_to_browser["details"] = "Failed to move old isolation directory contents: " + move_details;
                    }
                }
            } else {
                // No old path or old default path didn't exist, just validate new path
                response_to_browser["status"] = "success";
                response_to_browser["details"] = "Isolation path validated successfully. No old directory to move.";
            }
            send_message_to_browser(response_to_browser);
            break;
        }

        case MessageType::UNKNOWN:
        default: { // Handle any unknown or unrecognized message types
            std::cerr << "Unknown message type received: " << message_type_str << std::endl;
            nlohmann::json echo_response;
            echo_response["status"] = "unrecognized_message";
            echo_response["original_message"] = message;
            send_message_to_browser(echo_response);
            break; // End of UNKNOWN/default case
        }
    }

}

// Stub listener handler remains unchanged

int main() {
    // --- Print Welcome and Debug Info to STDERR ---
    std::cerr << "========================================" << std::endl;
    std::cerr << "  Secure Scan Native Host (Isolator)    " << std::endl;
    std::cerr << "========================================" << std::endl;
    std::cerr << "Native Host Name: " << NATIVE_HOST_NAME << std::endl;
#ifdef _WIN32
    std::cerr << "Process ID: " << GetCurrentProcessId() << std::endl; 
#endif
    std::cerr << "Listening for browser messages on stdin..." << std::endl;


    // --- IMPORTANT FOR WINDOWS: Set stdin and stdout to binary mode ---
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
        std::cerr << "ERROR: Could not set stdin to binary mode. Exiting." << std::endl;
        return 1;
    }
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
        std::cerr << "ERROR: Could not set stdout to binary mode. Exiting." << std::endl;
        return 1;
    }
#endif

    // --- Ensure C++ streams are not buffered and tied for immediate communication ---
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    // --- Start Native Messaging Listener ---
    start_native_messaging_listener(handle_browser_message);
    std::cerr << "Native Messaging listener initialized." << std::endl;

    // --- Main thread keeps running ---
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    return 0;
}