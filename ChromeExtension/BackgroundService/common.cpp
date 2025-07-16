#include "common.h"
#include "native_messaging.h"

MessageType stringToMessageType(const std::string& type_str) {
    auto it = MESSAGE_TYPE_MAP.find(type_str);
    if (it != MESSAGE_TYPE_MAP.end()) {
        return it->second;
    }
    return MessageType::UNKNOWN;
}

bool validateAndCheckWritePermission(const std::filesystem::path& target_path, std::string& errorMessage) {
    if (target_path.empty()) {
        errorMessage = "Isolation path cannot be empty.";
        return false;
    }

    try {
        // 1. Create directory if it doesn't exist
        if (!std::filesystem::exists(target_path)) {
            std::cerr << "Creating directory: " << target_path << std::endl;
            std::filesystem::create_directories(target_path);
        } else if (!std::filesystem::is_directory(target_path)) {
            // Path exists but is not a directory
            errorMessage = "Path exists but is not a directory.";
            return false;
        }

        // 2. Check write permission by attempting to create/write a temporary file
        std::filesystem::path temp_file_path = target_path / ("temp_check_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()));
        std::ofstream ofs(temp_file_path.string());
        if (!ofs.is_open()) {
            errorMessage = "Failed to open temporary file for writing. Possible permission denied.";
            return false;
        }
        ofs << "test";
        ofs.close();
        std::filesystem::remove(temp_file_path); // Clean up temp file
        std::cerr << "Write permission confirmed for: " << target_path << std::endl;
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        errorMessage = "Filesystem error: " + std::string(e.what());
        return false;
    } catch (const std::exception& e) {
        errorMessage = "General error during path validation: " + std::string(e.what());
        return false;
    }
}


// Returns true on success, false on failure, and populates details and moved_count
bool move_directory_contents(const std::filesystem::path& source_dir, const std::filesystem::path& dest_dir, std::string& details, int& moved_count) {
    moved_count = 0;
    std::string error_details;

    if (!std::filesystem::exists(source_dir) || !std::filesystem::is_directory(source_dir)) {
        details = "Source directory does not exist or is not a directory: " + source_dir.string();
        return true; // Not an error if source doesn't exist, just nothing to move
    }

    if (std::filesystem::equivalent(source_dir, dest_dir)) {
        details = "Source and destination directories are the same. No move needed.";
        return true; // No error, just skip
    }

    // Ensure destination directory exists and is writable
    if (!validateAndCheckWritePermission(dest_dir, error_details)) {
        details = "Destination directory invalid or not writable: " + error_details;
        return false;
    }

    try {
        for (const auto& entry : std::filesystem::directory_iterator(source_dir)) {
            std::filesystem::path current_path = entry.path();
            std::filesystem::path dest_path = dest_dir / current_path.filename();

            // Handle potential conflicts: if dest_path exists, remove it if it's a file, or if it's an empty dir.
            // For non-empty directories, this might require more complex merge logic.
            // Here, we assume direct overwrite for files, and recursive copy for subdirectories.
            if (std::filesystem::exists(dest_path)) {
                if (std::filesystem::is_regular_file(current_path) && std::filesystem::is_regular_file(dest_path)) {
                    std::cerr << "Removing existing file at destination: " << dest_path << std::endl;
                    std::filesystem::remove(dest_path);
                } else if (std::filesystem::is_directory(current_path) && std::filesystem::is_directory(dest_path)) {
                    // For subdirectories, recursively move contents, don't remove existing
                    std::string sub_details;
                    int sub_moved_count = 0;
                    if (!move_directory_contents(current_path, dest_path, sub_details, sub_moved_count)) {
                        details = "Failed to move subdirectory contents: " + sub_details;
                        return false;
                    }
                    moved_count += sub_moved_count;
                    // If subdirectory is now empty, remove it
                    if (std::filesystem::is_empty(current_path)) {
                        std::filesystem::remove(current_path);
                    }
                    continue; // Skip move for the directory itself, contents handled
                } else {
                    // Mismatch (file to dir, dir to file) or unhandled type
                    details = "Conflict at destination: " + dest_path.string() + " (type mismatch or unhandled).";
                    return false;
                }
            }

            std::cerr << "Moving: " << current_path << " to " << dest_path << std::endl;
            std::filesystem::rename(current_path, dest_path);
            moved_count++;
        }
        // After moving all contents, remove the source directory if it's empty
        if (std::filesystem::is_empty(source_dir)) {
             std::filesystem::remove(source_dir);
        }
        details = "Contents moved successfully.";
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        details = "Filesystem error during move: " + std::string(e.what());
        return false;
    } catch (const std::exception& e) {
        details = "General error during move: " + std::string(e.what());
        return false;
    }
}

// If the path is not empty and doesn't end with ".isolated", append it.
std::filesystem::path normalizeIsolationPath(const std::string& user_path_str) {
    if (user_path_str.empty()) {
        // If user provides empty string, it means use the default .isolated in exe dir.
        // We return an empty path here, and the calling function will handle the default.
        return std::filesystem::path();
    }

    std::filesystem::path path_obj(user_path_str);
    std::string filename_str = path_obj.filename().string(); // Get the last component of the path

    if (filename_str != ".isolated") { // Check if the last component is exactly ".isolated"
        path_obj /= ".isolated"; // Append if not
    }
    return path_obj;
}

