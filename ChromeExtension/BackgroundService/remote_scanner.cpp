// remote_scanner.cpp

#include "remote_scanner.h" // Include our own header first
#include "native_messaging.h"

#include <curl/curl.h>     // For HTTP requests
#include <iostream>        // For cerr/cout
#include <fstream>         // For file operations (if needed, e.g., for multipart form)
#include <chrono>          // For std::this_thread::sleep_for
#include <thread>          // For std::this_thread
#include <filesystem>      // For std::filesystem
#include <map>
#include <regex>
#include "json.hpp"



// IMPORTANT: send_message_to_browser must be defined in main.cpp or linked externally.
// It's declared in remote_scanner.h to be visible here.

// Callback function for writing received data from cURL
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Internal helper function to send file and get job_id
static std::string send_file_for_analysis_internal(const std::string& file_path, const std::string& upload_url) {
    CURL *curl;
    CURLcode res;
    std::string response_string;

    curl_mime *mime;
    curl_mimepart *part;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, upload_url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        
        // Build the multipart form data
        mime = curl_mime_init(curl);

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "exe_file"); // Form field name for the file
        curl_mime_filedata(part, file_path.c_str()); // The actual file content

        // Add filename if your server expects it as a separate part or header
        // For example, if server expects a 'filename' field:
        // part = curl_mime_addpart(mime);
        // curl_mime_name(part, "filename");
        // curl_mime_data(part, std::filesystem::path(file_path).filename().string().c_str());

        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        // Debugging options
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed during upload: " << curl_easy_strerror(res) << std::endl;
            response_string = "{ \"error\": \"Upload failed\", \"details\": \"" + std::string(curl_easy_strerror(res)) + "\" }";
        } else {
            std::cerr << "File upload response: " << response_string << std::endl;
        }
        
        curl_easy_cleanup(curl);
        curl_mime_free(mime);
    } else {
        response_string = "{ \"error\": \"cURL init failed\" }";
    }
    return response_string;
}

// Internal helper function to get analysis report
static std::string get_analysis_report_internal(const std::string& job_id, const std::string& report_base_url) {
    CURL *curl;
    CURLcode res;
    std::string report_url = report_base_url + job_id + "/";
    std::string response_string;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, report_url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects if -L is used in curl command
        
        // Debugging options
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed during report fetch: " << curl_easy_strerror(res) << std::endl;
            response_string = "{ \"error\": \"Report fetch failed\", \"details\": \"" + std::string(curl_easy_strerror(res)) + "\" }";
        } else {
            std::cerr << "Report response: " << response_string << std::endl;
        }
        
        curl_easy_cleanup(curl);
    } else {
        response_string = "{ \"error\": \"cURL init failed\" }";
    }
    return response_string;
}

// Initialize cURL library
void initialize_remote_scanner() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    std::cerr << "cURL global initialized." << std::endl;
}

// Cleanup cURL library
void cleanup_remote_scanner() {
    curl_global_cleanup();
    std::cerr << "cURL global cleaned up." << std::endl;
}


// The main function to perform remote scan and notify the browser
void perform_remote_scan_and_notify(const PendingFileDetails &pendingFileDetail) 
{
    const std::string &downloaded_file_full_path_str = pendingFileDetail.originalDownloadPath;
    const std::string &isolated_file_path_str = pendingFileDetail.isolatedFilePath;
    const std::string &filename = pendingFileDetail.filename;
    const std::string &notificationId = pendingFileDetail.notificationId;

    std::cerr << "[Remote Scan Thread] Sending file for analysis: " << filename << std::endl;

    // Define your analysis and report URLs here
    const std::string ANALYZE_URL = "http://xxbaicz.online:8081/analyze/";
    const std::string REPORT_BASE_URL = "http://xxbaicz.online:8081/report/";

    std::string upload_response = send_file_for_analysis_internal(isolated_file_path_str, ANALYZE_URL);
    
    std::string scan_result = "error";
    std::string result_details = "Failed to upload file or get job ID.";
    std::string job_id = "";

    try {
        nlohmann::json upload_json = nlohmann::json::parse(upload_response);
        if (upload_json.contains("job_id") && upload_json["job_id"].is_string()) {
            job_id = upload_json["job_id"].get<std::string>();
            std::cerr << "[Remote Scan Thread] Received job_id: " << job_id << std::endl;
            result_details = "File uploaded. Waiting for analysis report. Job id: " + job_id;
            scan_result = "pending"; // Or another status for in-progress
        } 
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "[Remote Scan Thread] JSON parse error on upload response: " << e.what() << std::endl;
        result_details = "Invalid JSON response from analyze endpoint: " + std::string(e.what());
    } catch (const std::exception& e) {
        std::cerr << "[Remote Scan Thread] Error processing upload response: " << e.what() << std::endl;
        result_details = "Error processing upload response: " + std::string(e.what());
    }

    // Immediately notify browser of upload status / pending status
    nlohmann::json upload_status_response;
    upload_status_response["type"] = "SCAN_RESULT"; // Reuse SCAN_RESULT type for initial feedback
    upload_status_response["status"] = scan_result; // "pending" or "error"
    upload_status_response["details"] = result_details;
    upload_status_response["filename"] = filename;
    upload_status_response["originalDownloadPath"] = downloaded_file_full_path_str;
    upload_status_response["isolatedPath"] = isolated_file_path_str;
    upload_status_response["notificationId"] = notificationId;
    send_message_to_browser(upload_status_response); // Assuming send_message_to_browser is accessible

    if (job_id.empty() || scan_result == "error") { // If upload failed or no job_id, stop here
        std::cerr << "[Remote Scan Thread] No valid job_id obtained or upload failed, skipping report retrieval." << std::endl;
        return;
    }

    // --- Poll for report ---
    ParsedScanResult parsed_result;
    bool report_received = false;
    int retry_count = 0;
    const int MAX_RETRIES = 3; // Max attempts to get the report
    const std::chrono::seconds RETRY_INTERVAL(5); // Wait 5 seconds between retries

    while (!report_received && retry_count < MAX_RETRIES) {
        std::cerr << "[Remote Scan Thread] Attempting to get report for job_id: " << job_id << " (Attempt " << retry_count + 1 << "/" << MAX_RETRIES << ")" << std::endl;
        std::this_thread::sleep_for(RETRY_INTERVAL);

        std::string full_text_report = get_analysis_report_internal(job_id, REPORT_BASE_URL);
        
        if( full_text_report.find("Monitor terminated.") == std::string::npos ) {
            retry_count++;
            continue;
        }
        
        // Call the new parsing function
        parsed_result = parse_analysis_report(full_text_report, filename, job_id);
        scan_result = parsed_result.status;
        result_details = parsed_result.details;

        report_received = true;
    }

    if (!report_received) {
        scan_result = "error";
        result_details = "Failed to retrieve analysis report after multiple attempts for job_id: " + job_id;
    }
    
    // Send final SCAN_RESULT to browser
    nlohmann::json final_response_to_browser;
    final_response_to_browser["type"] = "SCAN_RESULT";
    final_response_to_browser["status"] = scan_result;
    final_response_to_browser["details"] = result_details;
    final_response_to_browser["filename"] = filename;
    final_response_to_browser["originalDownloadPath"] = downloaded_file_full_path_str;
    final_response_to_browser["isolatedPath"] = isolated_file_path_str;
    final_response_to_browser["notificationId"] = notificationId;
    
    send_message_to_browser(final_response_to_browser); // Assuming send_message_to_browser is accessible
    std::cerr << "[Remote Scan Thread] Final scan result sent to browser: " << scan_result << std::endl;
}

std::string preprocess_report_string(const std::string& raw_report) {
    std::string processed_report = raw_report;

    processed_report = std::regex_replace(processed_report, std::regex("'([^']+)'\\s*:\\s*'([^']*)'"), "\"$1\":\"$2\"");
    processed_report = std::regex_replace(processed_report, std::regex("'([^']+)'\\s*:\\s*(\\[|\\{)"), "\"$1\":$2"); // For keys mapping to objects/arrays
    processed_report = std::regex_replace(processed_report, std::regex("([\\{,])\\s*'([^']+)'\\s*:"), "$1\"$2\":"); // For object keys
    processed_report = std::regex_replace(processed_report, std::regex(":\\s*'([^']+)'"), ":\"$1\""); // For string values (after the colon)

    std::cerr << "[Preprocess] Raw: " << raw_report << std::endl;
    std::cerr << "[Preprocess] Processed: " << processed_report << std::endl;

    return processed_report;
}

ParsedScanResult parse_analysis_report(const std::string& full_text_report, const std::string& filename, const std::string& job_id) {
    ParsedScanResult result;
    result.status = "error"; // Default to error
    result.details = "Failed to parse report.";

    // 1. Check for immediate error JSON from HTTP fetch
    try {
        nlohmann::json error_check_json = nlohmann::json::parse(full_text_report);
        if (error_check_json.contains("error")) {
            result.status = "error";
            result.details = "Report fetch error: " + error_check_json.value("details", "Unknown error.");
            if (error_check_json.contains("code")) result.details += " (Code: " + error_check_json["code"].dump() + ")";
            result.completed = true; // Error received, so consider it done polling
            return result;
        }
    } catch (const nlohmann::json::parse_error& e) {
        // This means it's likely a full text report, continue to parse as text
    }

    // 2. Search for the embedded JSON
    std::string json_head = "[Result]";
    std::string json_start_marker = "{";
    std::string json_end_marker = "}";

    size_t json_head_pos = full_text_report.find(json_head);
    size_t json_start_pos = full_text_report.find(json_start_marker, json_head_pos);
    size_t json_end_pos = full_text_report.find(json_end_marker, json_start_pos);

    result.completed = true; 

    if (json_head_pos != std::string::npos && json_start_pos != std::string::npos && json_end_pos != std::string::npos) {
        std::string raw_json_str = full_text_report.substr(json_start_pos, json_end_pos - json_start_pos + json_end_marker.length());
        std::string embedded_json_str = preprocess_report_string(raw_json_str);
        std::cerr << "[Parse Report] Detected embedded JSON string: " << embedded_json_str << std::endl;

        

        try {
            nlohmann::json report_json = nlohmann::json::parse(embedded_json_str);

            double cvss_level = report_json.value("level", 0.0);
            std::string description = report_json.value("description", "No description provided.");
            std::string evidence = report_json.value("evidence", "No evidence provided.");
            
            if (cvss_level >= 9.0) { 
                result.status = "malicious";
                result.details = "Critical severity detected! " + description + ". Evidence: " + evidence;
            } else if (cvss_level >= 7.0) { 
                result.status = "malicious";
                result.details = "High severity detected! " + description + ". Evidence: " + evidence;
            } else if (cvss_level >= 4.0) { 
                result.status = "suspicious";
                result.details = "Medium severity detected. " + description + ". Evidence: " + evidence;
            } else if (cvss_level > 0.0) { 
                result.status = "suspicious";
                result.details = "Low severity detected. " + description + ". Evidence: " + evidence;
            } else { 
                result.status = "clean";
                result.details = "No critical threats detected. " + description + ". Evidence: " + evidence;
            }
            
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "[Parse Report] JSON parse error on embedded report JSON: " << e.what() << std::endl;
            result.status = "error";
            result.details = "Failed to parse embedded report JSON: " + std::string(e.what()) + ". Embedded JSON: " + embedded_json_str;
        } catch (const std::exception& e) {
            std::cerr << "[Parse Report] Error processing embedded report JSON: " << e.what() << std::endl;
            result.status = "error";
            result.details = "Error processing embedded report JSON: " + std::string(e.what());
        }
    } else if (full_text_report.find("Monitor terminated.") != std::string::npos) {
        result.status = "clean";
        result.details = "No critical threats detected. ";
    } else {
        result.status = "error";
        result.details = "Unknown report format or analysis stuck. Raw report (truncated): " + full_text_report.substr(0, std::min((size_t)500, full_text_report.length())) + "..."; 
    }
    return result;
}