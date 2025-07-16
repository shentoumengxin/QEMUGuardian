#include "native_messaging.h"
#include <iostream>
#include <vector>
#include <thread>
#include <stdexcept>
#include <chrono> // For std::this_thread::sleep_for

// Function to send a JSON message to the browser via stdout
void send_message_to_browser(const nlohmann::json& message) {
    std::string message_str = message.dump();
    uint32_t message_length = message_str.length();

    // Send debug info to stderr (not part of NM protocol)
    std::cerr << "[NM Send] Preparing to send message (length " << message_length << "):" << std::endl;
    // std::cerr << message.dump(4) << std::endl; // Dump formatted JSON to stderr

    // Write message length (4 bytes) to stdout
    std::cout.write(reinterpret_cast<const char*>(&message_length), sizeof(message_length));
    // Write message content to stdout
    std::cout.write(message_str.c_str(), message_length);
    std::cout.flush(); // Ensure the message is sent immediately
    std::cerr << "[NM Send] Message sent to Chrome." << std::endl;
}

// Function to read a JSON message from the browser via stdin
nlohmann::json read_message_from_browser() {
    uint32_t message_length;
    
    // Read message length (4 bytes) from stdin
    std::cerr << "[NM Read] Attempting to read 4-byte message length..." << std::endl;
    std::cin.read(reinterpret_cast<char*>(&message_length), sizeof(message_length));

    if (std::cin.fail()) {
        if (std::cin.eof()) {
            std::cerr << "[NM Read] EOF reached on stdin. Browser likely disconnected." << std::endl;
            throw std::runtime_error("EOF reached on stdin. Browser likely disconnected.");
        } else {
            std::cerr << "[NM Read] Failed to read message length from stdin (fail bit set)." << std::endl;
            throw std::runtime_error("Failed to read message length from stdin.");
        }
    }
    std::cerr << "[NM Read] Read message length: " << message_length << " bytes." << std::endl;

    // Chrome limits messages TO host to 64MB, FROM host to 1MB. This check is for messages FROM browser.
    if (message_length == 0 || message_length > 1024 * 1024 * 64) { 
        std::cerr << "[NM Read] Invalid message length detected: " << message_length << " bytes." << std::endl;
        throw std::runtime_error("Invalid message length.");
    }

    // Read message content
    std::vector<char> message_buffer(message_length);
    std::cerr << "[NM Read] Attempting to read " << message_length << " bytes of message content..." << std::endl;
    std::cin.read(message_buffer.data(), message_length);

    if (std::cin.fail()) {
        std::cerr << "[NM Read] Failed to read message content from stdin." << std::endl;
        throw std::runtime_error("Failed to read message content.");
    }
    std::cerr << "[NM Read] Successfully read message content." << std::endl;

    // Parse JSON message
    try {
        nlohmann::json parsed_message = nlohmann::json::parse(message_buffer.begin(), message_buffer.end());
        std::cerr << "[NM Read] Successfully parsed JSON message." << std::endl;
        return parsed_message;
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "[NM Read] JSON parse error: " << e.what() << std::endl;
        throw std::runtime_error("JSON parse error: " + std::string(e.what()));
    }
}

// Thread function for Native Messaging listener
void native_messaging_listener_thread(std::function<void(const nlohmann::json&)> message_handler) {
    std::cerr << "[NM Listener] Native Messaging listener thread started." << std::endl;
    while (true) {
        try {
            nlohmann::json received_message = read_message_from_browser();
            // Call the handler function provided by main
            message_handler(received_message);
        } catch (const std::runtime_error& e) {
            std::cerr << "[NM Listener] Runtime error: " << e.what() << std::endl;
            break; // Break loop on critical errors like disconnect
        } catch (const std::exception& e) {
            std::cerr << "[NM Listener] General error: " << e.what() << std::endl;
            break; // Break loop on unexpected errors
        }
    }
    std::cerr << "[NM Listener] Native Messaging listener thread exiting." << std::endl;
}

// Function to start the Native Messaging listener in a separate thread
void start_native_messaging_listener(std::function<void(const nlohmann::json&)> message_handler) {
    std::thread nm_thread(native_messaging_listener_thread, message_handler);
    nm_thread.detach(); // Detach the thread to run independently
    std::cerr << "[NM] Native Messaging listener detached." << std::endl;
}