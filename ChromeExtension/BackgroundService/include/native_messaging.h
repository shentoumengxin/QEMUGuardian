#ifndef NATIVE_MESSAGING_H
#define NATIVE_MESSAGING_H

#include "json.hpp" // For nlohmann::json
#include <functional> // For std::function
#include <string>

// Function to send a JSON message to the browser via stdout
void send_message_to_browser(const nlohmann::json& message);

// Function to read a JSON message from the browser via stdin
nlohmann::json read_message_from_browser();

// Function to start the Native Messaging listener in a separate thread
// It takes a callback function to handle received messages
void start_native_messaging_listener(std::function<void(const nlohmann::json&)> message_handler);

#endif // NATIVE_MESSAGING_H