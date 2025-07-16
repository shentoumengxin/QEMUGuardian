// Define your Native Host's name
const NATIVE_HOST_NAME = "com.nus_dada_group.guardian";
const ISOLATION_PATH_STORAGE_KEY = "qemuGuardianIsolationPath"; // Key for storage

// Global variable to hold the Native Host port
let nativeHostPort = null;

// Helper function: Generate a unique notification ID
function generateUniqueNotificationId() {
  return `guardian_notification_${Date.now()}_${Math.random().toString(36)}`;
}

// Helper function to display notifications to the user
function showNotification(title, message, isError = false, notificationId = null, buttons = null, requireInteraction = false) {
  console.log(`Notification - ${title}: ${message}`);
  const options = {
    type: "basic",
    iconUrl: isError ? "images/guardian_err.png" : "images/guardian_min.png",
    title: title,
    message: message,
    priority: isError ? 2 : 0,
    buttons: buttons,
    requireInteraction: requireInteraction
  };
  
  if (notificationId) {
    chrome.notifications.create(notificationId, options);
  } else {
    chrome.notifications.create(options);
  }
}

// Store download item details keyed by notificationId for initial quarantine decision
const pendingDownloadDecisions = {};

// Store the scan result status for each notificationId (only status needed here)
const scanResultStatuses = new Map();

/**
 * Gets or creates a connection to the Native Host.
 * Handles onMessage and onDisconnect listeners for the single port.
 * @returns {chrome.runtime.Port | null} The port object or null if connection failed.
 */
function getNativeHostPort() {
  if (nativeHostPort && nativeHostPort.onMessage) { // Check if port exists and is active
    console.log("Reusing existing Native Host port.");
    return nativeHostPort;
  }

  console.log("Attempting to connect to Native Host...");
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
    console.log("Connected to Native Host:", NATIVE_HOST_NAME);

    // Set up message listener for the single port
    port.onMessage.addListener((response) => {
      console.log("Received response from native host:", response);
      
      switch (response.type) {
          case "ISOLATION_STATUS": {
              if (response.status === "successful") {
                  showNotification(
                    "File Isolated",
                    `File "${response.filename}" has been moved to quarantine. Remote scan initiated...`,
                    false,
                    response.notificationId
                  );
              } else {
                  showNotification(
                    "Isolation Failed",
                    `Failed to isolate file "${response.filename}". Reason: ${response.details || 'unknown error'}`,
                    true,
                    response.notificationId
                  );
              }
              break;
          }
          case "SCAN_RESULT": {
              const { status, details, filename, notificationId } = response;
              
              // Store the scan status for this notificationId for button logic
              scanResultStatuses.set(notificationId, status);
              
              let title = "Scan Result: " + status.charAt(0).toUpperCase() + status.slice(1);
              let message = `File "${filename}" (${status}). ${details}`;
              let buttons = [];
              let isError = false;
              let requireInteraction = true;

              if (status === "clean") {
                  message += "\nWhat would you like to do with the file?";
                  buttons = [
                    { title: "Keep" },          // buttonIndex 0
                    { title: "Restore" } // buttonIndex 1
                  ];
              } else if (status === "malicious") {
                  isError = true;
                  message += "\nIt is highly recommended to delete this file.";
                  buttons = [
                    { title: "Delete" },      // buttonIndex 0
                    { title: "Keep isolated(Risky)" }   // buttonIndex 1
                  ];
              } else if (status === "suspicious") {
                  isError = true;
                  message += "\nReview this file carefully.";
                  buttons = [
                    { title: "Delete" },      // buttonIndex 0
                    { title: "Keep isolated" },        // buttonIndex 1
                  ];
              } else if (status === "error") {
                   isError = true;
                   message = `Scan for "${filename}" failed. Reason: ${details}`;
                   requireInteraction = false;
                   buttons = [];
              }
              console.log(`DEBUG: Buttons array length for status ${status}: ${buttons.length}`);
              chrome.notifications.clear(notificationId, () => {
                  showNotification(title, message, isError, notificationId, buttons, requireInteraction);
              });
              break;
          }
          case "ACTION_DECISION_STATUS": {
              const { status, details, actionPerformed, notificationId, restoredPath } = response;
              let title = `File Action: ${actionPerformed.charAt(0).toUpperCase() + actionPerformed.slice(1)}`;
              let isError = status !== "success";
              let message = `Action "${actionPerformed}" for file finished: ${details}`;
              if (restoredPath) {
                  message += ` Restored to: ${restoredPath}`;
              }
              showNotification(title, message, isError, notificationId);
              // Clean up the scanResultStatuses entry after action is completed
              scanResultStatuses.delete(notificationId);
              break;
          }
          default: {
              console.warn("Received unknown message type from native host:", response.type, response);
              break;
          }
      }
    });

    // Set up disconnect listener for the single port
    port.onDisconnect.addListener(() => {
      const lastError = chrome.runtime.lastError;
      if (lastError) {
        console.error("Disconnected from native host. Error:", lastError.message);
        // If the native host exits normally, it might say "Native host has exited."
        if (!lastError.message.includes("Native host has exited.")) {
           showNotification(
              "Service Disconnected",
              `The file processing service disconnected unexpectedly. Reason: ${lastError.message}`,
              true
          );
        }
      } else {
        console.warn("Disconnected from native host gracefully.");
      }
      // Reset the port so it will be re-established next time it's needed
      nativeHostPort = null;
    });

    nativeHostPort = port; // Store the newly created port
    return nativeHostPort;

  } catch (e) {
    console.error("Failed to connect to Native Host:", e);
    showNotification(
      "Connection Failed",
      `Could not connect to the local service. Please ensure the Native Host is installed and running correctly.`,
      true
    );
    nativeHostPort = null; // Ensure port is null on failure
    return null;
  }
}


// Listen for Chrome download events
chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state && delta.state.current === "complete") {
    chrome.downloads.search({ id: delta.id }, (items) => {
      if (items && items.length > 0) {
        const downloadedItem = items[0];
        const dangerousExts = ['exe', 'msi', 'bat', 'cmd', 'ps1', 'sh', 'bin'];
        const ext = downloadedItem.filename.split('.').pop().toLowerCase();

        if (true) {
          console.log("Executable download completed:", downloadedItem.filename);

          const notificationId = generateUniqueNotificationId();
          
          // Store the downloaded item for later use when user makes a decision
          pendingDownloadDecisions[notificationId] = downloadedItem;

          // Ask the user whether to isolate the file
          showNotification(
            "Executable Downloaded",
            `File "${downloadedItem.filename}" has been downloaded. Would you like to quarantine it?`,
            false,
            notificationId,
            [
              { title: "Yes" },
              { title: "No" }
            ],
            true // Require user interaction
          );
        }
      }
    });
  }
});

// Listen for notification button click events (for initial quarantine decision and post-scan decisions)
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  const downloadedItem = pendingDownloadDecisions[notificationId];

  // Try to get the port
  const port = getNativeHostPort();
  if (!port) {
      showNotification("Communication Error", "Could not connect to the file processing service.", true, notificationId);
      return;
  }

  if (downloadedItem) {
    // This is the initial quarantine decision
    if (buttonIndex === 0) { // User clicked "Quarantine File"
      console.log(`User chose to quarantine file: ${downloadedItem.filename}`);
      
      // Get the custom isolation path from storage
      chrome.storage.local.get(ISOLATION_PATH_STORAGE_KEY, (data) => {
        const customIsolationPath = data[ISOLATION_PATH_STORAGE_KEY] || "";
        console.log("Using custom isolation path from storage:", customIsolationPath);

        const message = {
          type: "INITIATE_FILE_ISOLATION",
          downloadPath: downloadedItem.filename, // Full path where Chrome downloaded it
          filename: downloadedItem.filename,
          isolationPath: customIsolationPath, // User's preferred isolation path
          notificationId: notificationId // Pass unique ID for tracking
        };
        port.postMessage(message);
        console.log("Sent INITIATE_FILE_ISOLATION message to native host:", message);
      });

    } else if (buttonIndex === 1) { // User clicked "Do Not Quarantine"
      console.log(`User chose NOT to quarantine file: ${downloadedItem.filename}`);
      showNotification(
        "File Not Quarantined",
        `File "${downloadedItem.filename}" was not quarantined as per your request.`,
        false,
        notificationId
      );
    }
    delete pendingDownloadDecisions[notificationId]; // Clean up the stored item after initial decision
    chrome.notifications.clear(notificationId); // Clear the initial decision notification
  
  } else {
    // This is a post-scan decision (Delete, Isolate, Restore)
    let action = "";
    
    // Retrieve the scan result status using the notificationId
    const scanStatus = scanResultStatuses.get(notificationId);
    console.log(`Notification ID: ${notificationId}, Button Index: ${buttonIndex}, Scan Status: ${scanStatus}`);

    // Determine the action based on the scan status and button index
    if (scanStatus === "clean") {
      if (buttonIndex === 0) {
        action = "isolate"; // "Keep in Quarantine"
      } else if (buttonIndex === 1) {
        action = "restore"; // "Restore to Original Location"
      }
    } else if (scanStatus === "malicious") {
      if (buttonIndex === 0) {
        action = "delete"; // "Delete from Quarantine"
      } else if (buttonIndex === 1) {
        action = "isolate"; // "Keep in Quarantine (Risky)"
      }
    } else if (scanStatus === "suspicious") {
      if (buttonIndex === 0) {
        action = "delete"; // "Delete from Quarantine"
      } else if (buttonIndex === 1) {
        action = "isolate"; // "Keep in Quarantine"
      }
    }

    if (!action) {
      console.warn("Unknown button index or scan status for notificationId:", notificationId, "buttonIndex:", buttonIndex, "scanStatus:", scanStatus);
      chrome.notifications.clear(notificationId);
      scanResultStatuses.delete(notificationId); // Clean up
      return;
    }

    // Send user's decision to Native Host using the single port
    port.postMessage({
      type: "FILE_ACTION_DECISION",
      action: action, // "delete", "isolate", "restore"
      notificationId: notificationId // Pass the same ID back
    });
    console.log("Sent FILE_ACTION_DECISION to native host:", action, "for ID:", notificationId);

    chrome.notifications.clear(notificationId); // Clear the notification after decision
    // scanResultStatuses.delete(notificationId); // Cleanup is now in ACTION_DECISION_STATUS handler
  }
});

// Listener for messages from popup.js (Isolation Path Management)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "SAVE_ISOLATION_PATH") {
    const newPath = request.path;
    
    // Get the port for this request
    const port = getNativeHostPort();
    if (!port) {
        sendResponse({ status: "error", message: `Connection failed: Could not connect to the local service.` });
        return false; // Indicating that sendResponse will be called asynchronously
    }

    // Wrap the storage and port interaction in a promise or callback to sendResponse correctly
    chrome.storage.local.get(ISOLATION_PATH_STORAGE_KEY, (data) => {
        const oldPath = data[ISOLATION_PATH_STORAGE_KEY] || "";
        console.log("Current (old) isolation path from storage:", oldPath);

        // A temporary listener for this specific request's response
        const tempListener = (response) => {
            if (response.type === "UPDATE_ISOLATION_PATH_STATUS") { // Native Host should send this specific type
                port.onMessage.removeListener(tempListener); // Remove listener after receiving response

                if (response.status === "success") {
                    chrome.storage.local.set({ [ISOLATION_PATH_STORAGE_KEY]: newPath }, () => {
                        console.log("Isolation path saved:", newPath);
                        sendResponse({ status: "success", message: response.details, movedCount: response.movedCount });
                    });
                } else {
                    console.error("Path validation/move failed:", response.details);
                    sendResponse({ status: "error", message: response.details });
                }
            }
        };
        port.onMessage.addListener(tempListener);

        port.postMessage({ 
            type: "UPDATE_ISOLATION_PATH", 
            oldPath: oldPath, 
            newPath: newPath 
        });
        console.log("Sent UPDATE_ISOLATION_PATH to native host (old:", oldPath, "new:", newPath, ")");
    });
    return true; // Indicates that sendResponse will be called asynchronously
  } else if (request.type === "GET_ISOLATION_PATH") {
    chrome.storage.local.get(ISOLATION_PATH_STORAGE_KEY, (data) => {
      const path = data[ISOLATION_PATH_STORAGE_KEY] || "";
      console.log("Returning saved isolation path:", path);
      sendResponse({ path: path });
    });
    return true;
  } else if (request.type === "ANALYZE_FILE") {
    const downloadPath = request.filePath;
    const filename = request.filePath;
    const notificationId = generateUniqueNotificationId();
    console.log(`User chose to quarantine file: ${downloadPath}`);

    const port = getNativeHostPort();
    if (!port) {
        showNotification("Communication Error", "Could not connect to the file processing service.", true, notificationId);
        return;
    }

    // Get the custom isolation path from storage
    chrome.storage.local.get(ISOLATION_PATH_STORAGE_KEY, (data) => {
      const customIsolationPath = data[ISOLATION_PATH_STORAGE_KEY] || "";
      console.log("Using custom isolation path from storage:", customIsolationPath);

      const message = {
        type: "INITIATE_FILE_ISOLATION",
        downloadPath: downloadPath, // Full path where Chrome downloaded it
        filename: filename,
        isolationPath: customIsolationPath, // User's preferred isolation path
        notificationId: notificationId // Pass unique ID for tracking
      };
      port.postMessage(message);
      console.log("Sent INITIATE_FILE_ISOLATION message to native host:", message);
    });
  }
});


chrome.runtime.onInstalled.addListener(() => {
  console.log('Qemu Guardian extension installed or updated.');
  // Establish connection on install so it's ready
  getNativeHostPort(); 
});

// Clear any lingering notifications on startup/install
chrome.notifications.getAll((notifications) => {
  for (const id in notifications) {
    if (id.startsWith('guardian_notification_')) {
      chrome.notifications.clear(id);
      scanResultStatuses.delete(id); // Also clean up the map
      pendingDownloadDecisions[id]; // Also clean up the map
    }
  }
});