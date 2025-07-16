document.addEventListener('DOMContentLoaded', () => {
  const isolationPathInput = document.getElementById('isolationPath');
  const savePathButton = document.getElementById('savePathButton');
  const statusMessageDiv = document.getElementById('statusMessage');
  const filePathInput = document.getElementById('filePathInput');
  const analyzeButton = document.getElementById('analyzeButton');
  
  
  function showStatus(message, type) {
    statusMessageDiv.textContent = message;
    statusMessageDiv.className = `status-message ${type}`;
    statusMessageDiv.style.display = 'block';
    setTimeout(() => {
      statusMessageDiv.style.display = 'none';
    }, 8000); // Display for 8 seconds, longer for complex messages
  }


  // Load saved path when popup opens
  chrome.runtime.sendMessage({ type: "GET_ISOLATION_PATH" }, (response) => {
    if (response && response.path !== undefined) {
      isolationPathInput.value = response.path;
    }
  });

  // Save path when button is clicked
  savePathButton.addEventListener('click', () => {
    const newPath = isolationPathInput.value.trim();
    showStatus("Checking path and moving old files...", "info"); // Provide more detailed feedback

    chrome.runtime.sendMessage({ type: "SAVE_ISOLATION_PATH", path: newPath }, (response) => {
      if (response) {
        if (response.status === "success") {
          let successMessage = `Path saved: ${response.message}`;
          if (response.movedCount !== undefined && response.movedCount > 0) {
            successMessage += ` (${response.movedCount} items moved).`;
          } else if (response.movedCount === 0) {
            successMessage += ` (No items to move or already empty).`;
          }
          showStatus(successMessage, "success");
        } else if (response.status === "error") {
          showStatus(`Error saving path: ${response.message}`, "error");
        } else {
          showStatus(`Unexpected response from background: ${response.message}`, "error");
        }
      } else {
        showStatus("Failed to get response from background script. Native Host might not be running or an unknown error occurred.", "error");
      }
    });
  });

  analyzeButton.addEventListener('click', () => {
    let filePath = filePathInput.value.trim();
    if (filePath.startsWith('"') && filePath.endsWith('"')) {
      filePath = filePath.substring(1, filePath.length - 1);
      console.log("Removed quotes. New path:", filePath); // For debugging
    }
  
    if (filePath) {
      // Send to background script
      chrome.runtime.sendMessage({
        type: 'ANALYZE_FILE',
        filePath: filePath, // This is the key: sending the full file path
      });
      showStatus(`Analyzing file: ${filePath}...`, 'pending');
      filePathInput.value = ''; // Clear the input field
    } else {
      showStatus('Please enter a full file path.', 'warning');
    }
  });

});
