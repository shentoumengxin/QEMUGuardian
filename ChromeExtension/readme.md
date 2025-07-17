# Chrome Plugin Implementation

This plugin intercepts downloads to detect file vulnerabilities.

## How to Use It

Once the plugin is installed, here's what happens when you download a file:

1. The plugin automatically intercepts the download request and asks if you want to perform an isolation check on the file.
2. If you choose "yes," the plugin first moves the file to a hidden isolation directory. Then, it automatically sends the file to the remote server at [http://xxbaicz.online:8081/analyze/](http://xxbaicz.online:8081/analyze/) for inspection.
    After the check, the plugin returns the results and gives you several options:
      * **Keep isolated**: Leaves the file in the isolation directory.
      * **Restore**: Moves the file back to its original download location.
      * **Delete**: Permanently removes the file.
3. Clicking the plugin icon in your browser's top-right corner lets you change the isolation directory and automatically move all currently isolated files to the new location.
4. You can also manually send a file for inspection by clicking the plugin icon and entering the file's path.

-----

## Automatic Installation

1. In Chrome's **Extensions - Manage Extensions**, select "Load unpacked" and choose the `Extension` folder from this directory to load the plugin.
2. In **Extensions - Manage Extensions**, find and note the ID for the `Guardian` plugin.
3. **Linux** users can run the `setup.sh` script to automate the installation. **Windows** users can run the `setup.ps1` script in Powershell. These scripts will automatically create and register the `guardian_manifest` file for the background service.

-----

## Manual Installation

### For Windows Users

1. The `Extension` folder in this directory holds the unpacked extension. In Chrome's **Extensions - Manage Extensions**, choose "Load unpacked" and select this `Extension` folder to load it.

2. In **Extensions - Manage Extensions**, note the ID for the `Guardian` plugin.

3. Locate the background service program at `bin/windows/Guardian.exe`. In the *same directory*, create a file named `guardian_manifest.json` with the following content:

    ```json
    {
      "name": "com.nus_dada_group.guardian",
      "description": "Background Guardian Service",
      "path": "Guardian.exe",
      "type": "stdio",
      "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
    }
    ```

    **Replace `YOUR_EXTENSION_ID` with the actual plugin ID** you obtained in the previous step.

4. Create a `.reg` file with the following content:

    ```reg
    Windows Registry Editor Version 5.00

    [HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.nus_dada_group.guardian]
    @="C:\\absolute\\path\\to\\guardian_manifest.json"
    ```

    **Replace `C:\\absolute\\path\\to\\guardian_manifest.json` with the full, absolute path to your `guardian_manifest.json` file.** Double-click this `.reg` file to add the registry entry. The plugin should now be functional.

5. If you want to **compile the background service `Guardian.exe` yourself** using `MinGW32-make`, navigate to the `BackgroundService` directory in your terminal and run:

    ```powershell
    > cd ./BackgroundService
    > mkdir build
    > cd ./build
    > cmake .. -G "MinGW Makefiles"
    > cmake --build .
    ```

### For Linux Users

1. The `Extension` folder in this directory holds the unpacked extension. In Chrome's **Extensions - Manage Extensions**, choose "Load unpacked" and select this `Extension` folder to load it.

2. In **Extensions - Manage Extensions**, note the ID for the `Guardian` plugin.

3. Locate the background service program at `bin/linux/Guardian`. In the *same directory*, create a file named `guardian_manifest.json` with the following content:

    ```json
    {
      "name": "com.nus_dada_group.guardian",
      "description": "Background Guardian Service",
      "path": "/Absolute/Path/To/Guardian",
      "type": "stdio",
      "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
    }
    ```

    **Replace `YOUR_EXTENSION_ID` with the actual plugin ID** you obtained in the previous step.

4. Choose your installation scope:

      * For **current user only**: Place the `guardian_manifest.json` file in `~/.config/google-chrome/NativeMessagingHosts/`.
      * For **all users**: Place the `guardian_manifest.json` file in `/etc/opt/chrome/native-messaging-hosts/`.

    **Important:** Remember to modify the `path` field in `guardian_manifest.json` to point to the **absolute path** of your `Guardian` executable. The default isolation folder will also be placed in the same directory as `Guardian`. The plugin should now be functional.

5. If you want to **compile the background service yourself**, navigate to the `BackgroundService` directory in your terminal and run:

    ```bash
    > cd ./BackgroundService
    > mkdir build
    > cd ./build
    > cmake ..
    > cmake --build .
    ```

### For macOS Users

1. The `Extension` folder in this directory holds the unpacked extension. In Chrome's **Extensions - Manage Extensions**, choose "Load unpacked" and select this `Extension` folder to load it.

2. In **Extensions - Manage Extensions**, note the ID for the `Guardian` plugin.

3. A macOS version of the background service program has not yet been pre-compiled. If you need to use it, please compile the code in the `BackgroundService` directory yourself. After compilation, place the generated executable in `bin/macos`.

4. If the background service program is `bin/macos/Guardian`, in the *same directory*, create a file named `guardian_manifest.json` with the following content:

    ```json
    {
      "name": "com.nus_dada_group.guardian",
      "description": "Background Guardian Service",
      "path": "/Absolute/Path/To/Guardian",
      "type": "stdio",
      "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
    }
    ```

    **Replace `YOUR_EXTENSION_ID` with the actual plugin ID** you obtained in the previous step.

5. Choose your installation scope:

      * For **current user only**: Place the `guardian_manifest.json` file in `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`.
      * For **all users**: Place the `guardian_manifest.json` file in `/Library/Application Support/Google/Chrome/NativeMessagingHosts/`.

    **Important:** Remember to modify the `path` field in `guardian_manifest.json` to point to the **absolute path** of your `Guardian` executable. The default isolation folder will also be placed in the same directory as `Guardian`. The plugin should now be functional.
