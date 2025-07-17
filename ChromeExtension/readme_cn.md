# Chrome 插件实现

本插件实现了拦截下载并检测文件漏洞的功能。

## 使用过程

具体为，当安装好插件后，用户下载任意文件时，插件会有以下行为：

1. 自动拦截下载请求，询问是否对文件进行隔离检查。
2. 若选择“yes”，则插件会先将文件移动到隐藏的隔离目录，随后自动将插件发送到远端服务器 [http://xxbaicz.online:8081/analyze/](http://xxbaicz.online:8081/analyze/) 进行检查。
3. 检查完成后，插件返回检查结果，并根据检查结果提供给用户不同选项：
   - Keep isolated: 保持隔离
   - Restore: 恢复到原下载目录
   - Delete: 删除文件
4. 点击浏览器右上角的插件图标，可以修改隔离目录并自动移动所有隔离文件。
5. 点击浏览器右上角的插件图标，输入文件地址，可以手动将文件发送到远端服务器进行检查。

## 自动安装过程

1. 在 Chrome *扩展程序-管理扩展程序*中，选择“加载已解压的扩展程序”，并选择本目录下的 `Extension` 文件夹，即可加载扩展程序。
2. 在*扩展程序-管理扩展程序*中，查看本插件 `Guardian` 的 ID。
3. Linux 用户可以使用 `setup.sh` 脚本自动完成安装过程，Windows 用户可以使用 `setup.ps1` 脚本安装。脚本会自动创建后台服务的 guardian_manifest 文件，并将其注册到系统中。

## 手动安装过程

### Windows 用户

1. 本目录下的 `Extension` 文件夹即为已解压的扩展程序，在 Chrome *扩展程序-管理扩展程序*中，选择“加载已解压的扩展程序”，并选择该 `Extension` 文件夹，即可加载扩展程序。
2. 在*扩展程序-管理扩展程序*中，查看本插件 `Guardian` 的 ID。
3. 后台服务程序为 `bin/windows/Guardian.exe`，在同目录下创建一个名为 `guardian_manifest.json` 的文件，内容如下：

   ```json
   {
     "name": "com.nus_dada_group.guardian",
     "description": "Background Guardian Service",
     "path": "Guardian.exe",
     "type": "stdio",
     "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
   }
   ```

   其中 `YOUR_EXTENSION_ID` 替换为上一步中获取的插件 ID。
4. 创建一个 `.reg` 文件：

   ```reg
   Windows Registry Editor Version 5.00

   [HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.nus_dada_group.guardian]
   @="C:\\absolute\\path\\to\\guardian_manifest.json"
   ```

   其中 `C:\\absolute\\path\\to\\guardian_manifest.json` 需要替换为实际的绝对路径。双击运行该 `.reg` 文件，添加注册表项。此时该插件应该已经可以使用。
5. 若想自行编译后台服务 `Guardian.exe`，若是使用 `MinGW32-make`，可在 `Guardian` 目录下运行：

     ```powershell
     > cd ./BackgroundService
     > mkdir build
     > cd ./build
     > cmake .. -G "MinGW Makefiles"
     > cmake --build .
     ```

### Linux 用户

1. 本目录下的 `Extension` 文件夹即为已解压的扩展程序，在 Chrome *扩展程序-管理扩展程序*中，选择“加载已解压的扩展程序”，并选择该 `Extension` 文件夹，即可加载扩展程序。
2. 在*扩展程序-管理扩展程序*中，查看本插件 `Guardian` 的 ID。
3. 后台服务程序为 `bin/linux/Guardian`，在同目录下创建一个名为 `guardian_manifest.json` 的文件，内容如下：

   ```json
   {
     "name": "com.nus_dada_group.guardian",
     "description": "Background Guardian Service",
     "path": "/Absolute/Path/To/Guardian",
     "type": "stdio",
     "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
   }
   ```

   其中 `YOUR_EXTENSION_ID` 替换为上一步中获取的插件 ID。
4. 选择安装作用域：

   - 若仅当前用户使用，则将 `guardian_manifest.json` 文件放在 `~/.config/google-chrome/NativeMessagingHosts/`。
   - 若所有用户都使用，则将 `guardian_manifest.json` 文件放在 `/etc/opt/chrome/native-messaging-hosts/`。

   注意 `guardian_manifest.json` 中需要修改 `path` 字段为指向 Guardian 的绝对路径。默认的隔离文件夹也放置在 Guardian 同级目录。此时该插件应该已经可以使用。

5. 若想自行编译后台服务，Linux 用户也类似地：

    ```bash
    > cd ./BackgroundService
    > mkdir build
    > cd ./build
    > cmake ..
    > cmake --build .
    ```

### macOS 用户

1. 本目录下的 `Extension` 文件夹即为已解压的扩展程序，在 Chrome *扩展程序-管理扩展程序*中，选择“加载已解压的扩展程序”，并选择该 `Extension` 文件夹，即可加载扩展程序。
2. 在*扩展程序-管理扩展程序*中，查看本插件 `Guardian` 的 ID。
3. 暂未编译 mac 版本的后台服务程序，若需要使用，请自行编译 `BackgroundService` 目录下的代码。编译完成后，将生成的可执行文件放在 `bin/macos` 中。
4. 若后台服务程序为 `bin/macos/Guardian`，在同目录下创建一个名为 `guardian_manifest.json` 的文件，内容如下：

   ```json
   {
     "name": "com.nus_dada_group.guardian",
     "description": "Background Guardian Service",
     "path": "/Absolute/Path/To/Guardian",
     "type": "stdio",
     "allowed_origins": ["chrome-extension://YOUR_EXTENSION_ID/"]
   }
   ```

   其中 `YOUR_EXTENSION_ID` 替换为上一步中获取的插件 ID。
5. 选择安装作用域：

   - 若仅当前用户使用，则将 `guardian_manifest.json` 文件放在 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`。
   - 若所有用户都使用，则将 `guardian_manifest.json` 文件放在 `/Library/Application Support/Google/Chrome/NativeMessagingHosts/`。

   注意 `guardian_manifest.json` 中需要修改 `path` 字段为指向 Guardian 的绝对路径。默认的隔离文件夹也放置在 Guardian 同级目录。此时该插件应该已经可以使用。
