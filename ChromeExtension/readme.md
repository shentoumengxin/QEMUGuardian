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

## 安装过程

1. 本目录下的 `Extension` 文件夹即为已解压的扩展程序，在 Chrome *扩展程序-管理扩展程序*中，选择“加载已解压的扩展程序”，并选择该 `Extension` 文件夹，即可加载扩展程序。
2. 在*扩展程序-管理扩展程序*中，查看本插件 `File Scan Interceptor` 的 ID，并修改本目录下的 `guardian_manifest.json` 中的 `allowed_origins` 字段为该 ID。
3. 在 `.reg` 中，修改绝对路径指向 `guardian_manifest.json` 文件，然后双击运行该 `.reg` 文件，添加注册表项。
4. 将 `guardian_manifest.json` 和 `Guardian.exe` 放置在同一目录下，此时该插件应该已经可以使用。
5. 若想自行编译后台服务 `Guardian.exe`，若是使用 `MinGW32-make`，可在 `Guardian` 目录下运行：

     ```bash
     > mkdir build
     > cd ./build
     > cmake .. -G "MinGW Makefiles"
     > cmake --build .
     ```
