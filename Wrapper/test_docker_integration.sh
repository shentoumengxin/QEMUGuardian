#!/bin/bash

# 快速测试Docker集成
echo "=== Quick Docker Integration Test ==="

cd /home/zzh/QEMUGuardian/Wrapper

# 检查test目录
TEST_DIR="test/basic_tests/bin"
if [ ! -d "$TEST_DIR" ]; then
    echo "Error: Test directory $TEST_DIR not found"
    exit 1
fi

# 找到第一个测试文件
TEST_FILE="test/basic_tests/bin/test_code_injection"

echo "Using test file: $TEST_FILE"

# 创建临时目录只包含一个测试文件
TEMP_DIR=$(mktemp -d)
cp "$TEST_FILE" "$TEMP_DIR/"

echo "Created temporary test directory: $TEMP_DIR"

# 测试Docker模式 (如果有sudo权限)
if sudo -n true 2>/dev/null; then
    echo "Testing Docker mode..."
    sudo python3 wrapper.py "$TEMP_DIR" --docker --timeout 30
else
    echo "No sudo access available. Testing syntax only..."
    python3 -c "import wrapper; print('Wrapper syntax OK')"
fi

# 清理
rm -rf "$TEMP_DIR"
echo "Test completed."
