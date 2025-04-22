import sys
import os

# 添加当前目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 使用绝对导入
try:
    # 先尝试直接导入
    from server import main
except ImportError:
    # 如果失败，尝试从当前目录导入
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from server import main

if __name__ == "__main__":
    sys.exit(main())