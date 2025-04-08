#!/usr/bin/env python
# 网络工具集MCP入口文件

import sys
import os

# 将当前目录添加到Python的导入路径中
sys.path.insert(0, os.path.abspath("."))

# 导入network_tools包中的主模块
from network_tools.main import mcp

if __name__ == "__main__":
    try:
        # 运行MCP服务
        mcp.run(transport='stdio')
    except Exception as e:
        print(f"运行错误: {str(e)}")
        sys.exit(1) 