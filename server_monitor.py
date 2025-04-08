#!/usr/bin/env python3
"""
服务器监控工具入口脚本
"""
import sys
import os

# 确保可以导入server_monitor包
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server_monitor.main import init_mcp, cleanup_resources

# 在模块级别初始化mcp对象
try:
    mcp = init_mcp()
except Exception as e:
    print(f"初始化MCP时发生错误: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

def main():
    """主入口函数"""
    try:
        print("启动服务器监控服务...")
        if not mcp:
            print("错误：MCP对象未正确初始化")
            return 1
        mcp.run(transport='stdio')
    except KeyboardInterrupt:
        print("\n用户中断，正在退出...")
    except Exception as e:
        print(f"发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        print("清理资源...")
        cleanup_resources()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())