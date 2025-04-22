"""装饰器模块"""

import functools
import paramiko
import logging

# 配置日志
logger = logging.getLogger('decorators')

def handle_exceptions(func):
    """装饰器：统一处理工具函数中的异常"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed in {func.__name__}: {str(e)}")
            return {"status": "error", "error": f"SSH认证失败: {str(e)}"}
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error in {func.__name__}: {str(e)}")
            return {"status": "error", "error": f"SSH连接错误: {str(e)}"}
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
            return {"status": "error", "error": f"执行失败: {str(e)}"}
    return wrapper
