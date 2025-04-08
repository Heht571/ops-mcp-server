"""SSH连接管理器模块"""

import paramiko
from server_monitor.config.logger import logger

class SSHManager:
    """SSH连接管理器（上下文管理器）"""
    _connection_cache = {}  # 类级别的连接缓存

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str = "",
        port: int = 22,
        timeout: int = 30,
        use_cache: bool = True
    ):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.connect_params = {
            "hostname": hostname,
            "username": username,
            "password": password,
            "port": port,
            "timeout": timeout
        }
        self.connection_key = f"{username}@{hostname}:{port}"
        self.use_cache = use_cache
        self.is_new_connection = False

    def __enter__(self) -> paramiko.SSHClient:
        try:
            # 尝试从缓存获取连接
            if self.use_cache and self.connection_key in self._connection_cache:
                cached_client = self._connection_cache[self.connection_key]
                # 检查连接是否仍然有效
                try:
                    cached_client.exec_command("echo 1", timeout=5)
                    logger.debug(f"Using cached SSH connection for {self.connection_key}")
                    self.client = cached_client
                    return self.client
                except Exception:
                    # 连接已失效，从缓存中移除
                    logger.debug(f"Cached connection invalid for {self.connection_key}, creating new one")
                    self._connection_cache.pop(self.connection_key, None)

            # 创建新连接
            logger.debug(f"Creating new SSH connection to {self.connection_key}")
            self.client.connect(**self.connect_params)
            self.is_new_connection = True

            # 添加到缓存
            if self.use_cache:
                self._connection_cache[self.connection_key] = self.client

            return self.client
        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed for {self.connection_key}: {str(e)}")
            raise
        except paramiko.SSHException as e:
            logger.error(f"SSH connection error for {self.connection_key}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to {self.connection_key}: {str(e)}")
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 只有新创建的连接且不使用缓存时才关闭
        if not self.use_cache and self.is_new_connection:
            logger.debug(f"Closing SSH connection to {self.connection_key}")
            self.client.close()

    @classmethod
    def clear_cache(cls):
        """清除连接缓存"""
        for client in cls._connection_cache.values():
            try:
                client.close()
            except:
                pass
        cls._connection_cache.clear()
        logger.info("SSH connection cache cleared")