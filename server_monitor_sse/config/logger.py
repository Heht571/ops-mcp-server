"""日志配置模块"""

import logging

# 配置日志
def setup_logger():
    """配置并返回日志记录器"""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('server_monitor')
    return logger

logger = setup_logger()
