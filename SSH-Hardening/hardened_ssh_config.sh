#!/bin/bash

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否有sudo权限
if ! sudo -n true 2>/dev/null; then
    echo -e "${YELLOW}此脚本需要sudo权限来修改SSH配置${NC}"
    echo -e "${YELLOW}请输入密码：${NC}"
    sudo -v || { echo -e "${RED}无法获取sudo权限，退出${NC}"; exit 1; }
fi

# 检查系统兼容性
SSH_VERSION=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+')
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
if [[ ! -d "$SSH_CONFIG_DIR" ]]; then
    echo -e "${YELLOW}未检测到 $SSH_CONFIG_DIR 目录，可能是较旧的SSH版本${NC}"
    echo -e "${YELLOW}将直接修改主配置文件${NC}"
    USE_CONFIG_DIR=0
else
    USE_CONFIG_DIR=1
fi

# 创建 .ssh 目录并设置权限
mkdir -p ~/.ssh
chmod
