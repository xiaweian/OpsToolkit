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
chmod 700 ~/.ssh

# 创建 authorized_keys 文件并设置权限
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 确保文件所有权正确
if [ "$(whoami)" != "$(stat -c '%U' ~/.ssh)" ]; then
    echo -e "${YELLOW}修正 ~/.ssh 目录所有权${NC}"
    sudo chown -R "$(whoami)": ~/.ssh
fi

# 公钥处理函数，支持硬件密钥
process_ssh_keys() {
    echo -e "${YELLOW}请输入你的 SSH 公钥（支持 ssh-rsa/ssh-ed25519/ecdsa，或者 sk-ssh-ed25519），输入空行结束：${NC}"
    
    # 创建临时文件
    TEMP_AUTHKEYS=$(mktemp)
    touch "$TEMP_AUTHKEYS"
    chmod 600 "$TEMP_AUTHKEYS"
    
    # 多公钥输入循环
    while true; do
        read -r -p "SSH公钥（直接回车结束输入）: " pubkey
        [ -z "$pubkey" ] && break  # 空行结束输入
        
        # 增强的公钥格式验证
        if [[ ! $pubkey =~ ^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519)\ [A-Za-z0-9+/]+[=]{0,3}(\ .*)?$ ]]; then
            echo -e "${RED}警告：不支持的SSH公钥格式${NC}"
            echo -e "${YELLOW}支持格式：ssh-rsa, ssh-ed25519, ecdsa 或 sk-ssh-ed25519${NC}"
            continue
        fi
        
        # 检查重复公钥（包括注释不同的相同密钥）
        KEY_CONTENT=$(echo "$pubkey" | awk '{print $_
