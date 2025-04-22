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
chmod 700 ~/.ssh

# 创建 authorized_keys 文件并设置权限
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 确保文件所有权正确
if [ "$(whoami)" != "$(stat -c '%U' ~/.ssh)" ]; then
    echo -e "${YELLOW}修正 ~/.ssh 目录所有权${NC}"
    sudo chown -R $(whoami): ~/.ssh
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
        KEY_CONTENT=$(echo "$pubkey" | awk '{print $1" "$2}')
        if grep -qF "$KEY_CONTENT" ~/.ssh/authorized_keys; then
            echo -e "${YELLOW}此公钥已存在于authorized_keys中${NC}"
        else
            echo "$pubkey" >> "$TEMP_AUTHKEYS"
            echo -e "${GREEN}公钥已添加${NC}"
        fi
    done
    
    # 合并新旧密钥（保留原有非重复密钥）
    if [ -s "$TEMP_AUTHKEYS" ]; then
        # 保留原有不重复的密钥
        grep -vFf <(awk '{print $1" "$2}' "$TEMP_AUTHKEYS") ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null || true
        # 添加新密钥
        cat "$TEMP_AUTHKEYS" >> ~/.ssh/authorized_keys.tmp
        # 替换原文件
        mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        echo -e "${GREEN}共添加 $(wc -l < "$TEMP_AUTHKEYS") 个新公钥${NC}"
    else
        echo -e "${YELLOW}未添加任何新公钥${NC}"
    fi
    
    rm -f "$TEMP_AUTHKEYS"
}

# 调用公钥处理函数
process_ssh_keys

# 备份SSH配置
BACKUP_FILE="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
sudo cp /etc/ssh/sshd_config "$BACKUP_FILE"
echo -e "${GREEN}原始配置已备份至: $BACKUP_FILE${NC}"

# 修改 SSH 配置
echo -e "${YELLOW}正在设置SSH安全配置...${NC}"

# 设置安全配置
SSH_SECURITY_CONFIG="# 安全配置 - 禁用密码登录
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitRootLogin prohibit-password
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 6
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2

# 现代加密算法配置
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
"

if [ "$USE_CONFIG_DIR" -eq 1 ]; then
    # 使用配置目录
    CUSTOM_CONFIG_FILE="$SSH_CONFIG_DIR/99-disable-password-auth.conf"
    echo -e "${YELLOW}创建配置文件: $CUSTOM_CONFIG_FILE${NC}"
    echo "$SSH_SECURITY_CONFIG" | sudo tee "$CUSTOM_CONFIG_FILE" > /dev/null
else
    # 直接修改主配置文件
    echo -e "${YELLOW}修改主配置文件${NC}"
    
    # 禁用密码认证
    sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    
    # 添加缺失的配置项
    declare -A config_lines=( 
        ["AuthenticationMethods"]="publickey"
        ["Protocol"]="2"
        ["Ciphers"]="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
        ["HostKeyAlgorithms"]="ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"
        ["KexAlgorithms"]="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
        ["MACs"]="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
    )

    for key in "${!config_lines[@]}"; do
        if ! grep -q "^$key" /etc/ssh/sshd_config; then
            echo "$key ${config_lines[$key]}" | sudo tee -a /etc/ssh/sshd_config > /dev/null
        fi
    done
fi

# 检查配置文件有效性
echo -e "${YELLOW}
