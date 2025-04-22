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
    if ! sudo -v; then
        echo -e "${RED}无法获取sudo权限，退出${NC}"
        exit 1
    fi
fi

# 检查系统是否使用 config.d 目录
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
USE_CONFIG_DIR=0
if [[ -d "$SSH_CONFIG_DIR" ]]; then
    USE_CONFIG_DIR=1
else
    echo -e "${YELLOW}未检测到 $SSH_CONFIG_DIR 目录，可能是较旧的SSH版本${NC}"
    echo -e "${YELLOW}将直接修改主配置文件${NC}"
fi

# 创建 .ssh 目录并设置权限
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 确保文件所有权正确
if [[ "$(whoami)" != "$(stat -c '%U' ~/.ssh)" ]]; then
    echo -e "${YELLOW}修正 ~/.ssh 目录所有权${NC}"
    sudo chown -R "$(whoami)" ~/.ssh
fi

# 公钥处理函数
process_ssh_keys() {
    echo -e "${YELLOW}请输入你的 SSH 公钥（支持 ssh-rsa/ssh-ed25519/ecdsa 或 Yubikey），输入空行结束：${NC}"

    TEMP_AUTHKEYS=$(mktemp)
    chmod 600 "$TEMP_AUTHKEYS"

    while true; do
        read -r -p "SSH公钥（直接回车结束输入）: " pubkey
        [[ -z "$pubkey" ]] && break

        if [[ ! $pubkey =~ ^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519) [A-Za-z0-9+/=]+(\ .*)?$ ]]; then
            echo -e "${RED}不支持的SSH公钥格式${NC}"
            continue
        fi

        key_content=$(echo "$pubkey" | awk '{print $1" "$2}')
        if grep -qF "$key_content" ~/.ssh/authorized_keys; then
            echo -e "${YELLOW}此公钥已存在${NC}"
        else
            echo "$pubkey" >> "$TEMP_AUTHKEYS"
            echo -e "${GREEN}公钥已添加${NC}"
        fi
    done

    if [[ -s "$TEMP_AUTHKEYS" ]]; then
        grep -vFf <(awk '{print $1" "$2}' "$TEMP_AUTHKEYS") ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null || true
        cat "$TEMP_AUTHKEYS" >> ~/.ssh/authorized_keys.tmp
        mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
        echo -e "${GREEN}共添加 $(wc -l < "$TEMP_AUTHKEYS") 个新公钥${NC}"
    else
        echo -e "${YELLOW}未添加任何新公钥${NC}"
    fi

    rm -f "$TEMP_AUTHKEYS"
}

process_ssh_keys

# 备份 SSH 配置
BACKUP_FILE="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
sudo cp /etc/ssh/sshd_config "$BACKUP_FILE"
echo -e "${GREEN}配置已备份至: $BACKUP_FILE${NC}"

# SSH 安全配置内容
SSH_SECURITY_CONFIG="# SSH 安全配置
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
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
"

if [[ "$USE_CONFIG_DIR" -eq 1 ]]; then
    CONFIG_FILE="$SSH_CONFIG_DIR/99-disable-password-auth.conf"
    echo "$SSH_SECURITY_CONFIG" | sudo tee "$CONFIG_FILE" > /dev/null
    echo -e "${GREEN}配置已写入: $CONFIG_FILE${NC}"
else
    sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config

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

# 检查配置语法
echo -e "${YELLOW}检查 SSH 配置语法...${NC}"
if sudo sshd -t; then
    echo -e "${GREEN}配置语法无误，重启SSH服务${NC}"
    sudo systemctl restart sshd
else
    echo -e "${RED}配置有误，请检查手动恢复备份: $BACKUP_FILE${NC}"
fi
