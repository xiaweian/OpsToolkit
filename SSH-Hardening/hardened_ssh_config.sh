#!/bin/bash

# 颜色定义
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

# 检查系统兼容性
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
if [ ! -d "$SSH_CONFIG_DIR" ]; then
    echo -e "${YELLOW}未检测到 $SSH_CONFIG_DIR 目录，可能是较旧的SSH版本${NC}"
    echo -e "${YELLOW}将直接修改主配置文件${NC}"
    use_config_dir=0
else
    use_config_dir=1
fi

# 创建 .ssh 目录并设置权限
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# 创建 authorized_keys 文件并设置权限
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"

# 修复所有权
if [ "$(whoami)" != "$(stat -c '%U' "$HOME/.ssh")" ]; then
    echo -e "${YELLOW}修正 ~/.ssh 目录所有权${NC}"
    sudo chown -R "$(whoami)":"$(whoami)" "$HOME/.ssh"
fi

# 公钥处理函数
process_ssh_keys() {
    echo -e "${YELLOW}请输入你的 SSH 公钥（支持 ssh-rsa/ssh-ed25519/ecdsa/sk-ssh-ed25519），输入空行结束：${NC}"

    temp_authkeys=$(mktemp)
    touch "$temp_authkeys"
    chmod 600 "$temp_authkeys"

    while true; do
        read -r -p "SSH公钥（直接回车结束输入）: " pubkey
        [ -z "$pubkey" ] && break

        if ! echo "$pubkey" | grep -Eq '^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519) [A-Za-z0-9+/=]+(\s.+)?$'; then
            echo -e "${RED}警告：不支持的SSH公钥格式${NC}"
            echo -e "${YELLOW}支持格式：ssh-rsa, ssh-ed25519, ecdsa, sk-ssh-ed25519${NC}"
            continue
        fi

        key_content=$(echo "$pubkey" | awk '{print $1" "$2}')
        if grep -qF "$key_content" "$HOME/.ssh/authorized_keys"; then
            echo -e "${YELLOW}此公钥已存在于authorized_keys中${NC}"
        else
            echo "$pubkey" >> "$temp_authkeys"
            echo -e "${YELLOW}公钥已添加${NC}"
        fi
    done

    if [ -s "$temp_authkeys" ]; then
        grep -vFf <(awk '{print $1" "$2}' "$temp_authkeys") "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.tmp" 2>/dev/null || true
        cat "$temp_authkeys" >> "$HOME/.ssh/authorized_keys.tmp"
        mv "$HOME/.ssh/authorized_keys.tmp" "$HOME/.ssh/authorized_keys"
        chmod 600 "$HOME/.ssh/authorized_keys"
        echo -e "${YELLOW}共添加 $(wc -l < "$temp_authkeys") 个新公钥${NC}"
    else
        echo -e "${YELLOW}未添加任何新公钥${NC}"
    fi

    rm -f "$temp_authkeys"
}

# 调用函数
process_ssh_keys

# 备份 SSH 配置
timestamp=$(date +%Y%m%d%H%M%S)
backup_file="/etc/ssh/sshd_config.bak.$timestamp"
sudo cp /etc/ssh/sshd_config "$backup_file"
echo -e "${YELLOW}原始配置已备份至: $backup_file${NC}"

# SSH 安全配置内容
read -r -d '' SSH_SECURITY_CONFIG <<'EOF'
# 安全配置 - 禁用密码登录
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

# 加密算法
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
EOF

# 写入配置
if [ "$use_config_dir" -eq 1 ]; then
    custom_file="$SSH_CONFIG_DIR/99-custom-hardening.conf"
    echo "$SSH_SECURITY_CONFIG" | sudo tee "$custom_file" > /dev/null
    echo -e "${YELLOW}配置已写入: $custom_file${NC}"
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

# 检查配置有效性
echo -e "${YELLOW}验证 SSH 配置...${NC}"
if sudo sshd -t; then
    echo -e "${YELLOW}配置语法无误，正在重启 SSH 服务...${NC}"
    sudo systemctl restart ssh || sudo service ssh restart
    echo -e "${YELLOW}SSH 服务已重启${NC}"
else
    echo -e "${RED}配置存在语法错误，请检查修改内容${NC}"
    exit 1
fi
