#!/bin/bash

# 颜色定义
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# 检查是否有sudo权限
if ! command -v sudo &> /dev/null; then
    echo -e "${YELLOW}未检测到 sudo，正在尝试安装 sudo${NC}"

    if command -v apt &> /dev/null; then
        echo -e "${YELLOW}检测到 Debian/Ubuntu 系统，正在安装 sudo${NC}"
        apt-get update -y && apt-get install sudo -y || {
            echo -e "${RED}sudo 安装失败${NC}"
            exit 1
        }
    elif command -v dnf &> /dev/null; then
        echo -e "${YELLOW}检测到基于 RHEL/Oracle 的系统，使用 dnf 安装 sudo${NC}"
        dnf install sudo -y || {
            echo -e "${RED}sudo 安装失败${NC}"
            exit 1
        }
    elif command -v yum &> /dev/null; then
        echo -e "${YELLOW}检测到 CentOS/RHEL/Oracle 系统，使用 yum 安装 sudo${NC}"
        yum install sudo -y || {
            echo -e "${RED}sudo 安装失败${NC}"
            exit 1
        }
    else
        echo -e "${RED}未检测到合适的包管理器，请手动安装 sudo${NC}"
        exit 1
    fi

    echo -e "${YELLOW}sudo 安装完成，重新运行脚本...${NC}"
    exec $0 "$@"
fi

# 检查 sudo 权限
if ! sudo -n true 2>/dev/null; then
    echo -e "${YELLOW}需要 sudo 权限，请输入密码：${NC}"
    sudo -v || {
        echo -e "${RED}sudo 权限验证失败${NC}"
        exit 1
    }
fi

# SSH 配置目录检查
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
if [ ! -d "$SSH_CONFIG_DIR" ]; then
    echo -e "${YELLOW}未找到 $SSH_CONFIG_DIR，将直接修改主配置文件${NC}"
    use_config_dir=0
else
    use_config_dir=1
fi

# 设置 .ssh 权限
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"

# 修复权限
if [ "$(whoami)" != "$(stat -c '%U' "$HOME/.ssh")" ]; then
    echo -e "${YELLOW}修正 ~/.ssh 权限${NC}"
    sudo chown -R "$(whoami)":"$(whoami)" "$HOME/.ssh"
fi

# 处理 SSH 公钥
process_ssh_keys() {
    echo -e "${YELLOW}请输入你的 SSH 公钥，按回车结束输入：${NC}"
    temp_authkeys=$(mktemp)
    touch "$temp_authkeys"
    chmod 600 "$temp_authkeys"

    while true; do
        read -r -p "SSH 公钥: " pubkey
        [ -z "$pubkey" ] && break

        if ! echo "$pubkey" | grep -Eq '^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519(@openssh.com)?) [A-Za-z0-9+/=]+(\s.+)?$'; then
            echo -e "${RED}不支持的 SSH 公钥格式${NC}"
            continue
        fi

        key_content=$(echo "$pubkey" | awk '{print $1" "$2}')
        if grep -qF "$key_content" "$HOME/.ssh/authorized_keys"; then
            echo -e "${YELLOW}该公钥已存在${NC}"
        else
            echo "$pubkey" >> "$temp_authkeys"
            echo -e "${YELLOW}公钥已添加${NC}"
        fi
    done

    if [ -s "$temp_authkeys" ]; then
        grep -vFf <(awk '{print $1" "$2}' "$temp_authkeys") "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.tmp" || true
        cat "$temp_authkeys" >> "$HOME/.ssh/authorized_keys.tmp"
        mv "$HOME/.ssh/authorized_keys.tmp" "$HOME/.ssh/authorized_keys"
        chmod 600 "$HOME/.ssh/authorized_keys"
        echo -e "${YELLOW}新公钥已写入$(wc -l < "$temp_authkeys")个${NC}"
    else
        echo -e "${YELLOW}未添加新公钥${NC}"
    fi

    rm -f "$temp_authkeys"
}

process_ssh_keys

# 备份 SSH 配置
timestamp=$(date +%Y%m%d%H%M%S)
backup_file="/etc/ssh/sshd_config.bak.$timestamp"
sudo cp /etc/ssh/sshd_config "$backup_file"
echo -e "${YELLOW}原始配置已备份到 $backup_file${NC}"

read -r -d '' SSH_SECURITY_CONFIG <<'EOF'
# 安全配置
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
EOF

if [ "$use_config_dir" -eq 1 ]; then
    custom_file="$SSH_CONFIG_DIR/99-custom-hardening.conf"
    echo "$SSH_SECURITY_CONFIG" | sudo tee "$custom_file" > /dev/null
    echo -e "${YELLOW}配置写入 $custom_file${NC}"
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

echo -e "${YELLOW}验证 SSH 配置...${NC}"
if sudo sshd -t; then
    echo -e "${YELLOW}配置无误，正在重启 SSH 服务...${NC}"
    if systemctl list-units --type=service | grep -q sshd.service; then
        sudo systemctl restart sshd
    else
        sudo systemctl restart ssh || sudo service ssh restart
    fi
    echo -e "${YELLOW}SSH 服务已重启${NC}"
else
    echo -e "${RED}配置有误，请检查${NC}"
    exit 1
fi
