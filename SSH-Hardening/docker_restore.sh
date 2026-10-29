#!/bin/bash

# --- 配置区域 ---
RESTORE_DIR="/opt/backup/temp_restore"  # 临时下载和解压目录
RCLONE_REMOTE="infinicloud:docker_backups" # 你的网盘远程路径（带冒号）
TARGET_DIR="/root"                      # Docker 部署的目标根目录

# --- 执行步骤 ---

echo "=========================================="
echo "       Docker 备份一键还原工具"
echo "=========================================="

# 1. 检查 rclone 配置是否存在
if ! rclone listremotes | grep -q "infinicloud:"; then
    echo "[错误] 未检测到 rclone 远程配置 'infinicloud:'，请先检查 rclone 配置！"
    exit 1
fi

# 2. 从网盘获取最新的备份文件列表
echo "正在从网盘获取备份文件列表..."
LATEST_FILE=$(rclone lsf "$RCLONE_REMOTE" --files-only --max-age 365d | grep "docker_backup_" | sort | tail -n 1)

if [ -z "$LATEST_FILE" ]; then
    echo "[错误] 在网盘中没有找到任何匹配的备份文件！"
    exit 1
fi

echo "找到网盘中最新的备份文件: $LATEST_FILE"
read -p "是否确认还原该备份？(y/N): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "已取消还原操作。"
    exit 0
fi

# 3. 创建临时目录并下载备份
mkdir -p "$RESTORE_DIR"
echo "正在从网盘下载备份文件到本地..."
rclone copy "$RCLONE_REMOTE/$LATEST_FILE" "$RESTORE_DIR" --progress

if [ ! -f "$RESTORE_DIR/$LATEST_FILE" ]; then
    echo "[错误] 下载备份文件失败！"
    exit 1
fi

# 4. 停止当前正在运行的容器（如果在 /root 下存在 docker-compose）
if [ -f "$TARGET_DIR/docker-compose.yml" ]; then
    echo "检测到当前系统存在旧的 Docker Compose 配置，正在尝试停止容器..."
    cd "$TARGET_DIR" && docker compose down 2>/dev/null || true
fi

# 5. 解压并还原文件到 /root 目录
echo "正在解压并恢复文件到 $TARGET_DIR..."
tar -xzf "$RESTORE_DIR/$LATEST_FILE" -C "$TARGET_DIR"

if [ $? -eq 0 ]; then
    echo "[成功] 文件还原完成！"
else
    echo "[错误] 解压还原失败！"
    exit 1
fi

# 6. 清理本地临时下载的文件
rm -rf "$RESTORE_DIR"

# 7. 询问是否立即启动容器
read -p "是否现在执行 'docker compose up -d' 启动容器？(y/N): " START_CONFIRM
if [[ "$START_CONFIRM" == "y" || "$START_CONFIRM" == "Y" ]]; then
    cd "$TARGET_DIR"
    echo "正在启动 Docker 容器..."
    docker compose up -d
    echo "容器启动命令已发送，请用 'docker ps' 查看运行状态。"
else
    echo "还原结束。你可以稍后自行进入 /root 目录执行 'docker compose up -d' 启动。"
fi