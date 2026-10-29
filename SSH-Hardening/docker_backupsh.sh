#!/bin/bash

# --- 配置区域 ---
BACKUP_DIR="/opt/backup/temp"       # 临时存放压缩包的目录
HOST_NAME=$(hostname)               # 获取当前主机名
DATE=$(date +"%Y%m%d_%H%M%S")       # 时间戳
# 将主机名拼接到压缩包名字中，例如：docker_backup_debian-node1_20261029_071300.tar.gz
ARCHIVE_NAME="docker_backup_${HOST_NAME}_$DATE.tar.gz"
KEEP_DAYS=7                         # 本地保留最近几天的备份

# 目标网盘配置（请根据你实际的 rclone 远程名称修改，注意后面带冒号）
RCLONE_REMOTE="webdav:docker_backups" 

# --- 执行步骤 ---

# 1. 创建临时目录
mkdir -p "$BACKUP_DIR"

echo "[$(date)] 开始打包主機 [$HOST_NAME] 的 Docker 配置与数据..."

# 2. 打包 /root 目录下的 docker-compose.yml 和 data 文件夹
tar -czf "$BACKUP_DIR/$ARCHIVE_NAME" -C /root --exclude="data/*/data/*.log" docker-compose.yml data

if [ $? -eq 0 ]; then
    echo "[$(date)] 打包成功: $ARCHIVE_NAME"
else
    echo "[$(date)] 打包失败！"
    exit 1
fi

# 3. 上传到网盘/对象存储
echo "[$(date)] 正在上传备份到网盘..."
rclone copy "$BACKUP_DIR/$ARCHIVE_NAME" "$RCLONE_REMOTE" --progress

if [ $? -eq 0 ]; then
    echo "[$(date)] 上传成功！"
else
    echo "[$(date)] 上传失败！"
    exit 1
fi

# 4. 清理本地过期的临时压缩包
rm -f "$BACKUP_DIR/$ARCHIVE_NAME"

# 5. 清理本地保留超过 $KEEP_DAYS 天的旧备份
find "$BACKUP_DIR" -type f -name "docker_backup_${HOST_NAME}_*.tar.gz" -mtime +$KEEP_DAYS -exec rm -f {} \;

echo "[$(date)] 备份任务全部完成。"