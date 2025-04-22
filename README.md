# OpsToolkit 🛠️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![ShellCheck](https://github.com/xiaweian/OpsToolkit/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/xiaweian/OpsToolkit/actions)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)

> 系统运维与安全自动化工具集 | 适用于Linux服务器环境

---

## 🚀 快速开始

### 基本要求
- **Bash 5.0+**
- **sudo权限**
- **OpenSSH 8.0+**（SSH加固脚本需要）

```bash
# 克隆仓库
git clone https://github.com/xiaweian/OpsToolkit.git
cd OpsToolkit

# 执行SSH加固脚本（示例）
sudo ./SSH-Hardening/hardened_ssh_config.sh


---

## 📂 脚本目录

| 模块                | 描述                               | 关键功能                          |
|---------------------|------------------------------------|-----------------------------------|
| [SSH-Hardening]     | SSH服务安全配置                    | 禁用密码登录/FIDO2支持/加密算法   |
| [System-Lockdown]   | 系统基础安全加固                   | 内核参数/服务禁用/文件权限        |
| [Network-Scanner]   | 网络诊断工具集                     | 端口扫描/流量分析/连接监控        |
| [Log-Monitor]       | 实时日志分析                       | 异常登录检测/暴力破解防护         |

[SSH-Hardening]: /SSH-Hardening
[System-Lockdown]: /System-Lockdown
[Network-Scanner]: /Network-Scanner
[Log-Monitor]: /Log-Monitor

---

## 🔐 SSH加固脚本特性

```text
🛡️ 安全增强
✓ 强制公钥认证 + 禁用密码登录
✓ 硬件安全密钥(FIDO2/U2F)支持
✓ 仅允许现代加密算法(ChaCha20,AES-GCM)

⚙️ 智能功能
✓ 配置前自动验证SSH版本兼容性
✓ 原子化操作防止中间状态
✓ 带时间戳的自动备份(/etc/ssh/sshd_config.bak.*)
```

---

## 🛠️ 使用方法

### 1. 预览模式（Dry Run）
```bash
./SSH-Hardening/hardened_ssh_config.sh --dry-run
```

### 2. 自定义公钥源
```bash
# 从指定文件导入公钥
./SSH-Hardening/hardened_ssh_config.sh -k ~/custom_keys.txt
```

### 3. 恢复默认配置
```bash
sudo cp /etc/ssh/sshd_config.bak.20240325 /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## ⚠️ 注意事项

1. **生产环境建议**  
   - 先在测试环境验证脚本
   - 保留至少两个活跃SSH连接会话

2. 硬件密钥要求  
   ```text
   - 需要支持ED25519-SK算法的安全密钥
   - 例如：YubiKey 5系列以上
   ```

3. 系统兼容性  
   ```text
   ✅ Ubuntu 20.04+/Debian 11+
   ✅ CentOS/RHEL 8+
   ⚠️  macOS需手动调整部分参数
   ```

---

## 🤝 参与贡献

1. 提交Issue报告问题或建议
2. Fork仓库并创建特性分支
3. 提交Pull Request

遵循[贡献指南](CONTRIBUTING.md)的代码规范

---

## 📜 许可证

MIT License © 2024 [Your Name]  
完整文本见 [LICENSE](LICENSE) 文件

---

> 📌 **提示**：所有脚本应在理解其功能的前提下使用，作者不对误操作导致的后果负责。
```
