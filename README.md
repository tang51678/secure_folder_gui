# 🔐 文件加密工具GUI —— 安全、简单、无依赖

> 📁 图形化批量加密/解密工具 | 适用于非程序员 | 支持单文件 `.exe` 发布

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![PyInstaller](https://img.shields.io/badge/Packaged-PyInstaller-green)
![License](https://img.shields.io/badge/License-MIT-orange)

一个使用 Python 编写的图形化文件夹加解密工具，支持 **批量操作** + **多线程不卡顿** + **无命令行黑框**，非程序员也能轻松保护隐私文件。

---

## 🎯 功能亮点

- ✅ **GUI 图形界面**：无需命令行，双击即可使用
- ✅ **自动扫描当前目录下所有文件夹**
- ✅ **智能识别状态**：
  - 🔒 已加密 → 可解密
  - 🔓 未加密 → 可加密
- ✅ **支持多文件夹同时加解密**
- ✅ **内嵌密码输入框**：无弹窗，操作流畅
- ✅ **多线程处理**：大文件也不卡顿、不无响应
- ✅ **高安全性**：
  - AES-256-CBC 加密
  - PBKDF2-HMAC-SHA256 密钥派生
  - 每次加密使用随机 salt 和 IV
- ✅ **解密后自动删除 `.locked` 文件**，避免冗余
- ✅ 一键打包成 `.exe`，方便分发给家人朋友使用

---

## 🖼️ 界面预览

<img width="836" height="765" alt="image" src="https://github.com/user-attachments/assets/34c64db2-30db-42bb-8c48-1236f7abb733" />


---

## 🚀 使用方法

### 1. 本地运行（开发者模式）

```bash
# 安装依赖
pip install cryptography

# 运行脚本
python secure_folder_gui.py
