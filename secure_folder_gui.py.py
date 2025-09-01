# secure_folder_gui.py (v3.0) —— 批量加密 + 多线程 + 防卡顿
# 2024-06-20 by tangkaixing

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class SecureFolderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📁 文件夹批量加密/解密工具")
        self.root.geometry("850x750")
        self.root.resizable(True, True)
        self.selected_folder_paths = []  # 支持多个
        self.is_processing = False  # 防止重复运行

        self.setup_ui()

    def setup_ui(self):
        # === 标题区 ===
        title = tk.Label(
            self.root,
            text="🔐 文件夹安全卫士",
            font=("Microsoft YaHei", 16, "bold"),
            fg="darkblue"
        )
        title.pack(pady=10)

        desc = tk.Label(
            self.root,
            text="支持批量加密/解密，自动识别状态，后台运行不卡顿。",
            font=("Microsoft YaHei", 10),
            fg="gray"
        )
        desc.pack()

        # === 控制按钮区 ===
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)

        self.scan_btn = tk.Button(
            btn_frame, text="🔄 扫描当前目录", command=self.scan_folders,
            font=("微软雅黑", 10), bg="#007ACC", fg="white"
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.refresh_btn = tk.Button(
            btn_frame, text="⟳ 刷新列表", command=self.refresh_list,
            font=("微软雅黑", 10)
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        # === 文件夹列表（多选）===
        list_frame = tk.LabelFrame(self.root, text="可操作文件夹（支持多选）", padx=10, pady=10)
        list_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        self.folder_listbox = tk.Listbox(
            list_frame,
            height=10,
            width=90,
            font=("Consolas", 10),
            selectmode=tk.MULTIPLE,  # ← 关键：支持多选
            exportselection=False
        )
        self.scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.folder_listbox.yview)
        self.folder_listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.folder_listbox.pack(fill=tk.BOTH, expand=True)
        self.folder_listbox.bind('<<ListboxSelect>>', self.on_selection_change)

        # === 当前操作状态提示 ===
        self.status_var = tk.StringVar(value="📌 请选择要操作的文件夹")
        status_label = tk.Label(self.root, textvariable=self.status_var, fg="blue", font=("微软雅黑", 9))
        status_label.pack(pady=2)

        # === 文件处理进度 ===
        self.progress_var = tk.StringVar(value="")
        progress_label = tk.Label(self.root, textvariable=self.progress_var, fg="green", font=("微软雅黑", 9))
        progress_label.pack(pady=2)

        # === 密码区域 ===
        password_frame = tk.LabelFrame(self.root, text="密码输入", padx=15, pady=10)
        password_frame.pack(padx=20, pady=10, fill=tk.X)

        # 加密密码
        tk.Label(password_frame, text="加密密码：", font=("微软雅黑", 9)).grid(row=0, column=0, sticky='w', pady=2)
        self.pw_entry1 = tk.Entry(password_frame, width=45, show='*', font=("Consolas", 10))
        self.pw_entry1.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(password_frame, text="确认密码：", font=("微软雅黑", 9)).grid(row=1, column=0, sticky='w', pady=2)
        self.pw_entry2 = tk.Entry(password_frame, width=45, show='*', font=("Consolas", 10))
        self.pw_entry2.grid(row=1, column=1, padx=5, pady=2)

        # 解密密码
        tk.Label(password_frame, text="解密密码：", font=("微软雅黑", 9)).grid(row=2, column=0, sticky='w', pady=2)
        self.pw_decrypt_entry = tk.Entry(password_frame, width=45, show='*', font=("Consolas", 10))
        self.pw_decrypt_entry.grid(row=2, column=1, padx=5, pady=2)

        self.hide_password_fields()

        # === 操作按钮 ===
        action_frame = tk.Frame(self.root)
        action_frame.pack(pady=10)

        self.lock_btn = tk.Button(
            action_frame, text="🔒 批量加密", command=self.start_encrypt_thread,
            font=("微软雅黑", 10), bg="red", fg="white", width=20, state=tk.DISABLED
        )
        self.lock_btn.pack(side=tk.LEFT, padx=10)

        self.unlock_btn = tk.Button(
            action_frame, text="🔓 批量解密", command=self.start_decrypt_thread,
            font=("微软雅黑", 10), bg="green", fg="white", width=20, state=tk.DISABLED
        )
        self.unlock_btn.pack(side=tk.LEFT, padx=10)

        # === 日志输出 ===
        log_frame = tk.LabelFrame(self.root, text="操作日志", padx=10, pady=10)
        log_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=12, font=("Consolas", 9), bg="#f4f4f4"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # 启动扫描
        self.scan_folders()

    def log(self, msg):
        self.log_text.insert(tk.END, f"{msg}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def scan_folders(self):
        self.folder_listbox.delete(0, tk.END)
        self.log_text.delete(1.0, tk.END)
        self.selected_folder_paths.clear()
        self.hide_password_fields()
        self.reset_buttons()
        self.status_var.set("📌 正在扫描...")

        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.log(f"🔍 扫描路径: {base_dir}")

        try:
            entries = os.listdir(base_dir)
        except PermissionError:
            messagebox.showerror("权限错误", f"无法访问: {base_dir}")
            self.status_var.set("❌ 扫描失败")
            return
        except Exception as e:
            messagebox.showerror("错误", f"读取目录失败: {e}")
            self.status_var.set("❌ 扫描失败")
            return

        folders = []
        for entry in entries:
            path = os.path.join(base_dir, entry)
            if os.path.isdir(path) and not entry.startswith('.'):
                salt_file = os.path.join(path, '.salt')
                has_locked = any(f.endswith('.locked') for f in os.listdir(path))
                if os.path.exists(salt_file) and has_locked:
                    status = "🔒 已加锁（可解密）"
                elif not os.path.exists(salt_file):
                    status = "🔓 未加锁（可加密）"
                else:
                    status = "⚠️ 状态异常"
                folders.append((entry, status, path))

        if not folders:
            self.log("📭 无可用文件夹")
            self.status_var.set("📭 未发现可操作文件夹")
        else:
            for name, status, _ in sorted(folders):
                display = f"{name:<30} | {status}"
                self.folder_listbox.insert(tk.END, display)
            self.status_var.set(f"✅ 共发现 {len(folders)} 个文件夹")

    def refresh_list(self):
        self.scan_folders()

    def on_selection_change(self, event=None):
        """选择变化时更新按钮和密码区"""
        selection = self.folder_listbox.curselection()
        if not selection:
            self.hide_password_fields()
            self.reset_buttons()
            return

        self.selected_folder_paths = []
        has_encryptable = False
        has_decryptable = False

        for i in selection:
            line = self.folder_listbox.get(i)
            status = line.split('|')[1].strip()
            path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), line.split('|')[0].strip())
            self.selected_folder_paths.append(path)
            if "未加锁" in status:
                has_encryptable = True
            if "已加锁" in status:
                has_decryptable = True

        self.update_password_fields(has_encryptable, has_decryptable)

    def update_password_fields(self, can_encrypt, can_decrypt):
        """根据选择动态显示密码输入框"""
        self.hide_password_fields()

        if can_encrypt and not can_decrypt:
            self.show_encrypt_password()
            self.lock_btn.config(state=tk.NORMAL)
            self.unlock_btn.config(state=tk.DISABLED)
            self.status_var.set(f"📌 已选 {len(self.selected_folder_paths)} 个文件夹（加密模式）")
        elif can_decrypt and not can_encrypt:
            self.show_decrypt_password()
            self.unlock_btn.config(state=tk.NORMAL)
            self.lock_btn.config(state=tk.DISABLED)
            self.status_var.set(f"📌 已选 {len(self.selected_folder_paths)} 个文件夹（解密模式）")
        elif can_encrypt and can_decrypt:
            self.hide_password_fields()
            self.reset_buttons()
            self.status_var.set("❌ 混合状态：请只选加密或解密的文件夹")
            messagebox.showwarning("提示", "请不要同时选择加密和未加密的文件夹！")
        else:
            self.reset_buttons()

    def hide_password_fields(self):
        for widget in [self.pw_entry1, self.pw_entry2, self.pw_decrypt_entry]:
            widget.grid_remove()
        for label in self.root.option_get('text', '').split():
            try:
                self.root.nametowidget(f'.!labelframe2.!label{label}').grid_remove()
            except:
                pass
        for i in range(3):
            self.root.grid_columnconfigure(i, weight=0)

    def show_encrypt_password(self):
        self.pw_entry1.grid()
        self.pw_entry2.grid()
        self.root.grid_columnconfigure(1, weight=1)
        self.pw_entry1.focus()

    def show_decrypt_password(self):
        self.pw_decrypt_entry.grid()
        self.root.grid_columnconfigure(1, weight=1)
        self.pw_decrypt_entry.focus()

    def reset_buttons(self):
        self.lock_btn.config(state=tk.DISABLED)
        self.unlock_btn.config(state=tk.DISABLED)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_folder(self, folder_path: str, key: bytes):
        """加密整个文件夹"""
        salt = os.urandom(16)
        salt_path = os.path.join(folder_path, '.salt')
        try:
            with open(salt_path, 'wb') as f:
                f.write(salt)
            folder_key = self.derive_key(key.decode(), salt)
        except Exception as e:
            self.log(f"❌ {os.path.basename(folder_path)} 密钥生成失败: {e}")
            return False

        success = True
        for root_dir, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root_dir, file)
                if file == '.salt' or file.endswith('.locked'):
                    continue
                try:
                    self.progress_var.set(f"🔐 加密: {file}")
                    self.encrypt_file(file_path, folder_key)
                except Exception as e:
                    self.log(f"❌ 跳过 {file}: {e}")
                    success = False
        return success

    def decrypt_folder(self, folder_path: str, key: bytes):
        salt_path = os.path.join(folder_path, '.salt')
        if not os.path.exists(salt_path):
            self.log(f"❌ {os.path.basename(folder_path)} 缺少 .salt 文件")
            return False

        try:
            with open(salt_path, 'rb') as f:
                salt = f.read()
            folder_key = self.derive_key(key.decode(), salt)
        except Exception as e:
            self.log(f"❌ {os.path.basename(folder_path)} 密钥派生失败: {e}")
            return False

        # 获取所有 .locked 文件
        locked_files = []
        for root_dir, _, files in os.walk(folder_path):
            for f in files:
                if f.endswith('.locked'):
                    locked_files.append(os.path.join(root_dir, f))

        if not locked_files:
            self.log(f"🟢 {os.path.basename(folder_path)} 无需解密（无 .locked 文件）")
            return True  # 可视为成功

        success = True
        for lf in locked_files:
            try:
                self.progress_var.set(f"🔓 解密: {os.path.basename(lf)}")
                self.decrypt_file(lf, folder_key)  # 里面已包含删除逻辑
            except Exception as e:
                self.log(f"❌ 解密失败 {os.path.basename(lf)}: {e}")
                success = False

        # ✅ 只有全部解密成功，才删除 .salt
        if success:
            try:
                os.remove(salt_path)
                self.log(f"🗑️ 已清除密钥文件: {os.path.basename(folder_path)}/.salt")
            except Exception as e:
                self.log(f"⚠️ 无法删除 .salt 文件: {e}")
                success = False  # 不应阻止整体成功，但记录警告

        return success


    def encrypt_file(self, file_path: str, key: bytes):
        with open(file_path, 'rb') as f:
            data = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padding_len = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_len]) * padding_len
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        with open(file_path + '.locked', 'wb') as f:
            f.write(iv + encrypted_data)
        os.remove(file_path)

    def decrypt_file(self, locked_path: str, key: bytes):
        try:
            with open(locked_path, 'rb') as f:
                raw = f.read()
            if len(raw) < 16:
                raise ValueError("文件太小，无法解密")

            iv, cipher_data = raw[:16], raw[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(cipher_data) + decryptor.finalize()

            pad_len = padded_data[-1]
            if not (1 <= pad_len <= 16):
                raise ValueError("无效填充长度")

            data = padded_data[:-pad_len]
            original_path = locked_path[:-7]  # 移除 '.locked'

            # 写入原始文件
            with open(original_path, 'wb') as f:
                f.write(data)

            # ✅【核心修复】解密成功后立即删除 .locked 文件
            os.remove(locked_path)
            self.log(f"🗑️ 已删除加密文件: {os.path.basename(locked_path)}")

        except Exception as e:
            self.log(f"❌ 解密失败 {os.path.basename(locked_path)}: {e}")
            raise  # 向上抛出，便于批量控制


    def start_encrypt_thread(self):
        if self.is_processing:
            return
        pwd1 = self.pw_entry1.get().strip()
        pwd2 = self.pw_entry2.get().strip()
        if not pwd1 or not pwd2:
            messagebox.showwarning("输入错误", "密码不能为空！")
            return
        if pwd1 != pwd2:
            messagebox.showerror("错误", "两次密码不一致！")
            return
        if len(pwd1) < 4:
            if not messagebox.askyesno("提示", "密码太短，是否继续？"):
                return

        thread = threading.Thread(target=self.batch_encrypt, args=(pwd1.encode(),), daemon=True)
        thread.start()

    def start_decrypt_thread(self):
        if self.is_processing:
            return
        password = self.pw_decrypt_entry.get().strip()
        if not password:
            messagebox.showwarning("输入错误", "请输入解密密码！")
            return

        thread = threading.Thread(target=self.batch_decrypt, args=(password.encode(),), daemon=True)
        thread.start()

    def batch_encrypt(self, password: bytes):
        self.set_processing(True)
        self.log("🚀 开始批量加密...")
        success_count = 0
        total = len(self.selected_folder_paths)

        for i, path in enumerate(self.selected_folder_paths):
            self.status_var.set(f"📦 正在处理 ({i+1}/{total}): {os.path.basename(path)}")
            if self.encrypt_folder(path, password):
                self.log(f"✅ 成功加密: {os.path.basename(path)}")
                success_count += 1
            else:
                self.log(f"❌ 部分失败: {os.path.basename(path)}")

        self.log(f"🎉 批量加密完成：{success_count}/{total} 成功")
        self.set_processing(False)
        messagebox.showinfo("完成", f"加密完成：{success_count}/{total} 个文件夹")
        self.scan_folders()

    def batch_decrypt(self, password: bytes):
        self.set_processing(True)
        self.log("🚀 开始批量解密...")
        success_count = 0
        total = len(self.selected_folder_paths)

        for i, path in enumerate(self.selected_folder_paths):
            self.status_var.set(f"📦 正在处理 ({i+1}/{total}): {os.path.basename(path)}")
            if self.decrypt_folder(path, password):
                self.log(f"✅ 成功解密: {os.path.basename(path)}")
                success_count += 1
            else:
                self.log(f"❌ 解密失败: {os.path.basename(path)}")

        self.log(f"🎉 批量解密完成：{success_count}/{total} 成功")
        self.set_processing(False)
        messagebox.showinfo("完成", f"解密完成：{success_count}/{total} 个文件夹")
        self.scan_folders()

    def set_processing(self, processing: bool):
        """启用/禁用界面元素"""
        self.is_processing = processing
        state = tk.DISABLED if processing else tk.NORMAL
        for btn in [self.scan_btn, self.refresh_btn, self.lock_btn, self.unlock_btn]:
            btn.config(state=state)
        self.progress_var.set("⏳ 处理中，请勿关闭..." if processing else "")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFolderApp(root)
    root.mainloop()