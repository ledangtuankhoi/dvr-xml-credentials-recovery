# -*- coding: utf-8 -*-
"""
Cong cu Quan ly Cau hinh & Giai ma Mat khau Camera SMEYE (Khong can XML)
"""

import os
import sys
import sqlite3
import shutil
import base64

# ponytail: Senior dev minimalism - pure AES decoder in 40 lines with zero external dependencies
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

def key_expansion(key):
    w = list(key)
    for i in range(4, 44):
        temp = w[(i-1)*4 : i*4]
        if i % 4 == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // 4]
        for j in range(4):
            w.append(w[(i-4)*4 + j] ^ temp[j])
    return w

def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mul(a, b):
    res = 0
    while b > 0:
        if b & 1: res ^= a
        a = xtime(a)
        b >>= 1
    return res

def inv_cipher_block(block, round_keys):
    state = [[block[r + 4*c] for c in range(4)] for r in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_keys[160 + c*4 + r]
    for round_num in range(9, 0, -1):
        state[1] = [state[1][3], state[1][0], state[1][1], state[1][2]]
        state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
        state[3] = [state[3][1], state[3][2], state[3][3], state[3][0]]
        for r in range(4):
            for c in range(4):
                state[r][c] = INV_SBOX[state[r][c]]
        for r in range(4):
            for c in range(4):
                state[r][c] ^= round_keys[round_num*16 + c*4 + r]
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = mul(s0, 0x0e) ^ mul(s1, 0x0b) ^ mul(s2, 0x0d) ^ mul(s3, 0x09)
            state[1][c] = mul(s0, 0x09) ^ mul(s1, 0x0e) ^ mul(s2, 0x0b) ^ mul(s3, 0x0d)
            state[2][c] = mul(s0, 0x0d) ^ mul(s1, 0x09) ^ mul(s2, 0x0e) ^ mul(s3, 0x0b)
            state[3][c] = mul(s0, 0x0b) ^ mul(s1, 0x0d) ^ mul(s2, 0x09) ^ mul(s3, 0x0e)
    state[1] = [state[1][3], state[1][0], state[1][1], state[1][2]]
    state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
    state[3] = [state[3][1], state[3][2], state[3][3], state[3][0]]
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_keys[c*4 + r]
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)

SMEYE_KEY = bytes.fromhex('9401e1c79aab479aad75cab3135f1fcd')
ROUND_KEYS = key_expansion(SMEYE_KEY)

def decrypt_smeye(b64_str):
    if not b64_str: return ""
    try:
        raw_ct = base64.b64decode(b64_str)
        if len(raw_ct) < 16: return b64_str
        b1 = inv_cipher_block(raw_ct[:16], ROUND_KEYS)
        b2 = inv_cipher_block(raw_ct[16:32], ROUND_KEYS) if len(raw_ct) >= 32 else b""
        return (b1 + b2).rstrip(b'\x00').decode('utf-8', errors='ignore')
    except Exception:
        return b64_str

DB_PATH = os.path.expandvars(r"%APPDATA%\Dvrsoft\SMEYE\smeye.db")
BACKUP_DEFAULT = os.path.join(os.path.expanduser("~"), "Desktop", "SMEYE_Cameras_Backup.db")

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)

def list_cameras():
    if not os.path.exists(DB_PATH):
        print("\n[!] Chua tim thay file du lieu smeye.db!")
        return []
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ID, Name, DeviceID, Address, IDType, Port, User, Password, ChannelNum, encode FROM TDevice ORDER BY ID ASC")
    rows = cursor.fetchall()
    conn.close()
    
    print("\n" + "="*95)
    print(f"{'ID':<4} | {'Ten Camera':<12} | {'Loai':<12} | {'Cloud ID / IP':<22} | {'User':<6} | {'Mat khau':<15} | {'Kenh':<4}")
    print("="*95)
    for r in rows:
        dev_id, name, dev_id_str, addr, id_type, port, user, pwd_raw, channels, enc = r
        type_str = "Cloud (P2P)" if id_type == 2 else "IP / Domain"
        target = dev_id_str if dev_id_str else addr
        plain_pw = decrypt_smeye(pwd_raw) if enc == 1 else pwd_raw
        print(f"{dev_id:<4} | {name:<12} | {type_str:<12} | {target:<22} | {user:<6} | {plain_pw:<15} | {channels:<4}")
    print("="*95)
    return rows

def add_camera_interactive():
    print("\n--- THEM CAMERA MOI (TU DONG KHONG CAN XML) ---")
    name = input("1. Nhap ten Camera (khong dau, vi du: Longthanh): ").strip()
    if not name:
        print("[!] Ten camera khong duoc de trong!")
        return

    print("2. Chon loai ket noi:")
    print("   [1] Ma Cloud P2P / GID (Day 20 ky tu, vi du: JC2W4JXG7MTPD53Y111A)")
    print("   [2] Dia chi IP WAN / Ten mien (Vi du: 14.224.131.254)")
    choice = input("   Lua chon (1 hoac 2) [Mac dinh 1]: ").strip()
    id_type = 0 if choice == "2" else 2

    addr_prompt = "3. Nhap ma Cloud ID (20 ky tu): " if id_type == 2 else "3. Nhap dia chi IP / Domain: "
    address = input(addr_prompt).strip()
    if not address:
        print("[!] Dia chi khong duoc de trong!")
        return

    port_input = input("4. Nhap Media Port (Mac dinh 9000): ").strip()
    port = int(port_input) if port_input.isdigit() else 9000
    user = input("5. Nhap User (Mac dinh admin): ").strip() or "admin"
    password = input("6. Nhap Password truc tiep: ").strip()
    channels_input = input("7. Nhap so luong kenh Camera (Mac dinh 32): ").strip()
    channel_num = int(channels_input) if channels_input.isdigit() else 32

    conn = get_connection()
    cursor = conn.cursor()
    dev_id_val = address if id_type == 2 else ""
    ip_addr_val = address if id_type == 0 else ""

    cursor.execute("""
        INSERT INTO TDevice (
            Address, DeviceID, IDType, Port, User, Password, ChannelNum,
            Name, IsVirtualDevice, Reserve1, Reserve2, Reserve3,
            Reserve4, Reserve5, Reserve6, FactoryType, encode
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, '', '', '', 0, 0)
    """, (ip_addr_val, dev_id_val, id_type, port, user, password, channel_num, name))
    
    device_id = cursor.lastrowid
    cursor.execute("SELECT ID FROM TGroup WHERE Name = 'DefaultGroup' LIMIT 1")
    group_row = cursor.fetchone()
    group_id = group_row[0] if group_row else 1

    for ch in range(channel_num):
        ch_name = f"CH{ch+1:02d}"
        cursor.execute("""
            INSERT INTO TGroupChannel (GroupID, DeviceID, Channel, Stream, ChannelName, ProtocolType)
            VALUES (?, ?, ?, 0, ?, 0)
        """, (group_id, device_id, ch, ch_name))

    conn.commit()
    conn.close()
    print(f"\n[OK] Da them thanh cong Camera '{name}' ({channel_num} kenh) vao SMEYE!")

def backup_db():
    if not os.path.exists(DB_PATH):
        print("[!] Chua co du lieu de sao luu!")
        return
    shutil.copy2(DB_PATH, BACKUP_DEFAULT)
    print(f"\n[OK] Da sao luu toan bo danh sach camera ra Desktop:\n    -> {BACKUP_DEFAULT}")

def restore_db():
    backup_file = input(f"\nNhap duong dan file sao luu [Nhan Enter neu dung Desktop]: ").strip()
    if not backup_file:
        backup_file = BACKUP_DEFAULT
    if not os.path.exists(backup_file):
        print(f"[!] File khong ton tai: {backup_file}")
        return
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    shutil.copy2(backup_file, DB_PATH)
    print(f"\n[OK] Da phuc hoi thanh cong danh sach camera vao SMEYE!")

def main_menu():
    while True:
        print("\n" + "="*50)
        print("   QUAN LY & XEM MAT KHAU CAMERA SMEYE")
        print("="*50)
        print(" [1] Xem danh sach & MAT KHAU camera (Da giai ma)")
        print(" [2] Them camera moi (Nhap pass truc tiep, khong can XML)")
        print(" [3] Sao luu danh sach camera ra Desktop (De dong bo sang may khac)")
        print(" [4] Phuc hoi danh sach camera tu file sao luu")
        print(" [5] Thoat")
        print("="*50)
        choice = input("Chon chuc nang (1-5): ").strip()
        if choice == "1":
            list_cameras()
        elif choice == "2":
            add_camera_interactive()
        elif choice == "3":
            backup_db()
        elif choice == "4":
            restore_db()
        elif choice == "5":
            print("\nTam biet!")
            break
        else:
            print("[!] Lua chon khong hop le.")

if __name__ == "__main__":
    main_menu()
