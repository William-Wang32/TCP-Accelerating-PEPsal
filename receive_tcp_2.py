#!/usr/bin/env python3
# server_receive.py
import socket
import struct
import os
import hashlib
import argparse

SERVER_BIND_IP = "192.168.1.2"   # 接收端 VM 的 IP（可改）
PORT = 5001
BUFFER_SIZE = 8192

def recv_all(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def handle_client(conn, addr):
    print(f"Connection from {addr}")
    # 先接 filename 长度（4 bytes, unsigned int, network byte order）
    raw = recv_all(conn, 4)
    if not raw:
        print("客户端提前断开")
        return
    (fname_len,) = struct.unpack("!I", raw)
    fname = recv_all(conn, fname_len).decode('utf-8')
    # 再接 filesize（8 bytes, unsigned long long）
    raw = recv_all(conn, 8)
    if not raw:
        print("客户端提前断开（filesize）")
        return
    (filesize,) = struct.unpack("!Q", raw)
    print(f"Receiving file: {fname} ({filesize} bytes)")

    # 保存文件到当前目录（若重复则加后缀）
    save_name = fname
    base, ext = os.path.splitext(save_name)
    i = 1
    while os.path.exists(save_name):
        save_name = f"{base}_dup{i}{ext}"
        i += 1

    md5 = hashlib.md5()
    received = 0
    with open(save_name, 'wb') as f:
        while received < filesize:
            to_read = min(BUFFER_SIZE, filesize - received)
            chunk = conn.recv(to_read)
            if not chunk:
                print("传输中断")
                break
            f.write(chunk)
            md5.update(chunk)
            received += len(chunk)
            # 可选进度显示
            print(f"\rReceived {received}/{filesize} bytes", end='')
    print()
    if received == filesize:
        checksum = md5.hexdigest()
        print(f"文件接收完成，保存为: {save_name}")
        # 发送回执与校验和
        msg = f"OK|{checksum}"
        conn.sendall(msg.encode('utf-8'))
    else:
        conn.sendall(b"ERR|incomplete")
    conn.close()

def main():
    parser = argparse.ArgumentParser(description='TCP file receiver. Defaults are set in the script but can be overridden here.')
    parser.add_argument('-i', '--bind-ip', dest='bind_ip', default=SERVER_BIND_IP,
                        help=f"IP address to bind to (default: {SERVER_BIND_IP})")
    parser.add_argument('-p', '--port', dest='port', type=int, default=PORT,
                        help=f"Port to listen on (default: {PORT})")
    args = parser.parse_args()

    bind_ip = args.bind_ip
    port = args.port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind_ip, port))
        s.listen(1)
        print(f"Listening on {bind_ip}:{port} ...")
        while True:
            conn, addr = s.accept()
            try:
                handle_client(conn, addr)
            except Exception as e:
                print("处理客户端出错:", e)
                try:
                    conn.close()
                except:
                    pass

if __name__ == "__main__":
    main()
