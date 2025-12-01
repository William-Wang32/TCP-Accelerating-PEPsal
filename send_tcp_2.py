#!/usr/bin/env python3
# client_send_verbose.py
"""
用法:
  python3 client_send_verbose.py /path/to/file --server 192.168.1.2 --port 5000
可选参数:
  --buffer N        每次读/发的字节数（默认 8192）
  --csv-log FILE    将每个 chunk 的发包统计写入 CSV（便于后续分析）
"""

import socket
import struct
import sys
import os
import hashlib
import time
from datetime import datetime
import argparse
import csv

DEFAULT_SERVER_IP = "192.168.1.2"
DEFAULT_PORT = 5001
DEFAULT_BUFFER = 8192

def compute_md5(path, bufsize=65536):
    m = hashlib.md5()
    with open(path, 'rb') as f:
        while True:
            blk = f.read(bufsize)
            if not blk:
                break
            m.update(blk)
    return m.hexdigest()

def human_seconds(s):
    # 格式化秒数为带 3 位小数的字符串
    return f"{s:.3f}s"

def iso_now():
    return datetime.now().isoformat(sep=' ', timespec='milliseconds')

def send_file_verbose(filepath, server_ip, port, buffer_size, csv_log=None, timeout=10, verbose=True):
    """发送文件到服务器。verbose=True 时在 stdout 输出过程信息，verbose=False 则抑制普通信息输出（错误仍输出到 stderr）。"""
    def info_print(*a, **kw):
        if verbose:
            print(*a, **kw)

    def err_print(*a, **kw):
        # 错误信息始终打印到 stderr
        print(*a, file=sys.stderr, **kw)

    if not os.path.isfile(filepath):
        err_print("找不到文件:", filepath)
        return
    fname = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    info_print(f"[{iso_now()}] 准备发送: {fname} ({filesize} bytes) -> {server_ip}:{port}")
    local_md5 = compute_md5(filepath)
    info_print(f"[{iso_now()}] 本地 MD5: {local_md5}")

    stats_rows = []
    total_sent = 0
    try:
        # 记录连接时间
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            sock.connect((server_ip, port))
        except Exception as e:
            err_print(f"[{iso_now()}] 连接失败: {e}")
            sock.close()
            return
        t1 = time.perf_counter()
        connect_time = t1 - t0
        print(f"[{iso_now()}] TCP connect 成功 (耗时 {human_seconds(connect_time)})")

        # 发送文件元信息（filename len + filename + filesize）
        fname_bytes = fname.encode('utf-8')
        sock.sendall(struct.pack("!I", len(fname_bytes)))
        sock.sendall(fname_bytes)
        sock.sendall(struct.pack("!Q", filesize))

        # 逐 chunk 发送并记录时间
        send_start_total = time.perf_counter()
        with open(filepath, 'rb') as f:
            chunk_idx = 0
            while True:
                chunk = f.read(buffer_size)
                if not chunk:
                    break
                chunk_idx += 1
                chunk_len = len(chunk)

                cs = time.perf_counter()
                try:
                    sock.sendall(chunk)
                except BrokenPipeError:
                    info_print(f"[{iso_now()}] 发送时连接被对端关闭")
                    # break
                ce = time.perf_counter()
                dur = ce - cs
                total_sent += chunk_len
                # 计算瞬时吞吐（字节/秒），若 dur 非零
                inst_tp = (chunk_len / dur) if dur > 0 else float('inf')
                avg_tp = (total_sent / (ce - send_start_total)) if (ce - send_start_total) > 0 else float('inf')

                # 命令行输出当前 chunk 的信息（可选）
                info_print(f"[{iso_now()}] CHK#{chunk_idx:04d} sent {chunk_len} bytes | "
                           f"chunk_time={human_seconds(dur)} | inst_tp={inst_tp:.0f} B/s | "
                           f"cumulative={total_sent}/{filesize} B | avg_tp={avg_tp:.0f} B/s")

                # 保存到 stats_rows（用于 CSV）
                stats_rows.append({
                    'time': iso_now(),
                    'chunk_idx': chunk_idx,
                    'chunk_len': chunk_len,
                    'chunk_time_s': dur,
                    'inst_bps': inst_tp,
                    'cumulative_sent': total_sent
                })

        send_end_total = time.perf_counter()
        total_send_duration = send_end_total - send_start_total
        print(f"[{iso_now()}] 发送完成：总发送字节 {total_sent} bytes, 总耗时 {human_seconds(total_send_duration)}, "
                   f"平均吞吐 { (total_sent / total_send_duration) if total_send_duration>0 else 0 :.0f} B/s")

        # 写 CSV（如果需要）
        if csv_log:
            with open(csv_log, 'w', newline='', encoding='utf-8') as csvf:
                fieldnames = ['time', 'chunk_idx', 'chunk_len', 'chunk_time_s', 'inst_bps', 'cumulative_sent']
                writer = csv.DictWriter(csvf, fieldnames=fieldnames)
                writer.writeheader()
                for r in stats_rows:
                    writer.writerow(r)
            info_print(f"[{iso_now()}] 已写 CSV 日志: {csv_log}")

        # 在发送全部数据后等待服务器回执，记录接收时间与长度
        recv_start = time.perf_counter()
        try:
            # 设一个小 timeout 来避免无限阻塞（可以按需改）
            sock.settimeout(timeout)
            resp = sock.recv(4096)
            recv_end = time.perf_counter()
            if resp is None:
                info_print(f"[{iso_now()}] 未收到服务器回执")
            else:
                resp_len = len(resp)
                resp_text = resp.decode('utf-8', errors='replace')
                rtt = recv_end - send_end_total  # 从发送结束到收到回执的间隔（近似）
                recv_dur = recv_end - recv_start
                info_print(f"[{iso_now()}] 收到服务器回执: {resp_len} bytes | 内容: {resp_text} | "
                           f"recv_time={human_seconds(recv_dur)} | time_since_send_end={human_seconds(rtt)}")
                # 若返回 OK|md5，则对比
                if resp_text.startswith("OK|"): 
                    server_md5 = resp_text.split("|",1)[1].strip()
                    if server_md5 == local_md5:
                        info_print(f"[{iso_now()}] 校验成功：本地 MD5 与 服务器一致 ({server_md5})")
                    else:
                        info_print(f"[{iso_now()}] 校验失败：本地 {local_md5} <> 服务器 {server_md5}")
                else:
                    info_print(f"[{iso_now()}] 服务器回执非 OK: {resp_text}")
        except socket.timeout:
            recv_end = time.perf_counter()
            err_print(f"[{iso_now()}] 等待服务器回执超时（{timeout}s），从发送结束到超时 {human_seconds(recv_end - send_end_total)}")
        except Exception as e:
            recv_end = time.perf_counter()
            err_print(f"[{iso_now()}] 接收回执时出错: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

    # 最终汇总
    total_time_all = (recv_end - t0) if 'recv_end' in locals() else (time.perf_counter() - t0)
    print(f"[{iso_now()}] 会话结束，总耗时(从连接开始) {human_seconds(total_time_all)}，连接建立耗时 {human_seconds(connect_time)}")

def parse_args():
    p = argparse.ArgumentParser(description="Verbose TCP file sender with per-chunk logging")
    p.add_argument('file', help='要发送的文件路径')
    p.add_argument('--server', '-s', default=DEFAULT_SERVER_IP, help='接收端 IP (default: %(default)s)')
    p.add_argument('--port', '-p', default=DEFAULT_PORT, type=int, help='接收端端口 (default: %(default)s)')
    p.add_argument('--buffer', '-b', default=DEFAULT_BUFFER, type=int, help='每次读取/发送的 bytes (default: %(default)s)')
    p.add_argument('--csv-log', help='可选：写入 CSV 日志文件（每个 chunk 一行）')
    p.add_argument('--no-output', dest='no_output', action='store_true', help='不在终端输出进度信息（只写 CSV 或静默运行）')
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    send_file_verbose(args.file, args.server, args.port, args.buffer, csv_log=args.csv_log, verbose=(not args.no_output))
