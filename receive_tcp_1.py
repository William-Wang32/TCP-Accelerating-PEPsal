#!/usr/bin/env python3
"""简单的 TCP ACK 测试服务器。

默认绑定到 192.168.1.3:5000，接收数据后回送 b'ACK'。支持可选命令行参数 --host 和 --port 和 --raw-ack。
"""
import argparse
import socket
import sys
try:
    # scapy 用于构造并发送原始 TCP 报文（需要 root 权限）
    from scapy.all import sniff, IP, TCP, Raw, send
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False


def main():
    parser = argparse.ArgumentParser(description="简单的 TCP ACK 测试服务器（接收并返回 'ACK'）")
    parser.add_argument("--host", default="192.168.1.2", help="要绑定的主机，默认 192.168.1.2")
    parser.add_argument("--port", type=int, default=5000, help="要绑定的端口，默认 5000")
    parser.add_argument("--raw-ack", action="store_true", default=True,
                        help="尝试发送原始 TCP 报文作为 ACK（默认开启；需要 scapy 与 root 权限）；失败时回退到发送 b'ACK' 字节串。传入 --raw-ack 可保留此行为。")
    args = parser.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 允许重用地址，方便重复运行测试
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((args.host, args.port))
    except Exception as e:
        print(f"无法绑定到 {args.host}:{args.port}：{e}")
        sys.exit(2)

    s.listen(1)
    print(f"ACK server listening on {args.host}:{args.port}")

    try:
        conn, addr = s.accept()
        print('Connected by', addr)
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    print('Client closed connection')
                    break
                print('Server received:', data.decode('utf-8', errors='replace'))
                # 回送 ACK：默认为应用层字串 b'ACK'；若指定 --raw-ack，尝试发送原始 TCP 报文（仅在 scapy 可用且有权限时）
                if args.raw_ack:
                    if not HAVE_SCAPY:
                        print('scapy 未安装或不可用，回退到发送 b"ACK"')
                        try:
                            conn.sendall(b'ACK')
                        except BrokenPipeError:
                            print('BrokenPipe when sending ACK')
                            break
                    else:
                        # 发送原始 TCP ACK 报文的尽量保守实现：先抓取客户端刚发来的一个包，
                        # 从中读取 seq/ack 与负载长度，然后构造一个带 ACK 标志的 TCP 报文发送回去。
                        # 注意：在内核 TCP 栈仍然管理该连接时发送原始报文可能导致不一致（仅作测试用）。
                        try:
                            # 监听来自客户端到本服务器端口的最近一条 TCP 包，以获取 seq/ack
                            bpf = f"tcp and src host {addr[0]} and src port {addr[1]} and dst port {args.port}"
                            pkts = sniff(filter=bpf, timeout=2, count=1)
                            if not pkts:
                                print('未捕获到客户端数据包，回退到发送 b"ACK"')
                                try:
                                    conn.sendall(b'ACK')
                                except BrokenPipeError:
                                    print('BrokenPipe when sending ACK')
                                    break
                            else:
                                pkt = pkts[0]
                                if TCP not in pkt:
                                    print('捕获到的包不是 TCP，回退到发送 b"ACK"')
                                    try:
                                        conn.sendall(b'ACK')
                                    except BrokenPipeError:
                                        print('BrokenPipe when sending ACK')
                                        break
                                else:
                                    # 从捕获包读取必要字段
                                    client_seq = int(pkt[TCP].seq)
                                    client_ack = int(pkt[TCP].ack)
                                    # 数据长度（TCP payload）
                                    try:
                                        data_len = len(bytes(pkt[TCP].payload))
                                    except Exception:
                                        data_len = 0

                                    # 本端套接字的本地地址/端口
                                    local_ip, local_port = conn.getsockname()

                                    # 构造 TCP ACK：seq 使用客户端对我方的 ack（pkt[TCP].ack），
                                    # ack 使用客户端 seq + 数据长度
                                    server_seq = client_ack
                                    server_ack = client_seq + data_len

                                    ip = IP(src=local_ip, dst=addr[0])
                                    tcp = TCP(sport=local_port, dport=addr[1], flags='A', seq=server_seq, ack=server_ack)
                                    raw_pkt = ip / tcp
                                    # 发送原始 TCP 报文
                                    send(raw_pkt, verbose=True)
                                    print(f'Sent raw TCP ACK (seq={server_seq}, ack={server_ack}) to {addr}')
                        except PermissionError:
                            print('权限不足（需要 root）以发送原始报文，回退到发送 b"ACK"')
                            try:
                                conn.sendall(b'ACK')
                            except BrokenPipeError:
                                print('BrokenPipe when sending ACK')
                                break
                        except Exception as e:
                            print('发送原始 TCP 报文时出错，回退到发送 b"ACK"，错误：', e)
                            try:
                                conn.sendall(b'ACK')
                            except BrokenPipeError:
                                print('BrokenPipe when sending ACK')
                                break
                else:
                    # 默认行为：发送应用层 ACK 字符串
                    try:
                        conn.sendall(b'ACK')
                    except BrokenPipeError:
                        print('BrokenPipe when sending ACK')
                        break
    except KeyboardInterrupt:
        print('Server interrupted')
    finally:
        s.close()
        print('Server exiting')


if __name__ == '__main__':
    main()
