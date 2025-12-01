#!/usr/bin/env python3
import argparse
import socket
import time
import sys


def main():
    parser = argparse.ArgumentParser(description="简单 TCP 发送脚本，收到 ACK 后重复发送并输出时延 (RTT)")
    parser.add_argument("message", nargs="?", default="hello from pepsal client",
                        help="要发送的文本内容")
    parser.add_argument("--host", default="192.168.1.2", help="目标 IP 地址")
    parser.add_argument("--port", type=int, default=5000, help="目标端口")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="连接和接收的超时时间（秒），超时则停止重试")
    parser.add_argument("--repeat", type=int, default=100,
                        help="收到 ACK 后重复发送的次数；0 表示持续发送直到超时或连接关闭")
    args = parser.parse_args()

    try:
        # 明确创建 TCP (SOCK_STREAM) 套接字并连接。
        # 使用 AF_INET/ SOCK_STREAM 确保使用的是 TCP。
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # settimeout 会影响 connect()、recv() 和 send() 等操作
            sock.settimeout(args.timeout)
            sock.connect((args.host, args.port))
            # 在循环中发送并等待 ACK
            seq = 1
            remaining = args.repeat
            print(f"连接到 {args.host}:{args.port}（timeout={args.timeout}s），按 Ctrl-C 停止")

            while True:
                payload = f"{args.message} [seq={seq}]".encode("utf-8")
                try:
                    send_time = time.monotonic()
                    sock.sendall(payload)
                except BrokenPipeError:
                    print("连接已断开（BrokenPipe）")
                    break
                except Exception as e:
                    print("发送失败：", e)
                    break

                print(f"已发送 {len(payload)} 字节，seq={seq}")

                try:
                    reply = sock.recv(4096)
                except socket.timeout:
                    print(f"等待 ACK 超时（{args.timeout}s），停止。")
                    break
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print("接收数据时出错：", e)
                    break

                recv_time = time.monotonic()
                if not reply:
                    print("对端关闭连接。")
                    break

                # 视为 ACK
                try:
                    reply_text = reply.decode("utf-8", errors="replace")
                except Exception:
                    reply_text = str(reply)

                rtt_ms = (recv_time - send_time) * 1000.0
                print(f"收到 ACK: {reply_text.strip()} (RTT={rtt_ms:.2f} ms)")

                seq += 1
                # 如果用户指定了正的 repeat 次数，计数并在完成后退出
                if args.repeat > 0:
                    remaining -= 1
                    if remaining <= 0:
                        print("达到指定重复次数，退出。")
                        break

    except KeyboardInterrupt:
        print("用户中断（Ctrl-C）")
        sys.exit(1)
    except Exception as e:
        print("连接失败或出错：", e)
        sys.exit(2)


if __name__ == "__main__":
    main()