import os
import socket

host = '192.168.10.103'

if os.name == 'nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# キャプチャ結果にIPヘッダを含める
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == 'nt':
    # MS Windows の場合は ioctl を使用してプロミスキャスモードを有効化
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

received_data = sniffer.recvfrom(65565)

print(received_data)

# MS Windows の場合はプロミスキャスモードを無効化にして終了
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
