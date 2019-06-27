# -*- coding: utf8 -*-

import sys
import time
from time import sleep, ctime
import threading
import json

from scapy.all import *
from scapy.layers.inet import ICMP, IP


class NetworkAnalysis(object):
    def __init__(self, target, tot, tot_per, packet_len):
        self.target = target  # 目标地址
        self.tot = tot  # 执行次数
        self.tot_per = tot_per  # 发包数量
        self.packet_str = 'test' * (packet_len // 4)  # 包大小
        self.flt = "host " + target + " and icmp"  # 过滤条件
        self.out_list = []
        self.in_list = []

    def send_packet(self):
        '''发送线程'''
        times = 0
        while times < self.tot:
            times += 1

            send(IP(dst=self.target) / ICMP(seq=(0, self.tot_per)) / self.packet_str, verbose=0, loop=1, count=1)
            send(IP(dst=self.target) / ICMP(seq=self.tot_per + 2) / "bye", verbose=0)

    def recv_packet(self):
        '''接收线程'''
        sniff(prn=self.printrecv, store=1, filter=self.flt, stop_filter=self.checkstop, timeout=15)

    def checkstop(self, pktdata):
        '''收到seq+2的包就停止抓包并终止程序'''
        if ICMP in pktdata and pktdata[ICMP]:
            seq = str(pktdata[ICMP].seq)
            if int(seq) == self.tot_per + 2 and str(pktdata[IP].src) == self.target:
                # self.output()
                return True
        return False

    def printrecv(self, pktdata):
        '''将结果输出到list'''
        if ICMP in pktdata and pktdata[ICMP]:
            seq = str(pktdata[ICMP].seq)
            if seq == self.tot_per + 2:
                return
            if str(pktdata[IP].dst) == self.target:
                self.out_list.append(('+', 1, seq, time.clock()))
            else:
                self.in_list.append(('-', 0, seq, time.clock()))

    def output(self):
        # 将丢包延时时间置为负值添加到传回类表相应位置
        in_list_new = sorted(self.in_list, key=lambda x: int(x[2]))
        out_list_new = sorted(self.out_list, key=lambda x: int(x[2]))
        for o in out_list_new:
            if o[2] not in [ele[2] for ele in in_list_new]:
                in_list_new.insert(int(o[2]), ('-', 0, ''.join(o[2]), -o[3]))

        all = out_list_new + in_list_new
        all_new = sorted(all, key=lambda x: int(x[2]))

        # 延时时间列表
        index3 = 0
        time_delay_list = []
        while index3 < len(all_new):
            time_delay_list.append((all_new[index3 + 1][3] - all_new[index3][3]) / 2)
            index3 += 2

        new_time_delay_list = filter(lambda x: x >= 0, time_delay_list)
        new_time_delay_list.sort(key=lambda x: x)
        # 平均值列表求和
        sum = 0
        for i in new_time_delay_list:
            sum = sum + i
        result = {
            "target_address": self.target,  # 目标地址
            "packet_size": len(self.packet_str),  # 发包大小
            "send_num": len(self.out_list),  # 发包数量
            "recv_num": len(self.in_list),  # 收包数量
            "packet_loss": (float(len(self.out_list) - len(self.in_list))) / len(self.out_list),  # 丢包率
            "max_delay_time": new_time_delay_list[-1],  # 最大延时时间
            "min_delay_time": new_time_delay_list[0],  # 最小延时时间
            "avg_delay_time": sum / len(new_time_delay_list),  # 平均延时时间
        }
        return result

    def startup(self):
        '''线程开启方法'''

        send_thread = ThreadWraper(self.send_packet, (), self.send_packet.__name__)
        send_thread.setDaemon(True)
        send_thread.start()

        recv_thread = ThreadWraper(self.recv_packet, (), self.recv_packet.__name__)
        recv_thread.setDaemon(True)
        recv_thread.start()

        send_thread.join()
        recv_thread.join()


class ThreadWraper(threading.Thread):
    '''多线程类'''

    def __init__(self, func, arg, name=''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.arg = arg

    def run(self):
        apply(self.func, self.arg)


def main(num=1, counts=50, size=32, *ips):
    data = []
    for ip in ips:
        na = NetworkAnalysis(ip, num, counts, size)
        na.startup()
        res = na.output()
        data.append(res)
    return json.dumps(data)


# if __name__ == '__main__':
#     data = main(1, 100, 200, '11.132.168.85','11.133.173.254')
#     # data = main(1, 100, 200, '203.205.158.34', '124.251.78.32', '103.232.215.131', '14.118.130.214', '13.107.21.200')
#     print(data)
