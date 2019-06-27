# -*- coding: utf8 -*-
# C:\Python27\python network_analysis.py 211.162.70.229 1 100 2 # 此服务器丢包

import sys
import time
from time import sleep, ctime

import signal
import threading

from scapy.all import *
from scapy.layers.inet import ICMP, IP
import matplotlib.pyplot as plt

target = sys.argv[1]  # 指定目标IP地址
tot = int(sys.argv[2])  # 指定执行次数
tot_per = int(sys.argv[3])  # 指定每次发送的包量
vl = int(sys.argv[4])  # 指定是否回显(0：输出到null文件中，1：打印send，2：打印send和receive)
packet_len='test'* int(sys.argv[5])
flt = "host " + target + " and icmp"

# handle = open("/dev/null", 'w')
handle = open("null", 'w')

out_list = []
in_list = []


def output():
    print(len(out_list), len(in_list))
    # 将丢包延时时间置为负值添加到传回类表相应位置

    in_list_new = sorted(in_list, key=lambda x: int(x[2]))
    out_list_new = sorted(out_list, key=lambda x: int(x[2]))

    for o in out_list_new:
        if o[2] not in [ele[2] for ele in in_list_new]:
            in_list_new.insert(int(o[2]), ('-', 0, ''.join(o[2]), -o[3]))

    all = out_list_new + in_list_new

    # all.sort(lambda x, y: cmp(x[3], y[3]))
    # for item in all:
    #     print(item[0], item[1], item[2], item[3] * 10)
    # 统计每次延时时间
    all_new = sorted(all, key=lambda x: int(x[2]))
    index1 = index2 = index3 = 0

    # out时间列表
    time_out_list = []
    while index1 < len(out_list_new):
        time_out_list.append(out_list_new[index1][3])
        index1 += 1

    # in时间列表
    time_in_list = []
    while index2 < len(in_list_new):
        time_in_list.append(in_list_new[index2][3])
        index2 += 1

    # 延时时间列表
    time_delay_list = []
    while index3 < len(all_new):
        time_delay_list.append((all_new[index3 + 1][3] - all_new[index3][3]) / 2)
        index3 += 2
    draw(time_out_list, time_in_list, time_delay_list)

    sys.stdout.flush()
    os._exit(0)


def signal_handler(signal, frame):
    output()


class ThreadWraper(threading.Thread):
    def __init__(self, func, args, name=''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args

    def run(self):
        apply(self.func, self.args)


# 将结果输出到list
def printrecv(pktdata):
    if ICMP in pktdata and pktdata[ICMP]:
        seq = str(pktdata[ICMP].seq)
        if seq == tot_per + 2:
            return
        if str(pktdata[IP].dst) == target:
            handle.write('*')
            handle.flush()
            out_list.append(('+', 1, seq, time.clock()))
        else:
            if vl == 2:
                handle.write('.')
            else:
                handle.write('\b \b')
            handle.flush()
            in_list.append(('-', 0, seq, time.clock()))


# 收到seq+2的包就停止抓包并终止程序
def checkstop(pktdata):
    if ICMP in pktdata and pktdata[ICMP]:
        seq = str(pktdata[ICMP].seq)
        if int(seq) == tot_per + 2 and str(pktdata[IP].src) == target:
            handle.write("\nExit:" + ctime() + '\n')
            output()
            return True
    return False


# 发送线程
def send_packet():
    times = 0
    while times < tot:
        times += 1
        #   C:\Python27\python network_analysis.py 122.136.212.132 1 100 2
        # send(IP(dst=target) / ICMP(seq=(0, tot_per)) / "test", verbose=0, loop=1, count=1)
        send(IP(dst=target) / ICMP(seq=(0, tot_per),) / packet_len, verbose=0, loop=1, count=1)
        send(IP(dst=target) / ICMP(seq=tot_per + 2) / "bye", verbose=0)


# 接收线程
def recv_packet():
    sniff(prn=printrecv, store=1, filter=flt, stop_filter=checkstop)

def startup():
    handle.write("Start:" + ctime() + '\n')

    send_thread = ThreadWraper(send_packet, (), send_packet.__name__)
    send_thread.setDaemon(True)
    send_thread.start()

    recv_thread = ThreadWraper(recv_packet, (), recv_packet.__name__)
    recv_thread.setDaemon(True)
    recv_thread.start()

    send_thread.join()
    recv_thread.join()
    # signal.pause()


# 画图函数
def draw(out_list, in_list, time_delay_list):
    x = range(len(out_list))
    # 样本值
    y_send = out_list
    y_rec = in_list
    y_relay = time_delay_list

    plt.figure(figsize=(20, 8), dpi=100)
    plt.scatter(x, y_send, label="send")
    plt.scatter(x, y_rec, edgecolors='r', label="receive")
    plt.plot(x, y_relay, color="g", linestyle="--", label="relay time")
    # 显示图例
    plt.legend(loc="best")
    # x_ticks_label = [i for i in x]
    # y_ticks_label = range(40)
    # plt.xticks(x[::5], x_ticks_label[::5])
    # plt.yticks(y_ticks_label[::5])
    plt.xlabel("times")
    plt.ylabel("CPU time")
    plt.title("time relay")
    plt.grid(True, linestyle='--', alpha=0.5, color='y')  # 网格
    plt.show()


if __name__ == '__main__':
    if vl != 0:
        handle.close()
        handle = sys.stderr
    signal.signal(signal.SIGINT, signal_handler)
    startup()
