<<<<<<< HEAD

import pcap

#name 监听的网卡名称
#snaplen 捕获的每个数据包的最大长度
#promisc 是否开启混杂模式
#timeout_ms 接收数据包的超时时间
#immediate 立即模式，如果启用则不会缓存数据包

#!/usr/bin/env python3
# -*- encoding:utf-8 -*-

import dpkt
import getopt
import sys
import datetime
import time
import os
import platform
 
if 'Windows' in platform.platform():
    import winreg as wr
 
 
IF_REG = r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
def getInterfaceByName(name):
    '''Get guid of interface from regedit of windows system
    Args:
        name: interface name
    Returns:
        An valid guid value or None.
    Example:
        getInterfaceByName('eth0')
    '''
    reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
    reg_key = wr.OpenKey(reg, IF_REG)
    for i in range(wr.QueryInfoKey(reg_key)[0]):
        subkey_name = wr.EnumKey(reg_key, i)
        try:
            reg_subkey = wr.OpenKey(reg_key, subkey_name + r'\Connection')
            Name = wr.QueryValueEx(reg_subkey, 'Name')[0]
            wr.CloseKey(reg_subkey)
            if Name == name:
                return r'\Device\NPF_' + subkey_name
        except FileNotFoundError as e:
            pass
 
    return None
 
def mac_addr(mac):
    return '%02x:%02x:%02x:%02x:%02x:%02x'%tuple(mac)
 
def ip_addr(ip):
    return '%d.%d.%d.%d'%tuple(ip)
 
def captureData(iface):
    pkt = pcap.pcap(iface, promisc=True, immediate=True, timeout_ms=50)
    # filter method
    filters = {
        'DNS': 'udp port 53',
        'HTTP': 'tcp port 80'
    }
    # pkt.setfilter(filters['HTTP'])
 
    pcap_filepath = 'pkts/pkts_{}.pcap'.format(time.strftime("%Y%m%d-%H%M%S",
        time.localtime()))
    pcap_file = open(pcap_filepath, 'wb')
    writer = dpkt.pcap.Writer(pcap_file)
    print('Start capture...')
    try:
        pkts_count = 0
        for ptime, pdata in pkt:
            writer.writepkt(pdata, ptime)
            # anlysisData(pdata)
            printRawPkt(ptime, pdata)
            pkts_count += 1
    except KeyboardInterrupt as e:
        writer.close()
        pcap_file.close()
        if not pkts_count:
            os.remove(pcap_filepath)
        print('%d packets received'%(pkts_count))
 
def printRawPkt(time, data):
    eth = dpkt.ethernet.Ethernet(data)
    print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(time)))
    print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst))
    if not isinstance(eth.data, dpkt.ip.IP):
        print('')
        return
 
    ip = eth.data
 
    # get fragments info
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
 
    print('IP: %s -> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % (
        ip_addr(ip.src), ip_addr(ip.dst), ip.len, ip.ttl,
        do_not_fragment, more_fragments, fragment_offset))
 
def anlysisData(data):
    packet = dpkt.ethernet.Ethernet(data)
    if isinstance(packet.data, dpkt.ip.IP):
        ip = ip_addr(packet.data.dst)
        if packet.data.data.dport == 80 or packet.data.data.sport == 80:
            try:
                print(packet.data.data.data.decode('utf-8', errors='ignore'))
            except UnicodeDecodeError as uderr:
                print(uderr.__str__())
 
 
def main():
    if 'Windows' in platform.platform():
        iface = getInterfaceByName('Router')
    else:
        iface = 'ens33'
    captureData(iface)
 
if __name__ == "__main__":
    main()
=======
import sys

from PyQt5.QtWidgets import QApplication, QWidget, QPushButton,QHBoxLayout, QVBoxLayout, QGridLayout
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QAbstractItemView
from PyQt5.QtCore import Qt
import netifaces


def test_button():
    print("test")

class main_window(QWidget):
    def __init__(self):
        super().__init__()
        self.init_window()

    def init_window(self):
        self.main_layout = QGridLayout()
        self.main_layout.setAlignment(Qt.AlignTop)

#       btn1 = QPushButton("button1")
#       btn2 = QPushButton("button2")

# first row of main_layout
# information about nic       
        self.nic_info_layout = QGridLayout()
        
        self.label_nic = QtWidgets.QLabel("NIC")
        # label_nic.setText("NIC")
        
        self.combo_box_nic = QtWidgets.QComboBox()
        self.combo_box_nic.addItem(netifaces.interfaces()[0])
        self.combo_box_nic.addItem(netifaces.interfaces()[1])
        
        self.on_off_button = QPushButton("Start")

        # just for a test
        self.nic_info_layout.addWidget(self.label_nic, 0, 0, 1, 1)
        self.nic_info_layout.addWidget(self.combo_box_nic, 0, 1, 1, 7)
        self.nic_info_layout.addWidget(self.on_off_button, 0, 10, 1, 2)
# end of first row

# second row of main_layout
# protocal source destination and port
        self.ip_info_layout = QHBoxLayout()
        
        self.label_pro = QtWidgets.QLabel("PRO")
        self.label_source = QtWidgets.QLabel("SRC")
        self.label_source_port = QtWidgets.QLabel("SPORT")
        self.label_dst = QtWidgets.QLabel("DST")
        self.label_dst_port = QtWidgets.QLabel("DPORT")

        self.pro = QtWidgets.QLineEdit()
        self.source = QtWidgets.QLineEdit()
        self.source_port = QtWidgets.QLineEdit()
        self.dst = QtWidgets.QLineEdit()
        self.dst_port = QtWidgets.QLineEdit()

        self.ip_info_layout.addWidget(self.label_pro)
        self.ip_info_layout.addWidget(self.pro)
        
        self.ip_info_layout.addWidget(self.label_source)
        self.ip_info_layout.addWidget(self.source)
        
        self.ip_info_layout.addWidget(self.label_source_port)
        self.ip_info_layout.addWidget(self.source_port)
        
        self.ip_info_layout.addWidget(self.label_dst)
        self.ip_info_layout.addWidget(self.dst)
        
        self.ip_info_layout.addWidget(self.label_dst_port)
        self.ip_info_layout.addWidget(self.dst_port)
        
# end of second row
        
# third row of main_layout
# search bar
        self.search_layout = QHBoxLayout()
        
        self.line_search = QtWidgets.QLineEdit()
        self.line_search.setPlaceholderText("Search")
        
        self.search_layout.addWidget(self.line_search)
# end of third row

# fourth row of main_layout
# information of datagram
        self.data_info_layout = QHBoxLayout()
        
        self.data_info_table = QtWidgets.QTableWidget()
        self.data_info_table.setColumnCount(6)
        self.data_info_table.setHorizontalHeaderLabels(["No", "Time", "Source Address", "Destination Address", "Length", "Protocal"])
        self.data_info_table.setColumnWidth(0, 60);
        self.data_info_table.setColumnWidth(1, 100);
        self.data_info_table.setColumnWidth(2, 240);
        self.data_info_table.setColumnWidth(3, 240);
        self.data_info_table.setColumnWidth(4, 75);
        self.data_info_table.setColumnWidth(5, 90);

        self.data_info_layout.addWidget(self.data_info_table)
# end of fourth row

# fifth row of main_layout
# detail information like header of packet
        self.detail_layout = QHBoxLayout()

        self.detail_of_packet = QtWidgets.QTextBrowser()

        self.detail_layout.addWidget(self.detail_of_packet)
# end of fifth row

        self.main_layout.addLayout(self.nic_info_layout, 0, 0)
        self.main_layout.addLayout(self.ip_info_layout, 1, 0)
        self.main_layout.addLayout(self.search_layout, 2, 0)
        self.main_layout.addLayout(self.data_info_layout, 3, 0)
        self.main_layout.addLayout(self.detail_layout, 4, 0)

        self.setLayout(self.main_layout)
        self.setGeometry(300, 300, 600, 600)
        self.setWindowTitle("Network")
        self.show()


if __name__=='__main__':
    app = QApplication(sys.argv)
    window = main_window()
    sys.exit(app.exec_())
>>>>>>> e22ffca465bed6ccf0348d1713b228a4a123232d
