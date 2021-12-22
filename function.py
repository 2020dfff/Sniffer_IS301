import time
import sys
import threading
from scapy.all import *
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton,QHBoxLayout, QVBoxLayout, QGridLayout, QTableWidgetItem
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QAbstractItemView
from PyQt5.QtCore import Qt
import netifaces
import time
dict_pro = {0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 3: 'GGP', 4: 'IP-in-IP', 5: 'ST', 6: 'TCP', 7: 'CBT', 8: 'EGP', 9: 'IGP', 10: 'BBN-RCC-MON', 11: 'NVP-II', 12: 'PUP', 13: 'ARGUS', 14: 'EMCON', 15: 'XNET', 16: 'CHAOS', 17: 'UDP', 18: 'MUX', 19: 'DCN-MEAS', 20: 'HMP', 21: 'PRM', 22: 'XNS-IDP', 23: 'TRUNK-1', 24: 'TRUNK-2', 25: 'LEAF-1', 26: 'LEAF-2', 27: 'RDP', 28: 'IRTP', 29: 'ISO-TP4', 30: 'NETBLT', 31: 'MFE-NSP', 32: 'MERIT-INP', 33: 'DCCP', 34: '3PC', 35: 'IDPR', 36: 'XTP', 37: 'DDP', 38: 'IDPR-CMTP', 39: 'TP++', 40: 'IL', 41: 'IPv6', 42: 'SDRP', 43: 'IPv6-Route', 44: 'IPv6-Frag', 45: 'IDRP', 46: 'RSVP', 47: 'GREs', 48: 'DSR', 49: 'BNA', 50: 'ESP', 51: 'AH', 52: 'I-NLSP', 53: 'SWIPE', 54: 'NARP', 55: 'MOBILE', 56: 'TLSP', 57: 'SKIP', 58: 'IPv6-ICMP', 59: 'IPv6-NoNxt', 60: 'IPv6-Opts', 62: 'CFTP', 64: 'SAT-EXPAK', 65: 'KRYPTOLAN', 66: 'RVD', 67: 'IPPC', 69: 'SAT-MON', 70: 'VISA', 71: 'IPCU', 72: 'CPNX', 73: 'CPHB', 74: 'WSN', 75: 'PVP', 76: 'BR-SAT-MON', 77: 'SUN-ND', 78: 'WB-MON', 79: 'WB-EXPAK', 80: 'ISO-IP', 81: 'VMTP', 82: 'SECURE-VMTP', 83: 'VINES', 84: 'IPTM', 85: 'NSFNET-IGP', 86: 'DGP', 87: 'TCF', 88: 'EIGRP', 89: 'OSPF', 90: 'Sprite-RPC', 91: 'LARP', 92: 'MTP', 93: 'AX.25', 94: 'OS', 95: 'MICP', 96: 'SCC-SP', 97: 'ETHERIP', 98: 'ENCAP', 100: 'GMTP', 101: 'IFMP', 102: 'PNNI', 103: 'PIM', 104: 'ARIS', 105: 'SCPS', 106: 'QNX', 107: 'A/N', 108: 'IPComp', 109: 'SNP', 110: 'Compaq-Peer', 111: 'IPX-in-IP', 112: 'VRRP', 113: 'PGM', 115: 'L2TP', 116: 'DDX', 117: 'IATP', 118: 'STP', 119: 'SRP', 120: 'UTI', 121: 'SMP', 122: 'SM', 123: 'PTP', 124: 'IS-IS over IPv4', 125: 'FIRE', 126: 'CRTP', 127: 'CRUDP', 128: 'SSCOPMCE', 129: 'IPLT', 130: 'SPS', 131: 'PIPE', 132: 'SCTP', 133: 'FC', 134: 'RSVP-E2E-IGNORE', 135: 'Mobility Header', 136: 'UDPLite', 137: 'MPLS-in-IP', 138: 'manet', 139: 'HIP', 140: 'Shim6', 141: 'WESP', 142: 'ROHC'}

def check_invalid(window, pro, src, src_port, dst, dst_port, num):
    if(dict_pro[window.m_data_info_list.pro_list[num]] != pro.upper() and pro != ''):
        return True
    
    src = src.strip()
    
    if(window.m_data_info_list.src_list[num] != src and src != ''):
        return True

    if(str(window.m_data_info_list.src_port_list[num]) != src_port and src_port != ''):
        return True
    
    dst = dst.strip()

    if(window.m_data_info_list.dst_list[num] != dst and dst != ''):
        return True

    if(str(window.m_data_info_list.dst_port_list[num]) != dst_port and dst_port != ''):
        return True
    
    return False

def check_msg_not_in_detail(window, num):
    search_str = window.search_text.strip()
    if(search_str == ''):
        return False
    if(search_str in window.m_data_info_list.detail_info_utf8_list[num]):
        return False
    if(search_str in window.m_data_info_list.detail_info_gb_list[num]):
        return False
    return True


def check_parameter_changed(a, a1, b, b1, c, c1, d, d1, e, e1, f, f1):
    if((a == a1) and (b == b1) and (c == c1) and (d == d1) and (e == e1) and (f == f1)):
        return False
    return True


def data_info_table_listener(window):
    cur_num = 0
    row_num = 0
    latest_pro = window.parameter_pro
    latest_src = window.parameter_src
    latest_src_port = window.parameter_src_port
    latest_dst = window.parameter_dst
    latest_dst_port = window.parameter_dst_port
    latest_search_text  = window.search_text

    while(True):
        if(window.close_flag == True):
            break
        
        if(check_parameter_changed(latest_pro, window.parameter_pro, latest_src, window.parameter_src, latest_src_port, window.parameter_src_port, latest_dst, window.parameter_dst, latest_dst_port, window.parameter_dst_port, latest_search_text, window.search_text)):
            cur_num = 0
            row_num = 0
            latest_pro = window.parameter_pro
            latest_src = window.parameter_src
            latest_src_port = window.parameter_src_port
            latest_dst = window.parameter_dst
            latest_dst_port = window.parameter_dst_port
            latest_search_text = window.search_text
            window.data_info_table.clear()
            window.data_info_table.setHorizontalHeaderLabels(["No", "Time", "Source Address", "Destination Address", "Length", "Protocal"])
        
        if(cur_num < len(window.m_data_info_list.src_list)):
            if(check_invalid(window, latest_pro, latest_src, latest_src_port, latest_dst, latest_dst_port, cur_num)):
                cur_num = cur_num + 1 
                continue

            if(check_msg_not_in_detail(window, cur_num)):
                cur_num = cur_num + 1
                continue

            window.data_info_table.insertRow(row_num)
            # tmp_time = time.time() - window.start_time
            # tmp_time = round(tmp_time, 4)

            window.data_info_table.setItem(row_num, 0, QTableWidgetItem(str(cur_num)))
            window.data_info_table.setItem(row_num, 1, QTableWidgetItem(str(window.m_data_info_list.time_list[cur_num])))
            window.data_info_table.setItem(row_num, 2, QTableWidgetItem(str(window.m_data_info_list.src_list[cur_num])))
            window.data_info_table.setItem(row_num, 3, QTableWidgetItem(str(window.m_data_info_list.dst_list[cur_num])))
            window.data_info_table.setItem(row_num, 4, QTableWidgetItem(str(window.m_data_info_list.len_list[cur_num])))
            window.data_info_table.setItem(row_num, 5, QTableWidgetItem(str(dict_pro[window.m_data_info_list.pro_list[cur_num]])))
            cur_num = cur_num + 1
            row_num = row_num + 1

    print("data_info_table_listener finished!")
