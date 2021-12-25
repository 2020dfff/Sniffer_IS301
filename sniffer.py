import sys
import codecs
import time
from scapy.all import *


def to_hex(pkt):
    return hexdump(pkt)

class sniffer():

    def __init__(self):
        self.interface = "ens33"
        self.on_off_flag = 0;
        self.count = 0;
        self.frag_set = []

    def begin_sniff(self, window):
        self.window = window
        self.interface = window.combo_box_nic.currentText()
        window.start_time = time.time()
        sniff(iface = self.interface, prn = self.packetHandler, stop_filter = self.is_off)
        print("sniffer finished.")


    def packetHandler(self, pkt):
        if(IP in pkt):
            if(self.check_merge(pkt)):
               return
            
            if(pkt['IP'].flags == 'MF'):
                self.add_to_frag_set(pkt)
                # print(pkt['IP'].flags)
                return
        else: return
        
        if(TCP in pkt):
            self.window.m_data_info_list.append_src_port_list(pkt['TCP'].sport)
            self.window.m_data_info_list.append_dst_port_list(pkt['TCP'].dport)
        elif(UDP in pkt):
            self.window.m_data_info_list.append_src_port_list(pkt['UDP'].sport)
            self.window.m_data_info_list.append_dst_port_list(pkt['UDP'].dport)
        else:
            self.window.m_data_info_list.append_src_port_list(0)
            self.window.m_data_info_list.append_dst_port_list(0)
        
        #print("------------------")
        # tmp = to_hex(pkt)
        tmp = str(pkt)
        tmp_time = time.time() - self.window.start_time
        tmp_time = round(tmp_time, 4)
        # print("tmp = " + tmp)
        # print(tmp)
        # tmp = 0
        #print("------------------")
        self.window.m_data_info_list.append_hex_list(tmp)
        self.window.m_data_info_list.append_time_list(tmp_time)
        flag = 0
        flag2 = 0
        if(Raw in pkt):
            try:
                tmp1 = pkt[Raw].load.decode('utf-8')
                tmp2 = pkt[Raw].load.decode('GB2312')
                flag = 1
            except:
                pass
            if(flag):
                self.window.m_data_info_list.append_detail_info_utf8_list(tmp1)
                self.window.m_data_info_list.append_detail_info_gb_list(tmp2)
            else:
                try:
                    flag2 = 1
                except:
                    pass

            if(flag2):
                self.window.m_data_info_list.append_detail_info_utf8_list(pkt[Raw].load[10:].decode('utf-8', errors='ignore'))
                self.window.m_data_info_list.append_detail_info_gb_list(pkt[Raw].load[10:].decode('GB2312', errors='ignore'))
            else:
                self.window.m_data_info_list.append_detail_info_utf8_list('No extra information')
                self.window.m_data_info_list.append_detail_info_gb_list('No extra information')
        else:
            self.window.m_data_info_list.append_detail_info_utf8_list('No extra information')
            self.window.m_data_info_list.append_detail_info_gb_list('No extra information')

        self.window.m_data_info_list.append_src_list(pkt['IP'].src)
        self.window.m_data_info_list.append_dst_list(pkt['IP'].dst)
        self.window.m_data_info_list.append_pro_list(pkt['IP'].proto)
        self.window.m_data_info_list.append_len_list(pkt['IP'].len)
        self.window.m_data_info_list.append_packet_list(pkt)
        layer = []
        field = []
        while(pkt.payload):
            layer.append(pkt.name)
            field.append(pkt.fields)
            # print(pkt.name)
            # print(pkt.fields)
            # print(pkt.payload)
            pkt = pkt.payload

        self.window.m_data_info_list.append_layer_list(layer)
        self.window.m_data_info_list.append_field_list(field)
        # print(self.window.m_data_info_list.layer_list[self.count])
        # print(self.window.m_data_info_list.field_list[self.count])
        # print(self.window.m_data_info_list.detail_info_gb_list[self.count])
        # print(self.window.m_data_info_list.hex_list[self.count])
        self.count = self.count + 1

    def is_off(self, pkt):
        # print(self.on_off_flag)
        if(self.on_off_flag == 0):
            return True
        return False

    def add_to_frag_set(self, pkt):
        self.frag_set.append([pkt])
        return

    def check_merge(self, pkt):
        for i in self.frag_set:
            # print(i)
            if(i[0]['IP'].id == pkt['IP'].id):
                if(pkt['IP'].flags == 0):
                    self.window.m_data_info_list.append_src_list(pkt['IP'].src)
                    self.window.m_data_info_list.append_dst_list(pkt['IP'].dst)
                    self.window.m_data_info_list.append_pro_list(i[0]['IP'].proto)
                    total_len = pkt['IP'].len
                    for x in i:
                        total_len = total_len + x['IP'].len
                    self.window.m_data_info_list.append_len_list(total_len)
                    i[0]['IP'].len = total_len
                    i[0]['IP'].flags = "DF"
                    
                    layer = []
                    field = []
                    tmp_pkt = i[0]
                    while(tmp_pkt.payload):
                        layer.append(tmp_pkt.name)
                        field.append(tmp_pkt.fields)
                        # print(pkt.name)
                        # print(pkt.fields)
                        # print(pkt.payload)
                        tmp_pkt = tmp_pkt.payload
                    self.window.m_data_info_list.append_layer_list(layer)
                    self.window.m_data_info_list.append_field_list(field)
                    self.window.m_data_info_list.append_packet_list(i[0])
                else:
                    i.append(pkt)
                return True
        return False
