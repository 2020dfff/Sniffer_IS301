import sys
import codecs
import time
from scapy.all import *


class sniffer():

    def __init__(self):
        self.interface = "ens33"
        self.on_off_flag = 0;
        self.count = 0;
        self.frag_set = []

    def begin_sniff(self, window):
        self.window = window
        window.start_time = time.time()
        sniff(iface = self.interface, prn = self.packetHandler, stop_filter = self.is_off)
    
    def packetHandler(self, pkt):
        if(IP in pkt):
            if(self.check_merge(pkt)):
                return
            
            if(pkt['IP'].flags != 'DF'):
                self.add_to_frag_set(pkt)
                return

            self.window.m_data_info_list.append_src_list(pkt['IP'].src)
            self.window.m_data_info_list.append_dst_list(pkt['IP'].dst)
            self.window.m_data_info_list.append_pro_list(pkt['IP'].proto)
            self.window.m_data_info_list.append_len_list(pkt['IP'].len)
        else:
            return

        try:
            tmp = codecs.decode(bytes(pkt.load).hex(), "hex")
            # print(tmp.decode('utf-8'))
            # print(tmp.decode('GB2312'))
        except:
            pass

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
        
        self.count = self.count + 1

    def is_off(self, pkt):
        if(self.on_off_flag == 0):
            return True
        return False

    def add_to_frag_set(self, pkt):
        self.frag_set.append([pkt])

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
