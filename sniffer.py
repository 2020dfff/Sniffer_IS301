import sys
import codecs
import time
from scapy.all import *

class sniffer():

    def __init__(self):
        self.interface = "ens33"
        self.on_off_flag = 0;

    def begin_sniff(self, window):
        self.window = window
        window.start_time = time.time()
        sniff(iface = self.interface, prn = self.packetHandler, stop_filter = self.is_off)
    
    def packetHandler(self, pkt):
        if(IP in pkt):
            self.window.m_data_info_list.append_src_list(pkt['IP'].src)
            self.window.m_data_info_list.append_dst_list(pkt['IP'].dst)
            self.window.m_data_info_list.append_pro_list(pkt['IP'].proto)
            self.window.m_data_info_list.append_len_list(pkt['IP'].len)
            if(pkt['IP'].frag != 0):
                print("NONONO")

        try:
            tmp = codecs.decode(bytes(pkt.load).hex(), "hex")
            # print(tmp.decode('utf-8'))
        except:
            pass
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
        # print(self.window.m_data_info_list.field_list[0])

    def is_off(self, pkt):
        if(self.on_off_flag == 0):
            return True
        return False
