class data_info_list():

    def __init__(self):
        self.src_list = []
        self.src_port_list = []
        self.dst_list = []
        self.dst_port_list = []
        self.pro_list = []
        self.len_list = []
        self.layer_list = []
        self.field_list = []
        self.packet_list = []
        self.detail_info_utf8_list = []
        self.detail_info_gb_list = []
        self.hex_list = []
        self.time_list = []

    def append_src_list(self, src):
        self.src_list.append(src)
    
    def append_src_port_list(self, src_port):
        self.src_port_list.append(src_port)

    def append_dst_list(self, dst):
        self.dst_list.append(dst)

    def append_dst_port_list(self, dst_port):
        self.dst_port_list.append(dst_port)

    def append_pro_list(self, pro):
        self.pro_list.append(pro)

    def append_len_list(self, length):
        self.len_list.append(length)
    
    def append_layer_list(self, layer):
        self.layer_list.append(layer)

    def append_field_list(self, field):
        self.field_list.append(field)

    def append_packet_list(self, packet):
        self.packet_list.append(packet)

    def append_detail_info_utf8_list(self, detail_info):
        self.detail_info_utf8_list.append(detail_info)

    def append_detail_info_gb_list(self, detail_info):
        self.detail_info_gb_list.append(detail_info)

    def append_hex_list(self, hex_):
        self.hex_list.append(hex_)
    
    def append_time_list(self, time):
        self.time_list.append(time)

    def clear(self):
        self.src_list = []
        self.src_port_list = []
        self.dst_list = []
        self.dst_port_list = []
        self.pro_list = []
        self.len_list = []
        self.layer_list = []
        self.field_list = []
        self.packet_list = []
        self.detail_info_utf8_list = []
        self.detail_info_gb_list = []
        self.hex_list = []
        self.time_list = []
