class data_info_list():

    def __init__(self):
        self.src_list = []
        self.dst_list = []
        self.pro_list = []
        self.len_list = []
        self.layer_list = []
        self.field_list = []

    def append_src_list(self, src):
        self.src_list.append(src)

    def append_dst_list(self, dst):
        self.dst_list.append(dst)

    def append_pro_list(self, pro):
        self.pro_list.append(pro)

    def append_len_list(self, length):
        self.len_list.append(length)
    
    def append_layer_list(self, layer):
        self.layer_list.append(layer)

    def append_field_list(self, field):
        self.field_list.append(field)