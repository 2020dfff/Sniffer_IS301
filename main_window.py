import sys
import threading
from scapy.all import *
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton,QHBoxLayout, QVBoxLayout, QGridLayout, QTableWidgetItem, QTabWidget
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QAbstractItemView
from PyQt5.QtCore import Qt
from data_info_list import *
from function import *
from sniffer import *
import netifaces
import time



class main_window(QWidget):
    def __init__(self):
        super().__init__()
        # self.on_off_flag = 0
        self.close_flag = False
        self.m_data_info_list = data_info_list()
        self.m_sniffer = sniffer()

        self.parameter_pro = ''
        self.parameter_src = ''
        self.parameter_src_port = ''
        self.parameter_dst = ''
        self.parameter_dst_port = ''
        # self.src_list = []
        # self.dst_list = []
        # self.pro_list = []
        # self.len_list = []

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
        self.on_off_button.clicked.connect(self.on_off)
        
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
        self.data_info_table.setShowGrid(False)
        self.data_info_table.horizontalHeader().setStretchLastSection(True)
        self.data_info_table.setColumnCount(6)
        self.data_info_table.verticalHeader().setVisible(False)
        self.data_info_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.data_info_table.setHorizontalHeaderLabels(["No", "Time", "Source Address", "Destination Address", "Length", "Protocal"])
        self.data_info_table.setColumnWidth(0, 60);
        self.data_info_table.setColumnWidth(1, 100);
        self.data_info_table.setColumnWidth(2, 240);
        self.data_info_table.setColumnWidth(3, 240);
        self.data_info_table.setColumnWidth(4, 75);
        self.data_info_table.setColumnWidth(5, 90);
        self.data_info_table.clicked.connect(self.display_detail_info)

        self.data_info_layout.addWidget(self.data_info_table)

        # t = threading.Thread(target=self.data_info_table_listener)
        t = threading.Thread(target = data_info_table_listener, args=(self,))
        t.start()
        # t.join()
# end of fourth row

# fifth row of main_layout
        self.layer_info_layout = QHBoxLayout()
        
        self.layer_info_tab = QtWidgets.QTabWidget()
        self.layer_info_tab.setFont(QFont('Consolas', 10, QFont.Normal))
        
        self.layer_info_layout.addWidget(self.layer_info_tab)


# end of fifth row



# sixth row of main_layout
# detail information like header of packet
        
        self.detail_layout = QVBoxLayout()

        self.detail_label = QtWidgets.QLabel("Detail Information")
        # self.detail_of_packet = QtWidgets.QTextBrowser()
        self.detail_of_packet = QtWidgets.QTabWidget()
        self.detail_of_packet.setFont(QFont('Consolas', 10, QFont.Light))
        
        self.detail_layout.addWidget(self.detail_label)
        self.detail_layout.addWidget(self.detail_of_packet)
# end of sixth row

        self.main_layout.addLayout(self.nic_info_layout, 0, 0)
        self.main_layout.addLayout(self.ip_info_layout, 1, 0)
        self.main_layout.addLayout(self.search_layout, 2, 0)
        self.main_layout.addLayout(self.data_info_layout, 3, 0)
        self.main_layout.addLayout(self.layer_info_layout, 4, 0)
        self.main_layout.addLayout(self.detail_layout, 5, 0)

        self.setLayout(self.main_layout)
        self.setGeometry(300, 300, 815, 800)
        self.setWindowTitle("Network")
        self.show()

    def on_off(self):
        if(self.m_sniffer.on_off_flag == 0):
            # self.on_off_flag = 1;
            self.m_sniffer.on_off_flag = 1;
            self.on_off_button.setText("Stop")
            # t = threading.Thread(target=self.begin_sniff)
            t = threading.Thread(target = self.m_sniffer.begin_sniff, args=(self, ))
            t.start()
        else:
            self.on_off_button.setText("Start")
            self.m_sniffer.on_off_flag = 0;
            # self.on_off_flag = 0;

    def display_detail_info(self):
        num = int(self.data_info_table.selectedItems()[0].text())
        self.layer_info_tab.clear()
        self.detail_of_packet.clear()

        i = 0
        for x in self.m_data_info_list.layer_list[num]:
            temp_tab_text = QtWidgets.QTextBrowser()
            for key,value in self.m_data_info_list.field_list[num][i].items():
                temp_tab_text.append(str(key) + ":   " + str(value))

            self.layer_info_tab.addTab(temp_tab_text, x)
            i = i + 1
        
        temp_tab_text = QtWidgets.QTextBrowser()
        print(self.m_data_info_list.hex_list[0])
        temp_tab_text.setText(self.m_data_info_list.hex_list[num])
        self.layer_info_tab.addTab(temp_tab_text, "Whole in Hex")

        temp_tab_text = QtWidgets.QTextBrowser()
        temp_tab_text.setText(self.m_data_info_list.detail_info_utf8_list[num])
        self.detail_of_packet.addTab(temp_tab_text, "utf-8")
        
        temp_tab_text = QtWidgets.QTextBrowser()
        temp_tab_text.setText(self.m_data_info_list.detail_info_gb_list[num])
        self.detail_of_packet.addTab(temp_tab_text, "GB2312")
        # self.detail_of_packet.setText(self.m_data_info_list.detail_info_gb_list[num])
    
    def update_parameter(self):
        self.parameter_pro = self.pro.text()
        self.parameter_src = self.source.text()
        self.parameter_src_port = self.source_port.text()
        self.parameter_dst = self.dst.text()
        self.parameter_dst_port = self.dst_port.text()
        print("Yes")
        print(self.pro.text())
        print(self.source.text())
        print(self.dst.text())


    def keyPressEvent(self, event):
        if(event.key() ==  16777220 or event.key() == 16777221):
            self.update_parameter()

    def closeEvent(self, event):
        self.close_flag = True
        self.m_sniffer.on_off_flag = 0
        time.sleep(0.5)
