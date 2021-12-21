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
