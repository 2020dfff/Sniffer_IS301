data_info_list.py

class data_info_list
property:
src_list	sort ip address		192.168.33.11
dst_list	destination ip address	114.114.114.114
pro_list	protocal number(which can be converted to protocal name by dict_pro)	1(which is ICMP)
len_list	length of a packet	1500
layer_list	a list of protocal which a packet includes ['Ethernet', 'IP', 'TCP']
field_list	a list of property of each layer
packet_list a list of all packet received
method:
append_xxx_list		be used to append those list above


sniffer.py
class sniffer
property:
interface	network card name	"ens33"
on_off_flag	control stop and run of sniffer
frag_set	used to store those packets which need to be reassemble
count		number of packet recieved, useless
window		class main_window
method:
begin_sniffer	just begin sniffer
is_off		contro stop and run by on_off_flag(if True: stop)
packetHandler	deal with received packets
check_merge		check whther a packet can be merged with other packet which is fragmented
add_to_frag_set add packet to frag_set


function.py
property:
dict_pro	a dict used to convert protocol number to protocol number
method:
data_info_table_listener	used to pad data_info_table(still needed to improve)

