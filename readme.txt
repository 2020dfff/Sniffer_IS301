data_info_list.py

class data_info_list
property:
src_list	sort ip address		192.168.33.11
src_port_list source port of packets
dst_list	destination ip address	114.114.114.114
dst_port_list	destination port of packets
pro_list	protocal number(which can be converted to protocal name by dict_pro)	1(which is ICMP)
len_list	length of a packet	1500
layer_list	a list of protocal which a packet includes ['Ethernet', 'IP', 'TCP']
field_list	a list of property of each layer
packet_list a list of all packet received
detail_info_utf8_list	information decoded by utf8
detail_info_gb_list		information decoded by gb2312
time_list	time when received the packet
hex_list	hex	of packet
method:
append_xxx_list		be used to append those list above
clear				clear all list(used when switch net interface)

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
is_off		control stop and run by on_off_flag(if True: stop)

### VERY VERY VERY IMPORTANT FUNCTION
packetHandler	deal with received packets

first, check whether a packet can put together with other packet in frag_set
if true and this packet's flag is DF, put them together and add to data_info_list, return True
if true and this packet's flag is MF, add it to the frag_set, return True
if false, then return False
if check_merge returns true, simply skip this packet(because it has been dealt)

if check_merge returns False
then check whether the flag pf pkt is MF, if True, add it to frag_set and skip this packet

if a packet passes all tests above, we can add information like sport, dport and others into data_info_list.

To notice that detail_info_utf8_list and detail_info_gb_list is a little complicated, so much try and except make people go mad, I do this just want to filter some invalid byte like '0xff' at beginning, so don't care these details on how I implement, just remember this can get the informaton.

###

check_merge		check whther a packet can be merged with other packet which is fragmented
add_to_frag_set add packet to frag_set


function.py
property:
dict_pro	a dict used to convert protocol number to protocol number
method:

### VERY VERY IMPORTANT FUNCTION
data_info_table_listener	used to pad data_info_table(still needed to improve)
it need to detect whether search condition changed which is triggered by press key ENTER.So latest_xxx is used to save history condition and check them with current condition which is window.xxx.
check_parameter_changed is a shit function.But it finishes its job
I should write it like
def check_parameter_changed(*args):

then it check whether this packet matches the condition, which is checked by check_invalid and check_msg_not_in_detail, if it passes all tests, we can add it into window.data_info_table
line 79 to 85 is used to refresh table when restart sniffering.

###

check_invalid
just check whether packet's property contains the requirement(like protocal is ICMP)

check_msg_not_in_detail
just like above, check whether message in detail_info_utf8_list or detail_info_gb_list, if not_in return True else return False


main_window.py
class main_window(QWidget):
core of the window, here I just introduce design thought instead of introduce each properties because it's too much.

First it contains a data_info_list to contain data, and a sniffer to sniff packets. Then we start a thread to listen whether we need to add new row into data_info_table(which implemented in function.py), to be frank, that while true loop is foolish(but useful 0.0). When user clicks the start button, we start a thread to sniff. When close, we close all thread and exit.
