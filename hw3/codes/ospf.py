import sys

import dpkt

VERBOSE = False


class LsaLink:
    def __init__(self, data, link_state_id, advertising_router):
        self.id = decode_4byte_val(data[0:4].decode('Latin-1'))
        self.data = decode_4byte_val(data[4:8].decode('Latin-1'))
        self.type = data[8]
        self.metric_cnt = data[9]
        self.metric = decode_2byte_val(data[10:12].decode('Latin-1'))
        self.link_state_id = link_state_id
        self.advertising_router = advertising_router


def ip_value(ip):
    ip_list = ip.split('.')
    result = 0
    for i in range(0, 4):
        result = result * 256 + int(ip_list[i])
    return result


def ip_from_val(ip_val):
    ip = ''
    for i in range(0, 4):
        ip = '.' + str(ip_val & 0xFF) + ip
        ip_val = ip_val >> 8
    ip = ip[1:]
    return ip


def encode_2byte_val(in_val):
    in_val = int(in_val)
    left_byte = (in_val >> 8) & 0x0FF
    right_byte = (in_val & 0x0FF)
    return chr(left_byte) + chr(right_byte)


def encode_4byte_val(in_val):
    in_val = int(in_val)
    ll_byte = (in_val >> 24) & 0x0FF
    lm_byte = (in_val >> 16) & 0x0FF
    rm_byte = (in_val >> 8) & 0x0FF
    rr_byte = (in_val & 0x0FF)
    return chr(ll_byte) + '' + chr(lm_byte) + '' + chr(rm_byte) + '' + chr(rr_byte)


def decode_2byte_val(in_val):
    return ord(in_val[0]) * 256 + ord(in_val[1])


def decode_4byte_val(in_val):
    return ((ord(in_val[0]) * 256 + ord(in_val[1])) * 256 + ord(in_val[2])) * 256 + ord(in_val[3])


def verbose_log(string, *args):
    if VERBOSE:
        print('--> ' + string, *args)


def main():
    # files_dir = __file__[:__file__.rindex('/')] + '/files/'

    # pcap_fix_command = 'cd ' + files_dir + '  && rm Packets.pcap && editcap -F libpcap -T ether Packets Packets.pcap'
    # pcap_fix_process = subprocess.Popen(pcap_fix_command, shell=True, stdout=subprocess.PIPE)
    # pcap_fix_process.wait()
    # print('pcap fix process finished with return code ' + str(pcap_fix_process.returncode))

    # file_address = 'files/Packets.pcap'
    file_address = sys.argv[1]

    pcap_file = open(file_address, 'rb')
    # pcap = dpkt.pcap.Reader(pcap_file)
    pcap = dpkt.pcap.Reader(pcap_file)

    pass_counter = 0
    fail_counter = 0
    tot_count = 0

    # NOTE: Script will fail on proprietary protocol packets such as CISCO SLARP which is present in the given sample

    # NOTE: There are 9 different packet types in the given sample
    #       Their ethernet type code is that follows:
    #       SLARP   ????? (Script fails on this packet type)
    #       OSPF    0x159
    #       CDP     0x14f
    #       ARP     0x806
    #       0x6002  0x6002
    #       LOOP    0x9000
    #       ICMP    0x800
    #       TCP     0x800
    #       TELNET  0x800

    # Since we only need OSPF packets, we will filter them by ethernet type.

    ospf_lsupdate_packets = []

    for timestamp, link_layer_frame_data in pcap:
        tot_count += 1
        try:
            verbose_log('TRYING HDLC FORMAT')
            ip_packet_data = link_layer_frame_data[4:]
            ip_packet = dpkt.ip.IP(ip_packet_data)  # removing CISCO HDLC header

            # print([ip_packet])

            verbose_log('FOUND HDLC FORMAT')

            # the ip_packet is a valid OSPF packet    and its a Link State Update Packet
            if type(ip_packet.data) == dpkt.ospf.OSPF and ip_packet.data.type == 4:
                pass_counter += 1
                ospf_lsupdate_packets.append(ip_packet.data)
        except Exception:
            verbose_log('NOT HDLC !!!!')
            try:
                verbose_log('TRYING ETHERNET II FORMAT')
                ip_packet_data = link_layer_frame_data[14:]
                ip_packet = dpkt.ip.IP(ip_packet_data)  # removing ETHERNET II header

                verbose_log('FOUND ETHERNET II FORMAT')

                # the ip_packet is a valid OSPF packet    and its a Link State Update Packet
                if type(ip_packet.data) == dpkt.ospf.OSPF and ip_packet.data.type == 4:
                    pass_counter += 1
                    ospf_lsupdate_packets.append(ip_packet.data)

            except Exception:
                verbose_log('NOT ETHERNET II !!!!')
                fail_counter += 1

        verbose_log('FAIL_COUNT =', fail_counter)
        verbose_log('PASS_COUNT =', pass_counter)
        verbose_log('TOTAL_COUNT =', tot_count)

    router_lsas = []

    for packet in ospf_lsupdate_packets:
        # print([packet])
        packet_lsa_count = decode_4byte_val(packet.data[0:4].decode('Latin-1'))
        parser_head = 4

        for i in range(packet_lsa_count):  # TODO ADD LSAs AS TUPLES (ADD SOURCE ROUTER IP)
            lsa_type = packet.data[parser_head + 3]
            lsa_length = decode_2byte_val(packet.data[parser_head + 18:parser_head + 20].decode('Latin-1'))

            if lsa_type == 1:  # Router-LSA (1)
                lsa_data = packet.data[parser_head:parser_head + lsa_length]
                router_lsas.append((lsa_length, lsa_data))

            parser_head = parser_head + lsa_length

    # filtered all Router LSA packets

    verbose_log('Router LSA count:', len(router_lsas))

    lsa_links = []

    for lsa in router_lsas:
        link_state_id = decode_4byte_val(lsa[1][4:8].decode('Latin-1'))
        advertising_router = decode_4byte_val(lsa[1][8:12].decode('Latin-1'))
        number_of_links = decode_2byte_val(lsa[1][22:24].decode('Latin-1'))

        parser_head = 24

        for _ in range(number_of_links):
            lsa_link = LsaLink(lsa[1][parser_head:parser_head + 12], link_state_id, advertising_router)
            parser_head += 12
            lsa_links.append(lsa_link)

    verbose_log('LSA_Link count:', len(lsa_links))

    ip_set = []
    for lsa_link in lsa_links:
        # verbose_log(ip_from_val(lsa_link.id), ip_from_val(lsa_link.data), lsa_link.type, lsa_link.metric_cnt,
        #             lsa_link.metric, ip_from_val(lsa_link.link_state_id), ip_from_val(lsa_link.advertising_router))

        if lsa_link.type == 3:  # Stub 2 Point Links only
            # if lsa_link.data not in ip_set:
            #     ip_set.append(lsa_link.data)
            if lsa_link.advertising_router not in ip_set:
                ip_set.append(lsa_link.advertising_router)
                # if lsa_link.link_state_id not in ip_set:
                #     ip_set.append(lsa_link.link_state_id)
                # if lsa_link.id not in ip_set:
                #     ip_set.append(lsa_link.id)

    ip_set.sort()

    connections = {}
    for lsa_link in lsa_links:
        if lsa_link.type == 3:  # Stub 2 Point Links only
            if lsa_link.id not in connections:
                connections[lsa_link.id] = []
            if lsa_link.advertising_router not in connections[lsa_link.id]:
                connections[lsa_link.id].append(lsa_link.advertising_router)

    matrix_dimension = len(ip_set)
    matrix = [None] * matrix_dimension
    for i in range(matrix_dimension):
        matrix[i] = [None] * matrix_dimension
    for i in range(matrix_dimension):
        for j in range(matrix_dimension):
            matrix[i][j] = 0

    verbose_log('---------------')
    for connection in connections:
        for source_index in connections[connection]:
            for target_index in connections[connection]:
                if source_index != target_index:
                    # print(ip_set.index(source_index), ip_set.index(target_index))
                    matrix[ip_set.index(source_index)][ip_set.index(target_index)] = 1
                    matrix[ip_set.index(target_index)][ip_set.index(source_index)] = 1
                    if ip_from_val(source_index) == '192.128.1.1':
                        verbose_log(ip_from_val(target_index))
    verbose_log('---------------')

    for ip in ip_set:
        verbose_log(ip_from_val(ip))

    result = ''

    for i in range(matrix_dimension):
        for j in range(matrix_dimension):
            result += str(matrix[i][j])
            if j != matrix_dimension - 1:
                result += ','
            else:
                result += '\n'

    for ip in ip_set:
        verbose_log(ip_from_val(ip))

    result_file = open('adjacent_matrix.txt', 'w')
    result_file.write(result)
    result_file.close()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
