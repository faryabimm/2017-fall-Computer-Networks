import dpkt


# bahs script:
# cat 1.txt | grep $'No.     Time           Protocol' -A 1 | grep $'No.     Time           Protocol' -v > greped.txt

def main():
    files_dir = __file__[:__file__.rindex('/')] + '/files/'

    # pcap_fix_command = 'cd ' + files_dir + '  && rm Packets.pcap && editcap -F libpcap -T ether Packets Packets.pcap'
    # pcap_fix_process = subprocess.Popen(pcap_fix_command, shell=True, stdout=subprocess.PIPE)
    # pcap_fix_process.wait()
    # print('pcap fix process finished with return code ' + str(pcap_fix_process.returncode))

    pcap_file = open('files/Packets', 'rb')
    # pcap = dpkt.pcap.Reader(pcap_file)
    pcap = dpkt.pcapng.Reader(pcap_file)

    pass_counter = 0
    fail_counter = 0

    first_time = True

    for timestamp, packet_buffer in pcap:

        if first_time:
            first_time = False
            initial_time = timestamp

        # print(timestamp, packet_buffer)
        try:
            ethernet_object = dpkt.ethernet.Ethernet(packet_buffer)
            pass_counter += 1
            print('PASS\t ',  "%.6f" % round(timestamp - initial_time, 6), '\t', hex(ethernet_object.type))
        except dpkt.NeedData:
            fail_counter += 1
            print('FAIL\t ', "%.6f" % round(timestamp - initial_time, 6))

    print(pass_counter, fail_counter)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
