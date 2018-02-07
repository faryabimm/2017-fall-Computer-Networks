import os
from random import randrange

TWO_POW_16 = 1 << 16
TWO_POW_32 = 1 << 32


def generate_tcp_header(src_port, dst_port, seq_num, ack_num, checksum, flags, win_size):
    header = ''
    header += encode_2byte_val(src_port)
    header += encode_2byte_val(dst_port)
    header += encode_4byte_val(seq_num)
    header += encode_4byte_val(ack_num)

    # data_offset (4) , reserved (3), NS_flag (1)
    header += chr(5 << 4)  # header is composed of 5 32-bit words, reserved and NS flag bits are zeros
    header += flags
    header += encode_2byte_val(win_size)
    header += encode_2byte_val(checksum)
    header += '\x00\x00'  # urgent pointer

    return header


def generate_checksum(packet):
    length = len(packet)

    if length % 2 == 1:
        packet += '\x00'  # padding to get a len of a multiple of 16bits
        length += 1

    checksum_value = 0
    for i in range(0, length // 2):
        checksum_value = ones_comp_add_16bit(checksum_value, decode_2byte_val(packet[2 * i:2 * i + 2]))

    return encode_2byte_val(checksum_value)


def ones_comp_add_16bit(a, b):
    result = a + b
    return result if result < TWO_POW_16 else (result + 1) % TWO_POW_16


def generate_flags(syn, fin, ack, cwr):
    # CWR - ECE - URG - ACK - PSH - RST - SYN - FIN
    result = cwr
    result <<= 3
    result += ack
    result <<= 3
    result += syn
    result <<= 1
    result += fin
    return chr(result)


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


def read_pipe_blocking(pipe):
    try:
        data_length = pipe.read(4)
        data_length = data_length.decode('Latin-1')
        data_length = decode_4byte_val(data_length)
        data = pipe.read(data_length)
        data = data.decode('Latin-1')
        return data_length, data
    except OSError as error:
        print('cannot read pipe for some reason!')


def write_tick_pipe(pipe):
    pipe.write('tick\n')
    pipe.flush()


def read_pipe(pipe):
    pipe_has_data = True
    data_length = None
    data = None
    try:
        # data_length = decode_4byte_val(pipe.read(4).decode('Latin-1'))
        data_length = os.read(pipe.fileno(), 4)
        if len(data_length) == 0:
            pipe_has_data = False
        else:
            data_length = decode_4byte_val(data_length.decode('Latin-1'))
            data = os.read(pipe.fileno(), data_length).decode('Latin-1')
            # data = pipe.read(data_length).decode('Latin-1')
    except OSError:
        print('cannot read pipe for some reason!')
        pipe_has_data = False

    return data_length, data, pipe_has_data


def read_pipe_5(pipe):
    pipe_has_data = True
    data = None
    try:
        # data_length = decode_4byte_val(pipe.read(4).decode('Latin-1'))
        data = os.read(pipe.fileno(), 5)
        if len(data) == 0:
            pipe_has_data = False
        else:
            data = data.decode('Latin-1')
    except OSError:
        print('cannot read pipe for some reason!')
        pipe_has_data = False

    return data, pipe_has_data


def write_pipe(pipe, data):
    data_length = encode_4byte_val(len(data)).encode('Latin-1')
    data = data.encode('Latin-1')

    pipe.write(data_length)
    pipe.write(data)
    pipe.flush()


def read_tick_pipe(pipe):
    read_ticks = 0
    while True:
        data, has_data = read_pipe_5(pipe)
        if not has_data:
            break

        read_ticks += 1
    return read_ticks


def random_16_bit():
    return randrange(TWO_POW_16)


def print_log(message):
    print(message)


def create_syn_ack_packet(src_port, dst_port, ack_num, win_size):
    flags = generate_flags(syn=1, fin=0, ack=1, cwr=0)
    packet = generate_tcp_header(src_port, dst_port, 0, ack_num, 0, flags, win_size)
    packet = add_checksum(packet)
    return packet


def create_syn_packet(src_port, dst_port, ack_num, win_size):
    flags = generate_flags(syn=1, fin=0, ack=0, cwr=0)
    random_seq_num = random_16_bit()
    packet = generate_tcp_header(src_port, dst_port, random_seq_num, ack_num, 0, flags, win_size)
    packet = add_checksum(packet)
    return packet, random_seq_num + 1


def create_payload_packet(src_port, dst_port, ack_num, win_size, seq_number, payload):
    flags = generate_flags(syn=0, fin=0, ack=0, cwr=0)
    packet = generate_tcp_header(src_port, dst_port, seq_number, ack_num, 0, flags, win_size)
    packet += payload
    packet = add_checksum(packet)
    return packet


class SegmentParser:
    def __init__(self, segment_data):
        self.raw_data = segment_data
        self.src_port = decode_2byte_val(segment_data[0:2])
        self.dst_port = decode_2byte_val(segment_data[2:4])
        self.seq_number = decode_4byte_val(segment_data[4:8])
        self.ack_number = decode_4byte_val(segment_data[8:12])
        self.data_offset = ord(segment_data[12]) // 16
        self.cwr_flag = ord(segment_data[13]) & 0b1000_0000 != 0
        self.ack_flag = ord(segment_data[13]) & 0b0001_0000 != 0
        self.syn_flag = ord(segment_data[13]) & 0b0000_0010 != 0
        self.fin_flag = ord(segment_data[13]) & 0b0000_0001 != 0
        self.window_size = decode_2byte_val(segment_data[14:16])
        self.checksum = decode_2byte_val(segment_data[16:18])
        self.urg_pointer = decode_2byte_val(segment_data[18:20])
        self.payload = segment_data[20:]
        self.payload_size = len(self.payload)

    def __cmp__(self, other):
        return (self.raw_data == other.raw_data and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.seq_number == other.seq_number and
                self.ack_number == other.ack_number and
                self.data_offset == other.data_offset and
                self.cwr_flag == other.cwr_flag and
                self.ack_flag == other.ack_flag and
                self.syn_flag == other.syn_flag and
                self.fin_flag == other.fin_flag and
                self.window_size == other.window_size and
                self.checksum == other.checksum and
                self.urg_pointer == other.urg_pointer and
                self.payload == other.payload and
                self.payload_size == other.payload_size)

    def checksum_valid(self):
        checksum = decode_2byte_val(generate_checksum(self.raw_data))

        return checksum == 0x0000 or checksum == 0xFFFF


def create_ack_packet(src_port, dst_port, ack_num, win_size, seq_number):
    flags = generate_flags(syn=0, fin=0, ack=1, cwr=0)
    packet = generate_tcp_header(src_port, dst_port, seq_number, ack_num, 0, flags, win_size)
    packet = add_checksum(packet)
    return packet


def create_fin_packet(src_port, dst_port, ack_num, win_size, seq_number):
    flags = generate_flags(syn=0, fin=1, ack=0, cwr=0)
    packet = generate_tcp_header(src_port, dst_port, seq_number, ack_num, 0, flags, win_size)
    packet = add_checksum(packet)
    return packet


def add_checksum(packet):
    checksum = encode_2byte_val((TWO_POW_16 - 1) - decode_2byte_val(generate_checksum(packet)))
    final_packet = packet[:16] + checksum + packet[18:]
    return final_packet


def get_pipes_folder_path():
    return get_home_folder_path() + 'pipes/'


def get_home_folder_path():
    home_folder_path = str(__file__)
    home_folder_path = home_folder_path[:home_folder_path.rindex('/')]
    home_folder_path = home_folder_path[:home_folder_path.rindex('/')] + '/'
    return home_folder_path


def get_data_folder_path():
    return get_home_folder_path() + 'data/'


def get_codes_folder_path():
    return get_home_folder_path() + 'codes/'


def create_fin_ack_packet(src_port, dst_port, ack_num, win_size, seq_number):
    flags = generate_flags(syn=0, fin=0, ack=1, cwr=0)
    packet = generate_tcp_header(src_port, dst_port, seq_number, ack_num, 0, flags, win_size)
    packet = add_checksum(packet)
    return packet
