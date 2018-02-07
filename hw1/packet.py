import collections

from enum import Enum


class QTYPE(Enum):
    A = '\x00\x01'  # IPv4 Record
    NS = '\x00\x02'  # Name Server Record
    CNAME = '\x00\x05'  # Canonical Name Record
    SOA = '\x00\x06'  # Start of Authority Resource Record (SOARR)
    PTR = '\x00\x0C'  # Pointer Record
    MX = '\x00\x0F'  # Mail Exchanger
    AAAA = '\x00\x1C'  # IPv6 Record
    TXT = '\x00\x10'  # Text Record
    ALL = '\x00\xFF'  # ALL types


class QCLASS(Enum):
    IN = '\x00\x01'  # IN (Internet)


type_dictionary = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA'
}
response_code_dictionary = {
    0: 'No Error',
    1: 'Format Error',
    2: 'Server Failure',
    3: 'Name Error',
    4: 'Not Implemented',
    5: 'Refused',
}


class LogGenerator:
    def __init__(self):
        self.buffer = ''

    def log(self, string):
        self.buffer += string + '\n'
        # print(string)

    def flush(self, name, postfix):
        if self.buffer != '':
            filename = name + postfix + '.txt'
            file = open(filename, 'w+')
            file.write(self.buffer)
            file.close()


class Packet:
    def print_dictionary(self, dictionary):
        self.logger(self.stringify_dictionary(dictionary))

    def stringify_dictionary(self, dictionary):
        string = '{\n'
        for key, value in dictionary.items():
            string += str(key) + ' ' + str(value) + '\n'
        string += '}'
        return string

    def print_title(self, title):
        if title.lower() != 'header':
            self.logger('===============')
        self.logger(title.upper())
        self.logger('===============')

    def logger(self, string):
        self.log_generator.log(string)

    def extract_name(self, byte_stream, parser_head):
        name, parser_head = self.extract_name_rec(byte_stream, parser_head, '')
        name = name[:-1]
        name = name.lower()

        if '://' in name:
            name = name[name.find('://') + 3:]
        if name.startswith('www.'):
            name = name[4:]
        return name, parser_head

    def extract_name_rec(self, byte_stream, parser_head, name):
        is_pointer = ord(byte_stream[parser_head]) & 0xC0 == 0xC0
        if is_pointer:
            pointer = ((ord(byte_stream[parser_head]) & 0x3F) * 256) + (ord(byte_stream[parser_head + 1]))
            name, _ = self.extract_name_rec(byte_stream, pointer, name)
            parser_head += 2
        else:
            segment_size = ord(byte_stream[parser_head:parser_head + 1])
            parser_head += 1
            if segment_size == 0:
                return name, parser_head
            else:
                for x in range(0, segment_size):
                    name += byte_stream[parser_head:parser_head + 1]
                    parser_head += 1
                name += '.'
                name, parser_head = self.extract_name_rec(byte_stream, parser_head, name)

        return name, parser_head

    def extract_rdata(self, byte_stream, parser_head, rdata_type, rdata_length, record_dictionary):
        if rdata_type == QTYPE.A.value:
            rdata = ''
            ip = byte_stream[parser_head: parser_head + 4]
            parser_head += 4
            for i in range(0, 4):
                rdata += str(ord(ip[i])) + '.'
            rdata = rdata[:-1]
            record_dictionary['rdata :'] = rdata
            self.A_records[record_dictionary['name :']] = rdata
        elif rdata_type == QTYPE.NS.value:
            name_server, parser_head = self.extract_name(byte_stream, parser_head)
            record_dictionary['rdata :'] = name_server
            self.NS_records[self.dummy_name] = name_server
            self.dummy_name += 'a'
        elif rdata_type == QTYPE.CNAME.value:
            cname, parser_head = self.extract_name(byte_stream, parser_head)
            record_dictionary['rdata :'] = cname
        elif rdata_type == QTYPE.SOA.value:
            soa_rdata = {}

            primary_ns, parser_head = self.extract_name(byte_stream, parser_head)
            soa_rdata['Primary NS :'] = primary_ns

            admin_mb, parser_head = self.extract_name(byte_stream, parser_head)
            soa_rdata['Admin MB :'] = admin_mb

            serial_number = byte_stream[parser_head: parser_head + 4]
            parser_head += 4
            soa_rdata['Serial Number :'] = self.decode_4byte_val(serial_number)

            refresh_interval = byte_stream[parser_head: parser_head + 4]
            parser_head += 4
            soa_rdata['Refresh interval :'] = self.decode_4byte_val(refresh_interval)

            retry_interval = byte_stream[parser_head: parser_head + 4]
            parser_head += 4
            soa_rdata['Retry interval :'] = self.decode_4byte_val(retry_interval)

            expiration_limit = byte_stream[parser_head: parser_head + 4]
            parser_head += 4
            soa_rdata['Expiration Limit :'] = self.decode_4byte_val(expiration_limit)

            minimum_ttl = byte_stream[parser_head: parser_head + 4]
            parser_head += 4
            soa_rdata['Minimum TTL :'] = self.decode_4byte_val(minimum_ttl)

            soa_rdata = collections.OrderedDict(sorted(soa_rdata.items()))
            record_dictionary['rdata :'] = '\n' + self.stringify_dictionary(soa_rdata)
        elif rdata_type == QTYPE.PTR.value:
            ptr, parser_head = self.extract_name(byte_stream, parser_head)
            record_dictionary['rdata :'] = ptr
            self.PTR_records[record_dictionary['name :']] = ptr
        elif rdata_type == QTYPE.MX.value:
            mx_rdata = {}

            preference = byte_stream[parser_head: parser_head + 2]
            parser_head += 2
            mx_rdata['Preference :'] = self.decode_2byte_val(preference)

            mail_exchanger, parser_head = self.extract_name(byte_stream, parser_head)
            mx_rdata['Mail Exchanger :'] = mail_exchanger

            mx_rdata = collections.OrderedDict(sorted(mx_rdata.items()))
            record_dictionary['rdata :'] = '\n' + self.stringify_dictionary(mx_rdata)
        elif rdata_type == QTYPE.AAAA.value:
            ip = byte_stream[parser_head: parser_head + 16]
            parser_head += 16
            ipv6 = ''
            for i in range(0, 8):
                ipv6 += (hex(ord(ip[2 * i]))[2:]) if len(hex(ord(ip[2 * i]))[2:]) == 2 else '0' + (
                    hex(ord(ip[2 * i]))[2:])
                ipv6 += (hex(ord(ip[2 * i + 1]))[2:]) if len(hex(ord(ip[2 * i + 1]))[2:]) == 2 else '0' + (
                    hex(ord(ip[2 * i + 1]))[2:])
                ipv6 += ':'
            ipv6 = ipv6[:-1]
            record_dictionary['rdata :'] = ipv6
        elif rdata_type == QTYPE.TXT.value:
            text = byte_stream[parser_head: parser_head + rdata_length]
            parser_head += rdata_length
            record_dictionary['rdata :'] = text
        else:
            rdata = byte_stream[parser_head: parser_head + rdata_length]
            parser_head += rdata_length
            # record_dictionary['rdata :'] = rdata
            record_dictionary['rdata :'] = ''

        return record_dictionary, parser_head

    def decode_2byte_val(self, in_val):
        return ord(in_val[0]) * 256 + ord(in_val[1])

    def decode_4byte_val(self, in_val):
        return ((ord(in_val[0]) * 256 + ord(in_val[1])) * 256 + ord(in_val[2])) * 256 + ord(in_val[3])

    def decode_flags(self):
        self.QR = ((ord(self.flags[0]) >> 7) & 0x01)
        self.OPCODE = ((ord(self.flags[0]) >> 3) & 0x0F)
        self.AA = ((ord(self.flags[0]) >> 2) & 0x01)
        self.TC = ((ord(self.flags[0]) >> 1) & 0x01)
        self.RD = ((ord(self.flags[0]) >> 0) & 0x01)
        self.RA = ((ord(self.flags[1]) >> 7) & 0x01)
        self.RES = ((ord(self.flags[1]) >> 4) & 0x07)
        self.RCODE = ((ord(self.flags[1]) >> 0) & 0x0F)

    def get_record(self, byte_stream, parser_head):
        record_dictionary = {}

        self.NAME, parser_head = self.extract_name(byte_stream, parser_head)
        record_dictionary['name :'] = self.NAME

        self.TYPE = byte_stream[parser_head: parser_head + 2]
        parser_head += 2
        record_dictionary['type :'] = type_dictionary[self.decode_2byte_val(self.TYPE)] if self.decode_2byte_val(
            self.TYPE) in type_dictionary.keys() else self.decode_2byte_val(self.TYPE)

        self.CLASS = byte_stream[parser_head: parser_head + 2]
        parser_head += 2
        record_dictionary['class :'] = self.decode_2byte_val(self.CLASS)

        self.TTL = byte_stream[parser_head: parser_head + 4]
        parser_head += 4
        record_dictionary['ttl :'] = self.decode_4byte_val(self.TTL)

        self.RD_LENGTH = byte_stream[parser_head: parser_head + 2]
        parser_head += 2
        record_dictionary['rdlength :'] = self.decode_2byte_val(self.RD_LENGTH)

        record_dictionary, parser_head = self.extract_rdata(byte_stream, parser_head, self.TYPE,
                                                            self.decode_2byte_val(self.RD_LENGTH), record_dictionary)

        record_dictionary = collections.OrderedDict(sorted(record_dictionary.items()))
        self.print_dictionary(record_dictionary)

        return record_dictionary, parser_head

    def __init__(self, byte_stream, log_generator):
        self.log_generator = log_generator
        header_dictionary = {}
        self.A_records = {}
        self.dummy_name = 'a'
        self.NS_records = {}
        self.PTR_records = {}
        self.message_id = self.decode_2byte_val(byte_stream[:2])
        header_dictionary['id :'] = self.message_id

        self.flags = byte_stream[2:4]
        self.decode_flags()
        header_dictionary['is response :'] = 'True' if self.QR == 1 else 'False'
        header_dictionary['is authoritative :'] = 'True' if self.AA == 1 else 'False'
        header_dictionary['is truncated :'] = 'True' if self.TC == 1 else 'False'
        header_dictionary['recursion desired :'] = 'True' if self.RD == 1 else 'False'
        header_dictionary['recursion available :'] = 'True' if self.RA == 1 else 'False'
        header_dictionary['opcode :'] = self.OPCODE
        header_dictionary['response code :'] = response_code_dictionary[self.RCODE]
        header_dictionary['reserved :'] = self.RES

        self.QDCOUNT = byte_stream[4:6]
        header_dictionary['question count :'] = self.decode_2byte_val(self.QDCOUNT)

        self.ANCOUNT = byte_stream[6:8]
        header_dictionary['answer count :'] = self.decode_2byte_val(self.ANCOUNT)

        self.NSCOUNT = byte_stream[8:10]
        header_dictionary['authority count :'] = self.decode_2byte_val(self.NSCOUNT)

        self.ARCOUNT = byte_stream[10:12]
        header_dictionary['additional count :'] = self.decode_2byte_val(self.ARCOUNT)

        ################################################################################################################
        ################################################################################################################
        ################################################################################################################
        ################################################################################################################

        header_dictionary = collections.OrderedDict(sorted(header_dictionary.items()))
        self.print_title('header')
        self.print_dictionary(header_dictionary)

        ################################################################################################################
        ################################################################################################################
        ################################################################################################################
        ################################################################################################################

        parser_head = 12
        self.print_title('question')
        m = header_dictionary['question count :']
        for i in range(0, m):
            question_dictionary = {}
            self.QNAME_address, parser_head = self.extract_name(byte_stream, parser_head)
            question_dictionary['Domain Name :'] = self.QNAME_address

            self.QTYPE = byte_stream[parser_head: parser_head + 2]
            parser_head += 2
            question_dictionary['Query Type :'] = self.decode_2byte_val(self.QTYPE)

            self.QCLASS = byte_stream[parser_head: parser_head + 2]
            parser_head += 2
            question_dictionary['Query Class :'] = self.decode_2byte_val(self.QCLASS)

            question_dictionary = collections.OrderedDict(sorted(question_dictionary.items()))
            self.print_dictionary(question_dictionary)

        ################################################################################################################
        ################################################################################################################
        ################################################################################################################
        ################################################################################################################

        self.print_title('answer')
        n = header_dictionary['answer count :']
        for i in range(0, n):
            record_dictionary, parser_head = self.get_record(byte_stream, parser_head)

        self.print_title('authority')
        p = header_dictionary['authority count :']
        for i in range(0, p):
            record_dictionary, parser_head = self.get_record(byte_stream, parser_head)

        self.print_title('additional')
        q = header_dictionary['additional count :']
        for i in range(0, q):
            record_dictionary, parser_head = self.get_record(byte_stream, parser_head)
        self.logger('===============')


def QNAME_creator(address):
    QNAME = ''
    rdata_size = 0
    for element in str.split(address, '.'):
        QNAME += chr(len(element))
        QNAME += element
        rdata_size += len(element) + 1
        # for letter in list(element):
        #     QNAME += chr(ord(letter))
    QNAME += chr(0)  # end of QNAME
    rdata_size += 1
    return QNAME, rdata_size


def flag_generator(qr, opcode, aa, tc, rd, ra, rcode):
    aa = '1' if aa else '0'
    tc = '1' if tc else '0'
    rd = '1' if rd else '0'
    ra = '1' if ra else '0'

    flags_l = chr(int(qr + opcode + aa + tc + rd, 2))
    flags_r = chr(int(ra + '000' + rcode, 2))
    return flags_l + '' + flags_r


def encode_2byte_val(in_val):
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


def encode_ip(ip):
    ip_list = ip.split('.')
    encoded_ip = ''
    for i in range(0, 4):
        encoded_ip += chr(int(ip_list[i]))
    return encoded_ip


def packet_generator(message_id, flags, address, qa_type, qcount, acount, ans):
    packet = ''
    # packet += '\xAB\xDE'  # Message ID
    packet += encode_2byte_val(message_id)
    # packet += '\x00\x00'  # Flags (QR, OPCODE, AA, TC, RD, RA, RES, RCODE)
    packet += flags
    packet += chr(0) + '' + chr(qcount)  # QDCOUNT
    packet += chr(0) + '' + chr(acount)  # ANCOUNT
    packet += '\x00\x00'  # NSCOUNT
    packet += '\x00\x00'  # ARCOUNT

    qname, _ = QNAME_creator(address)
    packet += qname
    packet += qa_type
    packet += QCLASS.IN.value  # fixed by project definition

    if acount == 1:  # answer section
        packet += encode_4byte_val(3600)  # TTL
        packet += '\x00\x04'
        packet += encode_ip(ans)
    return packet


def query_packet_builder(message_id, address):
    return packet_generator(message_id, '\x00\x00', address, QTYPE.ALL.value, 1, 0, 0)


def answer_packet_builder(message_id, address, ans):
    return packet_generator(message_id, '\x80\x00', address, QTYPE.A.value, 0, 1, ans)


def iquery_response_packet_builder(message_id, address, ans):
    packet = ''
    # packet += '\xAB\xDE'  # Message ID
    packet += encode_2byte_val(message_id)
    # packet += '\x00\x00'  # Flags (QR, OPCODE, AA, TC, RD, RA, RES, RCODE)
    packet += '\x80\x00'
    packet += '\x00\x00'  # QDCOUNT
    packet += '\x00\x01'  # ANCOUNT
    packet += '\x00\x00'  # NSCOUNT
    packet += '\x00\x00'  # ARCOUNT

    qname, _ = QNAME_creator(address)
    packet += qname
    packet += QTYPE.PTR.value
    packet += QCLASS.IN.value  # fixed by project definition
    packet += encode_4byte_val(3600)  # TTL
    qname, rdata_length = QNAME_creator(ans)
    packet += encode_2byte_val(rdata_length)
    packet += qname
    return packet


def refused_answer_packet_builder(message_id):
    packet = ''
    # packet += '\xAB\xDE'  # Message ID
    packet += encode_2byte_val(message_id)
    # packet += '\x00\x00'  # Flags (QR, OPCODE, AA, TC, RD, RA, RES, RCODE)
    packet += '\x80\x05'
    packet += '\x00\x00'  # QDCOUNT
    packet += '\x00\x00'  # ANCOUNT
    packet += '\x00\x00'  # NSCOUNT
    packet += '\x00\x00'  # ARCOUNT
    return packet


def ip_inverter(ip):
    ip_list = ip.split('.')
    return ip_list[3] + '.' + ip_list[2] + '.' + ip_list[1] + '.' + ip_list[0]


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


def is_in_ip_format(ip):
    ip_list = ip.split('.')
    return (len(ip_list) == 4) and ''.join(ip_list).isdigit()
