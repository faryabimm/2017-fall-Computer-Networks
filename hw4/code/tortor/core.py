from os import urandom

from rsa import decrypt, VerificationError

from .crypto import blob_rsa_dec, blob_rsa_enc
from .net import Node
from .packet import Packet
from .utils import *

MAX_PATH_LENGTH = 6
MIN_PATH_LENGTH = 6
MIN_COUNTRY_CNT = 2
DOUBLE_ENC_HEADER_SIZE = 1540

# unfortunately i've discovered packet file classes and discovered their methods after i've implemented this file :)) so i've coded this file's methods from the scratch in bytes level!!!


class RelayAddress:
    """
    Information card for network nodes
    """

    def __init__(self, ip, pk):
        """
        :param ip: bytes
        :param pk: rsa.PublicKey
        """
        self.ip = ip
        self.pk = pk


class RelayConfig:
    def __init__(self, relay_list, net_graph):
        """
        The relay configuration object which contains a list
        of known public relays in addition to their network
        topology as a graph
        :param relay_list: List<RelayAddress>
        :param net_graph: Set<Tuple<bytes (IP of node1), bytes (IP of node2), float (edge weight)>>
        """
        self.relay_list = relay_list
        self.net_graph = net_graph
        self.dist_map = dict([((n1, n2), d) for n1, n2, d in net_graph])

    def look_up_pk(self, ip):
        """
        returns public key of node with given IP address
        :param ip: bytes
        :return: rsa.PublicKey
        """
        for r in self.relay_list:
            if r.ip == ip:
                return r.pk

    def latency(self, n1, n2):
        return self.dist_map[(n1, n2)]

    def get_ip_country(self, ip):
        return ip.split(b".")[2]


class Relay(Node):
    def __init__(self, ip, pubkey, privkey, config, hidden_keypair=None):
        """
        :param ip: IP address of this node
        :param pubkey: rsa.PublicKey
        :param register: dict: return route of registered nodes on this relay as HH
        :param privkey: rsa.PrivateKey
        :param config: RelayConfig
        :param hidden_keypair: public-key and private-key of this node's hidden identity for deep web [optional]
        """
        super().__init__(ip)
        self.pubkey = pubkey
        self.privkey = privkey
        self.register = dict()
        self.config = config
        self.hidden_keypair = hidden_keypair
        self.register = {}

    @staticmethod
    def eoh(dest_pk):
        """
        The end of hops header bytes string encrypted for
        certain node
        :param dest_pk:
        :return:
        """
        return rsa.encrypt(b'0.0.0.0', dest_pk)

    def on_packet(self, payload, src_ip):
        """
        this gets called when the Relay receives a packet. Here,
        we parse the packet and decide whether we are the intended
        receiver or whether we should pass it along to another
        node in the TorToar network.

        :param payload: see parent class
        :param src_ip: see parent class
        :return: see parent class
        """

        # parse packet
        packet = Packet.from_bytes(payload, self.privkey) if not self.hidden_keypair \
            else Packet.from_bytes(payload, self.privkey, self.hidden_keypair[1])
        log("@", self.ip, "next hop =", packet.header.hops[0], level=4)
        next_hop_ip = decrypt(packet.header.hops[0], self.privkey)

        # decide whether packet targets us or another node
        if next_hop_ip == b"0.0.0.0":
            self.receive_packet(packet)
        else:
            self.relay_packet(packet, next_hop_ip)

    def relay_packet(self, packet, next_hop_ip):
        """
        Called on a packet that is not intended
        for current node. This method should update the
        packet header and pass it through the network.

        :param packet:
        :param next_hop_ip:
        :return:
        """

        # TODO_DONE this is filled by the student

        phone_book = {}
        for elem in self.config.relay_list:
            phone_book[elem.ip] = elem.pk

        header = packet.header[256:] + urandom(256)
        header_enc = blob_rsa_enc(header, phone_book[next_hop_ip])
        body_enc = packet.body

        length = Relay.encode_4byte_val(len(header_enc) + len(body_enc) + 4)
        packet = length + header_enc + body_enc
        self.netman.convey_packet(self.ip, next_hop_ip, packet)

    def receive_packet(self, packet):
        """
        Called when a packet intended for current node is received. Keep in mind
        that the current node might be the hidden-handler and not the final node,
        but this method will be called all the same. Here, we shall check the
        body of the received packet, and act based on its type.

        Register packets: the hops should be kept in memory for the given hidden pubkey
        Data packet: the final destination must be checked. If the current node
                     is the FINAL receiver, self.on_data() should be called. otherwise,
                     a new packet must be created and sent through the registered
                     return hops to the final receiver.

        :param packet: Packet - received packet
        """
        # TODO_DONE this is filled by the student

        byte_flag = packet.body[:1]

        if byte_flag == b'\x01':
            reg_body = Packet
            sender_pub_key = packet.body[1:256 + 1]
            route_block = packet.body[256 + 1: 256 + 1 + 256 * 5]
            challenge = packet.body[256 + 1 + 256 * 5:]
            self.register[sender_pub_key] = route_block
        else:
            dest_pub_key = packet.body[1:256 + 1]
            sender_pub_key = packet.body[1 + 256:1 + 256 * 2]
            data_blob = packet.body[1 + 256 * 2:]

            if dest_pub_key == self.pubkey or dest_pub_key == self.hidden_keypair[0]:
                self.on_data(sender_pub_key, data_blob, hidden=dest_pub_key == self.hidden_keypair[0])
            else:
                path = self.register[dest_pub_key]

                body_enc = blob_rsa_enc(packet.body, dest_pub_key)

                phone_book = {}
                for elem in self.config.relay_list:
                    phone_book[elem.ip] = elem.pk

                next_hop_ip = blob_rsa_dec(path[:256], self.privkey)
                header_enc = blob_rsa_enc(path, phone_book[next_hop_ip])

                length = Relay.encode_4byte_val(len(header_enc) + len(body_enc) + 4)
                packet = length + header_enc + body_enc
                self.netman.convey_packet(self.ip, next_hop_ip, packet)

    @property
    def address(self):
        return RelayAddress(ip=self.ip, pk=self.pubkey)

    def on_data(self, sender_pk, payload, hidden=False):
        """
        Called when a data packet is delivered to its final
        recipient
        """
        message = blob_rsa_dec(payload, self.privkey if not hidden else self.hidden_keypair[1])
        print("Message:", message, "from", sender_pk)

    def build_circuit(self, from_node, to_node):
        """
        Based on relay's configurations, this method should return a path

        from the first node to the other, with the following characteristics:
        i)   the minimum (edge count) length of the path should be 4
        ii)  the middle nodes should cross at least two different countries
             HINT: use get_ip_country() to look up country of and IP addr
        iii) the number of hops be the minimum possible
        iv)  the path should have the minimum weighted length amongst all
             paths having features i, ii and iii.
             The edge weights indicates network latency (the lower, the better)

        Use the Data Structure & Algorithms force, Luke :)

        :param from_node: start node (IP)
        :param to_node: target node (IP)
        :return: List<bytes (IP addresses)> - list of all nodes (denoted by IP) in the path including start and end
        """
        # TODO_DONE this is filled by the student

        graph = {}

        for element in self.config.net_graph:
            if element[0] not in graph:
                graph[element[0]] = []

            graph[element[0]].append((element[1], element[2]))

        paths = [([(from_node, 0)], 0)]
        Relay.find_all_paths(paths, [], graph, from_node, to_node, 0)

        # print(paths)

        paths = list(
            filter(lambda x: len(x[0]) >= MIN_PATH_LENGTH and Relay.country_count(x) >= MIN_COUNTRY_CNT, paths))
        paths = sorted(paths, key=lambda x: x[1])

        print(paths)

        the_path = [elem[0] for elem in paths[0][0]]

        return the_path

    @staticmethod
    def find_all_paths(paths, path, graph, start_ip, target_ip, cost_so_far):
        if len(path) > MAX_PATH_LENGTH:
            return
        if start_ip == target_ip:
            paths.append((path, cost_so_far))
            return
        print(graph)
        for elem in graph[start_ip]:
            new_path = list(path)
            new_path.append(elem)
            Relay.find_all_paths(paths, new_path, graph, elem[0], target_ip, cost_so_far + elem[1])

    @staticmethod
    def country_count(path):
        # print(path)
        countries = set()
        countries.add([path[0][i][0] for i in range(1, len(path[0]) - 1)])  # not first and last nodes!
        return len(countries)

    def register_on(self, target_node, go_route, return_route):
        """
        creates a packet for registering itself on target_node
        based on the provided forth and backward routes and sends it

        :param target_node: RelayAddress :param go_route: List<bytes (IP addresses)> path from current node to the target node INCLUDING themselves
        :param return_route: List<bytes (IP addresses)> path from target node to the current node INCLUDING themselves
        """
        # TODO_DONE this is filled by the student

        phone_book = {}
        for elem in self.config.relay_list:
            phone_book[elem.ip] = elem.pk

        flag_byte = b'\x01'

        header = b""

        for i in range(1, 6):
            if i == len(go_route) - 1:
                header += rsa.encrypt(b"0.0.0.0", phone_book[go_route[i]])  # last address place should be 0.0.0.0
            elif i < len(go_route) - 1:
                header += rsa.encrypt(go_route[i + 1], phone_book[go_route[i]])
                # each hop should be able to decrypt address of its next hop
            else:
                header += urandom(256)  # random filling empty address places

        header_enc = blob_rsa_enc(header, phone_book[go_route[0]])

        sender_pub_key = self.pubkey

        route_block = b""

        for i in range(1, 6):
            if i == len(return_route) - 1:
                route_block += rsa.encrypt(b"0.0.0.0",
                                           phone_book[return_route[i]])  # last address place should be 0.0.0.0
            elif i < len(return_route) - 1:
                route_block += rsa.encrypt(return_route[i + 1], phone_book[return_route[i]])
                # each hop should be able to decrypt address of its next hop
            else:
                route_block += urandom(256)  # random filling empty address places

        challenge = self.challenge()

        body_raw = flag_byte + sender_pub_key + route_block + challenge
        body_enc = blob_rsa_enc(body_raw, target_node.pubkey)

        length = Relay.encode_4byte_val(len(header_enc) + len(body_enc) + 4)
        packet = length + header_enc + body_enc
        self.netman.convey_packet(self.ip, go_route[1], packet)

    def send_data_hidden(self, message_raw, hidden_handler, dest_pk, route):
        """
        Sends a packet to a hidden TorToar circuit. (dark-web-ish data node)

        :param message_raw: bytes
        :param hidden_handler: RelayAddress
        :param dest_pk: rsa.PublicKey - public key of hidden target node
        :param route: List<bytes (IP addresses)> - path from current node to the target node INCLUDING themselves
        """
        # TODO_DONE this is filled by the student
        phone_book = {}
        for elem in self.config.relay_list:
            phone_book[elem.ip] = elem.pk

        # target_node = route[-1]

        flag_byte = b'\x00'

        dest_pub_key = dest_pk
        sender_pub_key = self.pubkey

        message_enc = blob_rsa_enc(message_raw, dest_pk)

        body_raw = flag_byte + dest_pub_key + sender_pub_key + message_enc
        body_enc = blob_rsa_enc(body_raw, hidden_handler.pk)

        header = b""

        for i in range(1, 6):
            if i == len(route) - 1:
                header += rsa.encrypt(b"0.0.0.0", phone_book[route[i]])  # last address place should be 0.0.0.0
            elif i < len(route) - 1:
                header += rsa.encrypt(route[i + 1], phone_book[route[i]])
                # each hop should be able to decrypt address of its next hop
            else:
                header += urandom(256)  # random filling empty address places

        header_enc = blob_rsa_enc(header, phone_book[route[0]])

        length = Relay.encode_4byte_val(len(header_enc) + len(body_enc) + 4)

        packet = length + header_enc + body_enc

        self.netman.convey_packet(self.ip, route[1], packet)

    def send_data_simple(self, message_raw, relay_address, route):
        """
        send a normal (not hidden) data packet through the given hops
        :param message_raw: bytes - the message to be sent
        :param relay_address: RelayAddress - target node address
        :param route: List<bytes (IP addresses)> - path from current node to the target node INCLUDING themselves
        """

        # TODO_DONE this is filled by the student

        phone_book = {}
        for elem in self.config.relay_list:
            phone_book[elem.ip] = elem.pk

        target_node = route[-1]

        message_enc = blob_rsa_enc(message_raw, phone_book[target_node])

        header = b""

        for i in range(1, 6):
            if i == len(route) - 1:
                header += rsa.encrypt(b"0.0.0.0", phone_book[route[i]])  # last address place should be 0.0.0.0
            elif i < len(route) - 1:
                header += rsa.encrypt(route[i + 1], phone_book[route[i]])
                # each hop should be able to decrypt address of its next hop
            else:
                header += urandom(256)  # random filling empty address places

        header_enc = blob_rsa_enc(header, phone_book[route[0]])

        flag_byte = b'\x00'

        dest_pub_key = relay_address.pk
        sender_pub_key = self.pubkey

        body_raw = flag_byte + dest_pub_key + sender_pub_key + message_enc
        body_enc = blob_rsa_enc(body_raw, phone_book[target_node])

        length = Relay.encode_4byte_val(len(header_enc) + len(body_enc) + 4)

        packet = length + header_enc + body_enc

        self.netman.convey_packet(self.ip, route[1], packet)

    def challenge(self):
        """
        Used for generating the time based challenge required
        for registering on remote hosts
        :return: bytes - signed challenge (placed directly in register packet)
        """
        return rsa.sign(b"%d" % self.netman.current_time, self.privkey, "SHA-1")

    def verify(self, challenge, pubkey):
        """
        Used for verifying time based challenges when receiving
        register messages
        :param challenge: bytes - received challenge bytes
        :param pubkey: rsa.PublicKey - public key of the registering remote node
        :return: boolean - whether challenge is valid
        """
        try:
            return rsa.verify(self.netman.current_time, challenge, pubkey)
        except VerificationError:
            return False


def encode_4byte_val(in_val):
    in_val = int(in_val)
    ll_byte = (in_val >> 24) & 0x0FF
    lm_byte = (in_val >> 16) & 0x0FF
    rm_byte = (in_val >> 8) & 0x0FF
    rr_byte = (in_val & 0x0FF)
    result = chr(ll_byte) + '' + chr(lm_byte) + '' + chr(rm_byte) + '' + chr(rr_byte)
    return result.encode('Latin-1')


def decode_4byte_val(in_val):
    in_val = in_val.decode('Latin-1')
    return ((ord(in_val[0]) * 256 + ord(in_val[1])) * 256 + ord(in_val[2])) * 256 + ord(in_val[3])
