import socket
import threading
import sys
from packet import *

SERVER_PORT_NUMBER = 15353
BUFFER_SIZE = 4096


def main():
    # root_server_ip = '198.41.0.4'
    root_server_ip = sys.argv[1]

    print('----> (DISPATCHER) Root Server IP is:\t', root_server_ip)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    udp_socket.bind(('', SERVER_PORT_NUMBER))  # binds udp socket to localhost:12355

    print('----> (DISPATCHER) Socket Initialized')

    next_worker_port_number = 15354
    while True:
        worker_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        worker_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        worker_socket.bind(('', next_worker_port_number))
        next_worker_port_number += 1

        data, client_address = udp_socket.recvfrom(BUFFER_SIZE)
        print('----> (DISPATCHER) Client Connected. Dispatching Worker Thread ', next_worker_port_number - 1)
        thread = threading.Thread(target=worker_thread,
                                  args=(udp_socket, root_server_ip, data, client_address, worker_socket,
                                        next_worker_port_number - 1))
        thread.start()


def worker_thread(udp_socket, root_server_ip, data, client_address, worker_socket, worker_number):
    try:
        request_log_generator = LogGenerator()
        received_responses_log_generator = LogGenerator()
        response_packet_log_generator = LogGenerator()

        print('----> ({}) Parsing Client Request, Logging'.format(worker_number))
        data = data.decode('Latin-1')
        user_query_packet = Packet(data, request_log_generator)

        qr = user_query_packet.QR
        opcode = user_query_packet.OPCODE

        if not (qr == 0 and opcode == 0):  # refused packet condition
            print('----> ({}) Refused Query. Generating Response Packet'.format(worker_number))
            my_response_packet = refused_answer_packet_builder(user_query_packet.message_id)
            udp_socket.sendto(my_response_packet.encode('Latin-1'), client_address)
            print('----> ({}) Logging Response Packet'.format(worker_number))
            Packet(my_response_packet, response_packet_log_generator)
        else:
            if is_in_ip_format(user_query_packet.QNAME_address):
                print('----> ({}) Inverse Query.'.format(worker_number))
                inverse_query(udp_socket, user_query_packet, root_server_ip, client_address, request_log_generator,
                              received_responses_log_generator, response_packet_log_generator, worker_socket,
                              worker_number)
            else:
                print('----> ({}) Normal Query.'.format(worker_number))
                normal_query(udp_socket, user_query_packet, root_server_ip, client_address, request_log_generator,
                             received_responses_log_generator, response_packet_log_generator, worker_socket,
                             worker_number)

        print('----> ({}) Creating Log Files'.format(worker_number))

        request_log_generator.flush(str(user_query_packet.message_id), '-request')
        received_responses_log_generator.flush(str(user_query_packet.message_id), '')
        response_packet_log_generator.flush(str(user_query_packet.message_id), '-response')

        print('----> ({}) Done Handling Client Request'.format(worker_number))

    except KeyboardInterrupt:
        udp_socket.close()
        exit(0)


def inverse_query(udp_socket, user_query_packet, root_server_ip, client_address, request_log_generator,
                  received_responses_log_generator, response_packet_log_generator, worker_socket, worker_number):
    refused = False

    target_address = ip_inverter(user_query_packet.QNAME_address) + '.in-addr.arpa'
    my_query_packet = query_packet_builder(user_query_packet.message_id, target_address)

    print('----> ({}) Generating Query Packet. Logging.'.format(worker_number))
    Packet(my_query_packet, request_log_generator)

    server_ip = root_server_ip
    while True:
        server_address = (server_ip, 53)

        print('----> ({}) Querying server @'.format(worker_number), server_ip)
        received_responses_log_generator.log('connecting to ' + server_ip)
        received_responses_log_generator.log('===============')

        worker_socket.sendto(my_query_packet.encode('Latin-1'), server_address)

        print('----> ({}) Receiving Server Response'.format(worker_number))

        server_response, _ = worker_socket.recvfrom(BUFFER_SIZE)

        print('----> ({}) Parsing Server Response. Logging.'.format(worker_number))
        server_response = server_response.decode('Latin-1')
        server_response_packet = Packet(server_response, received_responses_log_generator)

        if target_address in server_response_packet.PTR_records.keys():
            print('----> ({}) Query Target Found!'.format(worker_number))
            break
        elif any(server_response_packet.A_records):
            # server_ip = sorted(server_response_packet.A_records.values())[0]
            ip_val = sorted(map(lambda x: ip_value(x), server_response_packet.A_records.values()))[0]
            server_ip = ip_from_val(ip_val)
        elif any(server_response_packet.NS_records):
            server_ip = sorted(server_response_packet.NS_records.values())[0]
        else:
            print('----> ({}) Query Target Could Not Be Found!'.format(worker_number))
            refused = True
            break

    if not refused:
        print('----> ({}) Generating Response Packet.'.format(worker_number))
        ans = server_response_packet.PTR_records[target_address]
        my_response_packet = iquery_response_packet_builder(user_query_packet.message_id, target_address, ans)
    else:
        print('----> ({}) Generating Refused Response Packet.'.format(worker_number))
        my_response_packet = refused_answer_packet_builder(user_query_packet.message_id)

    print('----> ({}) Sending Response Packet to Client.'.format(worker_number))
    udp_socket.sendto(my_response_packet.encode('Latin-1'), client_address)

    print('----> ({}) Logging Response Packet.'.format(worker_number))
    Packet(my_response_packet, response_packet_log_generator)


def normal_query(udp_socket, user_query_packet, root_server_ip, client_address, request_log_generator,
                 received_responses_log_generator, response_packet_log_generator, worker_socket, worker_number):
    refused = False

    print('----> ({}) Generating Query Packet. Logging.'.format(worker_number))
    my_query_packet = query_packet_builder(user_query_packet.message_id, user_query_packet.QNAME_address)
    Packet(my_query_packet, request_log_generator)

    server_ip = root_server_ip
    target_address = user_query_packet.QNAME_address
    while True:
        server_address = (server_ip, 53)
        print('----> ({}) Querying server @'.format(worker_number), server_ip)
        received_responses_log_generator.log('connecting to ' + server_ip)
        received_responses_log_generator.log('===============')

        worker_socket.sendto(my_query_packet.encode('Latin-1'), server_address)

        print('----> ({}) Receiving Server Response'.format(worker_number))
        server_response, _ = worker_socket.recvfrom(BUFFER_SIZE)

        print('----> ({}) Parsing Server Response. Logging.'.format(worker_number))
        server_response = server_response.decode('Latin-1')
        server_response_packet = Packet(server_response, received_responses_log_generator)

        if target_address in server_response_packet.A_records.keys():
            print('----> ({}) Query Target Found!'.format(worker_number))
            break
        else:
            if len(server_response_packet.A_records) != 0:
                # server_ip = sorted(server_response_packet.A_records.values())[0]
                ip_val = sorted(map(lambda x: ip_value(x), server_response_packet.A_records.values()))[0]
                server_ip = ip_from_val(ip_val)
            else:
                print('----> ({}) Query Target Could Not Be Found!'.format(worker_number))
                refused = True
                break

    if not refused:
        print('----> ({}) Generating Response Packet.'.format(worker_number))
        ans = server_response_packet.A_records[target_address]
        my_response_packet = answer_packet_builder(user_query_packet.message_id, user_query_packet.QNAME_address, ans)
    else:
        print('----> ({}) Generating Refused Response Packet.'.format(worker_number))
        my_response_packet = refused_answer_packet_builder(user_query_packet.message_id)

    print('----> ({}) Sending Response Packet to Client.'.format(worker_number))
    udp_socket.sendto(my_response_packet.encode('Latin-1'), client_address)

    print('----> ({}) Logging Response Packet.'.format(worker_number))
    Packet(my_response_packet, response_packet_log_generator)


if __name__ == '__main__':
    main()