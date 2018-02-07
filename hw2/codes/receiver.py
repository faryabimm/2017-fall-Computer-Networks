import os

from codes import utility


class Receiver:
    def __init__(self, receiver_port):
        self.receiver_port = receiver_port
        self.sender_port = None
        self.next_seq_num = None
        self.window_size = 0
        self.received_file = ''
        self.segment_cache = {}

        try:
            os.mkfifo(utility.get_pipes_folder_path() + 'receiver_' + self.receiver_port + '_data.pipe')
        except OSError as error:
            print('failed to create receive fifo files!')
        self.data_pipe = open(utility.get_pipes_folder_path() + 'receiver_' + receiver_port + '_data.pipe', 'rb')
        self.ack_pipe = open(utility.get_pipes_folder_path() + 'backwardnet_data.pipe', 'wb')
        # self.data_pipe = open(utility.get_pipes_folder_path() + 'sender_112_data.pipe', 'rb')

        self.print_log_message('is running...')

        self.start()

    def start(self):

        self.print_verbose('initiating connection')

        self.initiate_connection()

        utility.print_log('receive: initiating file reception')

        self.receive_file()

    def print_log_message(self, message):
        print('receiving host ' + self.receiver_port + ': ' + message)

    def print_verbose(self, message):
        self.print_log_message('---> ' + message)

    def terminate(self):
        self.print_log_message('is terminated.')
        exit(0)

    def wait_for_connection(self):

        self.print_verbose('waiting for SYN')
        segment_length, segment_data = utility.read_pipe_blocking(self.data_pipe)
        segment = utility.SegmentParser(segment_data)

        if segment.checksum_valid() and segment.syn_flag is True:
            self.print_verbose('received SYN')
            self.sender_port = segment.src_port
            self.next_seq_num = segment.seq_number + 1
            self.window_size = segment.window_size

        else:
            self.print_verbose('bad SYN segment, listening for SYN again')
            self.wait_for_connection()

    def send_syn_ack(self):
        self.print_verbose('sending SYN/ACK')
        packet = utility.create_syn_ack_packet(self.sender_port, self.receiver_port,
                                               self.next_seq_num, self.window_size)
        utility.write_pipe(self.ack_pipe, packet)
        self.print_verbose('sent SYN/ACK')

    def wait_for_ack(self):
        self.print_verbose('waiting for ACK')
        segment_length, segment_data, _ = utility.read_pipe(self.data_pipe)
        segment = utility.SegmentParser(segment_data)

        if segment.checksum_valid() and segment.ack_flag is True and segment.ack_number == 0:
            self.print_verbose('received ACK. connection established')
            self.next_seq_num = segment.seq_number + 1
            self.window_size = segment.window_size
        else:
            self.print_verbose('bad ACK segment, listening for ACK again')
            self.wait_for_ack()
            # TODO_DONE PACKET LOSS CONDITIONS?
            # THERE ARE NO PACKET LOSS CONDITIONS :D

    # TODO IMPLEMENT ACK SENDING
    def get_payload_packet(self):
        segment_length, segment_data, _ = utility.read_pipe(self.data_pipe)
        segment = utility.SegmentParser(segment_data)

        if segment.checksum_valid():
            return segment
        else:
            return self.get_payload_packet()

    def receive_file(self):
        while True:
            segment = self.get_payload_packet()
            self.print_verbose('received segment #' + str(segment.seq_number))
            if segment.fin_flag is True:
                self.print_verbose('got FIN packet! initiating finish sequence')
                self.terminate_connection()
                break
            else:
                if segment.seq_number != self.next_seq_num:
                    # TODO FIX THIS TO BE CIRCULAR AND INITIAL SEQ NUM TO BE 32 BIT
                    if segment.seq_number > self.next_seq_num:
                        self.print_verbose('got out of order packet! caching')
                        self.segment_cache[segment.seq_number] = segment
                        self.send_ack()
                    else:
                        self.print_verbose('got redundant packet. ignoring')
                        self.send_ack()
                else:
                    self.print_verbose('got in order packet! delivering to APP')
                    cache_sequence = False
                    while True:
                        self.received_file += segment.payload
                        self.next_seq_num += 1

                        if cache_sequence:
                            self.print_verbose('cached packet is in sequence! delivering to APP')
                        else:
                            cache_sequence = True

                        if self.next_seq_num in self.segment_cache.keys():
                            segment = self.segment_cache[self.next_seq_num]
                            self.segment_cache.pop(self.next_seq_num)
                        else:
                            break

                    self.send_ack()

    def send_ack(self):
        packet = utility.create_ack_packet(self.sender_port, self.receiver_port, self.next_seq_num, self.window_size, 0)
        utility.write_pipe(self.ack_pipe, packet)
        self.print_verbose('sent ack #' + str(utility.SegmentParser(packet).ack_number))

    def initiate_connection(self):
        self.wait_for_connection()
        self.send_syn_ack()
        self.wait_for_ack()

    def terminate_connection(self):
        self.send_fin_ack()
        self.send_fin()
        self.wait_for_fin_ack()

        self.print_verbose('saving file data')
        data_file = open(utility.get_data_folder_path() + 'retrieved_file_' + self.receiver_port + '.jpg', 'wb')
        data_file.write(self.received_file.encode('Latin-1'))
        data_file.close()
        self.print_verbose('saved file data')

        self.terminate()

    def send_fin_ack(self):
        self.print_verbose('sending FIN/ACK')
        packet = utility.create_fin_ack_packet(self.sender_port, self.receiver_port, self.next_seq_num
                                               , self.window_size, 0)
        utility.write_pipe(self.ack_pipe, packet)
        self.print_verbose('sent FIN/ACK')

    def send_fin(self):
        self.print_verbose('sending FIN')
        packet = utility.create_fin_packet(self.sender_port, self.receiver_port, 0, self.window_size, 0)
        utility.write_pipe(self.ack_pipe, packet)
        self.print_verbose('sent FIN')

    def wait_for_fin_ack(self):
        self.print_verbose('waiting for FIN/ACK')
        segment_length, segment_data, _ = utility.read_pipe(self.data_pipe)
        segment = utility.SegmentParser(segment_data)

        if segment.checksum_valid() and segment.ack_flag is True and segment.ack_number == 0:
            self.print_verbose('received FIN/ACK.')
        else:
            self.print_verbose('bad FIN/ACK segment, listening for FIN/ACK again')
            self.wait_for_fin_ack()
