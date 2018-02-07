import os
import time
from math import inf
from threading import Thread, Lock
from pathlib import Path

from codes import config, utility, congestion_manager


class AckChecker:
    def __init__(self, ack_pipe, parent):
        self.there_is_ack = False
        self.ack_data = None
        self.parent = parent
        self.ack_pipe = ack_pipe
        self.task_done = False
        self.thread = Thread(target=self.watch_acks, args=())
        self.thread.start()

    def watch_acks(self):
        while True:
            if self.there_is_ack:
                continue
            if self.task_done:
                break

            _, self.ack_data = utility.read_pipe_blocking(self.ack_pipe)

            self.parent.ack_mutex.acquire()
            self.there_is_ack = True
            self.parent.ack_mutex.release()

    def read_data(self):
        return self.ack_data, self.there_is_ack

    def go_on(self):
        self.ack_data = None
        self.there_is_ack = False

    def shutdown(self):
        self.task_done = True


class TimeWatcher:
    def __init__(self, time_pipe, parent):
        self.current_time = 0
        self.parent = parent
        self.time_pipe = time_pipe
        self.task_done = False
        self.thread = Thread(target=self.watch_time, args=())
        self.thread.start()

    def watch_time(self):
        while True:
            if self.task_done:
                break
            data, has_data = utility.read_pipe_5(self.time_pipe)
            if not has_data:
                break

            self.parent.mutex.acquire()
            self.current_time += 1
            self.parent.mutex.release()

    def shutdown(self):
        self.task_done = True


class Sender:
    def __init__(self, sender_port, receiver_port, initial_rtt, max_window, file_path):

        self.sender_port = sender_port
        self.receiver_port = receiver_port

        self.check_receiver_existence()

        self.next_seq_number = 0
        self.window_size = 1
        self.window_base = 0
        self.window_iter = 0
        self.next_base = 0
        self.next_size = 0
        self.last_window_end_seq_num = 0  # TODO FIRST ASSIGNMENT; slow start to normal mode transition
        self.file = None
        self.congestion_window = []
        self.congestion_window_prev = []
        self.backlog_window = []

        self.slow_start_phase = True
        self.file_finished = False
        self.mutex = Lock()
        self.ack_mutex = Lock()

        self.dup_ack_scenario = False
        self.dup_ack_count = 0
        self.dup_ack_candidate = None
        self.exec_timeout = False

        self.timeout_scenario = False
        self.timeout_rem_time = 0
        self.timeout_candidate = None
        self.exec_dup_ack = False

        self.timeout_time = 0

        self.cng_manager = congestion_manager.CongestionManager(initial_rtt, max_window)

        self.ss_threshold = inf
        self.max_window = max_window

        try:
            os.mkfifo(utility.get_pipes_folder_path() + 'sender_' + sender_port + '_data.pipe')
            os.mkfifo(utility.get_pipes_folder_path() + 'sender_' + sender_port + '_time.pipe')
        except OSError as error:
            print('failed to create sender fifo files!')

        # self.ack_pipe = open(utility.get_pipes_folder_path() + 'receiver_' + receiver_port + '_data.pipe', 'rb')
        # self.ack_pipe = open(utility.get_pipes_folder_path() + 'backwardnet_data.pipe', 'rb')
        self.ack_pipe = open(utility.get_pipes_folder_path() + 'sender_' + sender_port + '_data.pipe', 'rb')
        self.data_pipe = open(utility.get_pipes_folder_path() + 'forwardnet_data.pipe', 'wb')
        self.time_pipe = open(utility.get_pipes_folder_path() + 'sender_' + sender_port + '_time.pipe', 'rb')

        self.time_watcher = TimeWatcher(self.time_pipe, self)
        self.ack_watcher = AckChecker(self.ack_pipe, self)

        # try:
        #     posix.open(utility.get_pipes_folder_path() + 'forwardnet_data.pipe', posix.O_WRONLY | posix.O_NONBLOCK)
        # except OSError as error:
        #     if error.errno == errno.ENXIO:
        #         self.print_log_message('no receiving host ' + self.receiver_port + ' is available')
        #     self.terminate()

        # TODO_DONE GUARD TO CHECK THERE IS A RECEIVER ON THE OTHER SIDE

        self.start(file_path)

    def send_file(self):
        # INITIAL VALUES
        self.window_base = self.next_seq_number
        self.next_base = self.next_seq_number
        self.window_size = 1
        self.slow_start_phase = True
        self.next_size = 1
        self.window_iter = 0

        while not (self.file_finished and self.window_iter == self.window_size and len(self.backlog_window) == 0):
            self.send_window()

    def send_window(self):
        executed_dup_ack = False
        if self.window_iter >= self.window_size or len(self.congestion_window) == 0:
            self.refill_window()
        while self.window_iter < self.window_size:

            self.mutex.acquire()
            send_time = self.time_watcher.current_time
            send_seq_num = self.send_segment(self.window_iter)
            self.print_verbose('sent data segment #' + str(send_seq_num))
            self.mutex.release()

            time.sleep(0.05)

            self.mutex.acquire()
            sample_rtt = self.time_watcher.current_time - send_time
            self.print_verbose('sample rtt time is :' + str(sample_rtt) + ' s')
            self.check_ack(sample_rtt, send_seq_num)
            self.mutex.release()

            if self.exec_dup_ack:
                executed_dup_ack = True
                self.scenario_call(is_timeout=False)
                break

        if not executed_dup_ack:
            if self.timeout_scenario:
                self.scenario_call(is_timeout=True)

    def scenario_call(self, is_timeout):
        self.timeout_scenario = False
        self.exec_timeout = False
        self.dup_ack_scenario = False
        self.exec_dup_ack = False

        candidate_seq_num = self.timeout_candidate if is_timeout else self.dup_ack_candidate

        self.print_verbose('non-normal scenario on segment #' + str(candidate_seq_num))

        # candidate = self.grep_segment_candidate(candidate_seq_num)

        to_backlog = [seg for seg in self.congestion_window if seg.seq_number >= candidate_seq_num]
        to_backlog.extend(self.backlog_window)
        self.backlog_window = to_backlog
        self.print_verbose('backlog updated')

        not_to_backlog = [seg for seg in self.congestion_window if seg.seq_number < candidate_seq_num]
        self.congestion_window_prev = not_to_backlog
        self.print_verbose('window history updated')

        self.congestion_window = []
        self.print_verbose('current window cleared')

        if is_timeout:
            self.slow_start_phase = True
            self.print_verbose('timeout scenario on segment #' + str(candidate_seq_num))
            self.ss_threshold = max(config.MIN_WIN_SIZE, self.next_size // 2)
            self.window_size = 1
            self.next_size = 1
            self.window_base = candidate_seq_num
            self.next_base = candidate_seq_num
            self.window_iter = 0
        else:
            self.slow_start_phase = False
            self.print_verbose('dup_ack scenario on segment #' + str(candidate_seq_num))
            self.next_size = max(config.MIN_WIN_SIZE, self.next_size // 2)
            self.window_base = candidate_seq_num
            self.next_base = candidate_seq_num
            self.window_iter = 0

    def grep_segment_candidate(self, seq_num):
        try:
            segment = next(seg for seg in self.congestion_window if seg.seq_number == seq_num)
        except StopIteration:
            segment = next(seg for seg in self.congestion_window_prev if seg.seq_number == seq_num)

        return segment

    def refill_window(self):
        self.print_verbose('refilling empty window')
        # make sure not to exceed maximum window size

        if self.next_size > self.max_window:
            self.next_size = self.max_window
            self.print_verbose('shrunk window size to max size of ' + str(self.next_size) + ' upon allocating')
        else:
            self.print_verbose('window size is ' + str(self.next_size) + ' upon allocating')

        if len(self.congestion_window) != 0:
            self.print_verbose('window is normally passed without timeout or dup_ack')
            self.congestion_window_prev = self.congestion_window
            self.congestion_window = []
            self.print_verbose('current window cleared and window history updated')

        for _ in range(self.next_size):
            if len(self.backlog_window) != 0:
                segment = self.backlog_window[0]
                self.backlog_window.pop(0)
            else:
                segment = self.new_segment()
            self.congestion_window.append(segment)

        self.window_size = self.next_size
        self.window_base = self.next_base
        self.next_base = self.window_base + self.next_size
        self.window_iter = 0

    def send_segment(self, offset):
        seq_num = self.window_base + offset % utility.TWO_POW_32
        try:
            segment = next(seg for seg in self.congestion_window if seg.seq_number == seq_num)
            utility.write_pipe(self.data_pipe, segment.raw_data)
        except StopIteration:
            self.print_verbose('couldn\'t find segment #' + str(seq_num) + ' in window! :\\')

        return seq_num

    def check_ack(self, sample_rtt, send_seq_num):
        self.print_verbose('checking for ack #' + str(send_seq_num + 1))

        ack_data, there_is_ack = self.check_single_ack()

        if not there_is_ack:
            if not self.timeout_scenario:
                self.timeout_scenario = True
                self.timeout_time = sample_rtt
                self.timeout_candidate = send_seq_num
            elif self.timeout_time > sample_rtt:
                self.timeout_time = sample_rtt
                self.timeout_candidate = send_seq_num
            self.print_verbose('there is no ack. reserved for timeout with value ' + str(self.timeout_time) + ' s')
            self.window_iter += 1
        else:  # THERE IS ACK
            if sample_rtt >= self.cng_manager.timeout_interval():  # ACK RETRIEVED LATE:
                if not self.timeout_scenario:
                    self.timeout_scenario = True
                    self.timeout_time = sample_rtt
                    self.timeout_candidate = send_seq_num
                elif self.timeout_time > sample_rtt:
                    self.timeout_time = sample_rtt
                    self.timeout_candidate = send_seq_num
                self.print_verbose(
                    'ack is not in time! reserved for timeout with value ' + str(self.timeout_time) + ' s')
                self.window_iter += 1
            else:  # ACK RETRIEVED IN TIME
                ack_segment = utility.SegmentParser(ack_data)
                self.print_verbose('found ack #' + str(ack_segment.ack_number))
                if self.congestion_window[self.window_iter].seq_number < ack_segment.ack_number:

                    ack_count = ack_segment.ack_number - self.congestion_window[self.window_iter].seq_number
                    self.print_verbose('this ack, acked ' + str(ack_count) + ' segment(s)')
                    self.window_iter += ack_count

                    if self.slow_start_phase:
                        self.next_size += ack_count
                        self.print_verbose('window size increased by ' + str(ack_count) + ' segment(s) and now is '
                                           + str(self.next_size))
                    elif self.window_iter == self.window_size + self.window_base:
                        self.next_size += 1
                        self.print_verbose('window size increased by 1 segment and now is '
                                           + str(self.next_size))

                    self.dup_ack_scenario = False
                    self.timeout_scenario = False
                    self.cng_manager.update_rtt(sample_rtt)
                else:
                    self.print_verbose('this ack is duplicate')
                    if not self.timeout_scenario:
                        self.timeout_scenario = True
                        self.timeout_time = sample_rtt
                        self.timeout_candidate = send_seq_num
                    elif self.timeout_time > sample_rtt:
                        self.timeout_time = sample_rtt
                        self.timeout_candidate = send_seq_num
                    self.print_verbose('reserved for timeout with value ' + str(self.timeout_time) + ' s')

                    if not self.dup_ack_scenario:
                        self.dup_ack_scenario = True
                        self.dup_ack_candidate = ack_segment.ack_number
                        self.dup_ack_count = 1
                        self.print_verbose('reserved for dup_ack in 2 dups')

                    elif self.dup_ack_candidate == ack_segment.ack_number:
                        if self.dup_ack_count == config.DUP_ACK_CNT - 1:
                            self.exec_dup_ack = True
                            self.print_verbose(str(config.DUP_ACK_CNT) + '_dups reached!')
                        else:
                            self.dup_ack_count += 1
                            self.print_verbose('reserved for dup_ack in ' +
                                               str(config.DUP_ACK_CNT - self.dup_ack_count) + ' dups')
                    self.window_iter += 1

    def new_segment(self):
        data_size, data = self.read_a_mss()
        self.file_finished = data_size != config.MSS

        packet = utility.create_payload_packet(self.sender_port, self.receiver_port, 0,
                                               self.window_size, self.next_seq_number, data)
        segment = utility.SegmentParser(packet)
        self.next_seq_number += 1

        self.print_verbose('created data segment #' + str(segment.seq_number))

        return segment

    def establish_connection(self):
        self.send_syn()
        self.wait_for_syn_ack()
        self.send_ack()

    def print_log_message(self, message):
        print('sending host ' + self.sender_port + ': ' + message)

    def print_verbose(self, message):
        self.print_log_message('---> ' + message)

    def read_a_mss(self):
        read_data = self.file.read(config.MSS).decode('Latin-1')
        data_length = len(read_data)

        return data_length, read_data

    def terminate(self):
        self.print_log_message('is terminated.')
        exit(0)

    def send_fin(self):
        self.print_verbose('sending FIN')
        packet = utility.create_fin_packet(self.sender_port, self.receiver_port, 0,
                                           self.window_size, self.next_seq_number)
        self.next_seq_number += 1
        utility.write_pipe(self.data_pipe, packet)
        self.print_verbose('sent FIN')

    def start(self, file_path):
        self.establish_connection()
        self.file = open(file_path, 'rb')
        self.send_file()
        self.file.close()
        self.close_connection()

    def check_single_ack(self):

        time.sleep(0.05)

        self.ack_mutex.acquire()

        ack_data, there_is_ack = self.ack_watcher.read_data()
        self.ack_watcher.go_on()

        self.ack_mutex.release()

        return ack_data, there_is_ack

    def close_connection(self):
        self.send_fin()
        self.wait_for_fin_ack()
        self.wait_for_fin()
        self.send_fin_ack()

        self.time_watcher.shutdown()
        self.ack_watcher.shutdown()

        self.terminate()

    def send_syn(self):
        self.print_verbose('sending SYN')
        packet, self.next_seq_number = utility.create_syn_packet(self.sender_port, self.receiver_port, 0,
                                                                 self.window_size)

        utility.write_pipe(self.data_pipe, packet)
        self.print_verbose('sent SYN')
        self.print_log_message('is running...')

    def wait_for_syn_ack(self):
        self.print_verbose('waiting for SYN/ACK')

        segment_data, _ = self.check_single_ack()

        segment = utility.SegmentParser(segment_data)

        if segment.checksum_valid() and segment.syn_flag is True and segment.ack_flag is True:
            self.print_verbose('received SYN/ACK')
        else:
            self.print_verbose('invalid SYN/ACK. resending SYN')
            self.send_syn()
            self.wait_for_syn_ack()

    def send_ack(self):
        self.print_verbose('sending ACK')
        packet = utility.create_ack_packet(self.sender_port, self.receiver_port, 0, self.window_size,
                                           self.next_seq_number)
        self.next_seq_number += 1
        utility.write_pipe(self.data_pipe, packet)
        self.print_verbose('sent ACK')

    def wait_for_fin_ack(self):
        self.print_verbose('waiting for FIN/ACK')

        segment_data, _ = self.check_single_ack()

        segment = utility.SegmentParser(segment_data)

        if segment.checksum_valid() and segment.ack_flag is True:
            self.print_verbose('received FIN/ACK')
        else:
            self.print_verbose('invalid FIN/ACK. resending FIN')
            self.send_fin()
            self.wait_for_fin_ack()

    def wait_for_fin(self):
        self.print_verbose('waiting for FIN')

        segment_data, _ = self.check_single_ack()

        segment = utility.SegmentParser(segment_data)

        if segment.checksum_valid() and segment.fin_flag is True:
            self.print_verbose('received FIN')
        else:
            self.print_verbose('invalid FIN. resending FIN')
            self.send_fin()
            self.wait_for_fin_ack()
            self.wait_for_fin()

    def send_fin_ack(self):
        self.print_verbose('sending FIN/ACK')
        packet = utility.create_fin_ack_packet(self.sender_port, self.receiver_port, 0, self.window_size,
                                               self.next_seq_number)
        self.next_seq_number += 1
        utility.write_pipe(self.data_pipe, packet)
        self.print_verbose('sent FIN/ACK')

    def check_receiver_existence(self):
        receiver_pipe = Path(utility.get_pipes_folder_path() + 'receiver_' + str(self.receiver_port) + '_data.pipe')

        if not receiver_pipe.exists():
            self.print_log_message('no receiving host ' + str(self.receiver_port) + ' is available.')
            exit(0)
        else:
            pass
