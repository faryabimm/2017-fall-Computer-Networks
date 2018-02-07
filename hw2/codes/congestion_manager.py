from math import inf

from codes import config


class CongestionManager:
    def __init__(self, initial_rtt, max_window):
        self.rtt = initial_rtt
        self.window_size = 1
        self.max_window = max_window
        self.ss_threshold = inf

    def update_rtt(self, sample_rtt):
        self.rtt = (1 - config.ALPHA) * self.rtt + config.ALPHA * sample_rtt

    def timeout_interval(self):
        return 2 * self.rtt
