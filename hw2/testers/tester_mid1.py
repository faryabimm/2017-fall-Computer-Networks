import random

from codes import utility


def main():
    out_pipe = open(utility.get_pipes_folder_path() + 'receiver_113_data.pipe', 'wb')
    in_pipe = open(utility.get_pipes_folder_path() + 'forwardnet_data.pipe', 'rb')
    time_pipe = open(utility.get_pipes_folder_path() + 'sender_112_time.pipe', 'w')

    while True:
        try:
            size, read_data = utility.read_pipe_blocking(in_pipe)
        except IndexError:
            break

        for _ in range(random.randrange(10)):
            utility.write_tick_pipe(time_pipe)
            print('tick')

        # if random.choice([True, False]):
        utility.write_pipe(out_pipe, read_data)
        print('passed data of size ' + str(size) + ' after a delay of ' + str(_) + ' s')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as interrupt:
        print(interrupt.args)
        exit(0)
