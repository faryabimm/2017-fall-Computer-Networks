from codes import utility


def main():
    in_pipe = open(utility.get_pipes_folder_path() + 'backwardnet_data.pipe', 'rb')
    out_pipe = open(utility.get_pipes_folder_path() + 'sender_112_data.pipe', 'wb')

    while True:
        try:
            _, read_data = utility.read_pipe_blocking(in_pipe)
        except IndexError:
            break
        # if random.choice([True, False]):
        utility.write_pipe(out_pipe, read_data)
        print('passed data of size ' + str(_))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as interrupt:
        print(interrupt.args)
        exit(0)
