from codes import sender, utility


def main():
    sender.Sender('112', '113', 30, 20, utility.get_data_folder_path() + 'photo.jpg')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as interrupt:
        print(interrupt.args)
        exit(0)
