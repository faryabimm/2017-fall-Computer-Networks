import os

from codes import receiver


def main():
    print(os.popen('cd /Users/mohammadmahdi/Development/PycharmProjects/NW_HW2/ && ./renew.sh').read())
    receiver.Receiver('113')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as interrupt:
        print(interrupt.args)
        exit(0)
