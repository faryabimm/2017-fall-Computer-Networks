from codes import utility
import os

pipes_folder_path = utility.get_pipes_folder_path()
read_fifo = open(utility.get_pipes_folder_path() + 'forwardnet_data.pipe', 'rb')

for i in range(80):
    data = read_fifo.readall()

    print(data)

