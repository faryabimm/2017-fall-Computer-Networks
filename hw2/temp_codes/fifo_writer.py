from codes import utility

write_fifo = open(utility.get_pipes_folder_path() + 'forwardnet_data.pipe', 'w')

for i in range(70):
    write_fifo.write('tick\n')

while True:
    pass
