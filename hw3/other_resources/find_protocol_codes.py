command = open('command_output.txt', 'r')
wireshark = open('wireshark_output_greped.txt', 'r')

result = ''

codes = {}

for _ in range(3477):
    command_elements = command.readline().split()
    wireshark_elements = wireshark.readline().split()
    wireshark.readline()

    if len(command_elements) == 3:
        codes[wireshark_elements[2]] = command_elements[2]
    else:
        codes[wireshark_elements[2]] = 'FAIL'

command.close()
wireshark.close()

for key in codes:
    result += key + '\t' + codes[key] + '\n'


result_file = open('code_maps.txt', 'w')
result_file.write(result)
result_file.close()




