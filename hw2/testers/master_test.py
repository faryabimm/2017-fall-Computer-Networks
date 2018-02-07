import subprocess
import time

from codes import utility

renew_command = 'cd ' + utility.get_home_folder_path() + '  && ./renew.sh'

renew_process = subprocess.Popen(renew_command, shell=True, stdout=subprocess.PIPE)
renew_process.wait()

print('renew process exited with return code ' + str(renew_process.returncode))

receiver_command = 'cd ' + utility.get_codes_folder_path() + '  && ./receive 9464'
receiver_process = subprocess.Popen(receiver_command, shell=True, stdout=subprocess.PIPE)

time.sleep(0.1)

sender_command = 'cd ' + utility.get_codes_folder_path() + \
                 '  && ./sender 8800 9464 10 50 "' + utility.get_data_folder_path() + 'photo.jpg"'
sender_process = subprocess.Popen(sender_command, shell=True, stdout=subprocess.PIPE)

time.sleep(0.1)

pipe_forward_command = 'cd ' + utility.get_codes_folder_path() + \
                       '  && ./pipe forwardnet_data.pipe receiver_9464_data.pipe sender_8800_time.pipe'
pipe_forward_process = subprocess.Popen(pipe_forward_command, shell=True, stdout=subprocess.PIPE)

time.sleep(0.1)

pipe_backward_command = 'cd ' + utility.get_codes_folder_path() + \
                       '  && ./pipe backwardnet_data.pipe sender_8800_data.pipe'
pipe_backward_process = subprocess.Popen(pipe_backward_command, shell=True, stdout=subprocess.PIPE)


receiver_process.wait()
sender_process.wait()
pipe_forward_process.wait()
pipe_backward_process.wait()


print('receive process exited with return code ' + str(receiver_process.returncode))
print('send process exited with return code ' + str(sender_process.returncode))
print('pipe_forward process exited with return code ' + str(pipe_forward_process.returncode))
print('pipe_backward process exited with return code ' + str(pipe_backward_process.returncode))

