# ANTI-RANSOMWARE 

**Ransomware** is a type of `cryptovirology` that threatens to publish the victims personal data or permanently block access unless a ransome is *paid*.

**Cryptovirology** refers to the use of cryptography to devise particularly powerful malware, such as `ransomware` and `asymmetric backdoors`.

**Cryptography** and it's applications are *defensive* in nature and provide privacy, authentication and security to users. Cryptovirology employs a twist on cryptography showing that it can be used *offensively*.

In a properly implemented cryptoviral extortion attack, recorvering the files without the decryption key is an intractable problem and difficult to trace digital currencies such as `PaysafeCard` or `Bitcoin` and other cryptocurrencies are used for the ransoms, making tracing and prosecuting the perpetrators difficult.

`Ransomware` attacks are typically carried out using a **Trojan** disguised as a legitimate file that the user is tricked into downloading or opening when it arrives as an *email attachment*, or *embedded link in a phishing email*.


## THE PROCESSES INVOLVED

- Infecction: Attackers deliver the malware Payload to the target.

- Security Key Exchange: Attackers are notified they have the victim.

- Encryption: Ransomware encrypts the victim's file.

- Extortion: Attacker sends the ransome note and payment request.

- Recorvery/Restore: Payment is sent in exchange for the decryption key.


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
> Note: We know that there are libraries that uses the AES encryption with just a few function calls, but we are doing this manually.



# REFERENCES
- https://pythonassets.com/posts/detecting-changes-in-the-file-system-in-real-time-with-watchdog/

