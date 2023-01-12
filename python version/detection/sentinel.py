from pathlib import Path
from tkinter import ttk
import datetime
import queue
import tkinter as tk
import pygame
import psutil
from prettytable import PrettyTable
import time
import pickle
import pefile
import sys
import array
import joblib
import math
import os




#  WATCHDOG CODE FOR DETECTION
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import (
    EVENT_TYPE_CREATED,
    EVENT_TYPE_DELETED,
    EVENT_TYPE_MODIFIED,
    EVENT_TYPE_MOVED
)

# Create a list of file extensions to watch
ransomware_dictionary = [".encrypt", ".cry", ".crypto", ".darkness", ".enc" , ".exx", ".kb15", ".kraken", ".locked", ".nochance", ".___xratteamLucked", ".__AiraCropEncrypted!",
  "._AiraCropEncrypted", "._read_thi$_file" , ".02", ".0x0", ".725", ".1btc", ".1999", ".1cbu1", ".1txt", ".2ed2", ".31392E30362E32303136_[ID-KEY]_LSBJ1", ".73i87A",
  ".726", ".777", ".7h9r", ".7z.encrypted", ".7zipper", ".8c7f", ".8lock8", ".911", ".a19", ".a5zfn", ".aaa" , ".abc" , ".adk", ".adr", ".adair", ".AES", ".aes128ctr",
  ".AES256" , ".aes_ni", ".aes_ni_gov", ".aes_ni_0day" , ".AESIR", ".AFD", ".aga", ".alcatraz", ".Aleta", ".amba", ".amnesia", ".angelamerkel", ".AngleWare", ".antihacker2017",
  ".animus", ".ap19", ".atlas", ".aurora", ".axx", ".B6E1", ".BarRax", ".barracuda", ".bart", ".bart.zip", ".better_call_saul", ".bip", ".birbb", ".bitstak", ".bitkangoroo", 
  ".boom", ".black007", ".bleep", ".bleepYourFiles" , ".bloc", ".blocatto", ".block", ".braincrypt", ".breaking_bad", ".bript", ".brrr", ".btc", ".btcbtcbtc", ".btc-help-you", 
  ".cancer", ".canihelpyou", ".cbf", ".ccc", ".CCCRRRPPP", ".cerber", ".cerber2", ".cerber3", ".checkdiskenced", ".chifrator@qq_com", ".CHIP" , ".cifgksaffsfyghd", ".clf",
  ".clop", ".cnc", ".cobain", ".code", ".coded", ".comrade", ".coverton", ".crashed", ".crime", ".crinf", ".criptiko" , ".crypton", ".criptokod" , ".cripttt" , ".crjoker", 
  ".crptrgr", ".CRRRT" , ".cry", ".cry_", ".cryp1" , ".crypt", ".crypt38", ".crypted", ".cryptes", ".crypted_file", ".crypto", ".cryptolocker", ".CRYPTOSHIEL", ".CRYPTOSHIELD", 
  ".CryptoTorLocker2015!", ".cryptowall", ".cryptowin", ".crypz", ".CrySiS", ".css", ".ctb2", ".ctbl", ".CTBL", ".czvxce", ".d4nk", ".da_vinci_code", ".dale", ".damage",
  ".darkness" , ".darkcry", ".dCrypt", ".decrypt2017", ".ded", ".deria", ".desu", ".dharma", ".disappeared", ".diablo6", ".divine", ".dll", ".doubleoffset", ".domino", 
  ".doomed", ".dxxd", ".dyatel@qq_com", ".ecc", ".edgel", ".enc", ".encedRSA", ".EnCiPhErEd", ".encmywork", ".encoderpass", ".ENCR", ".encrypted", ".EnCrYpTeD", ".encryptedAES", 
  ".encryptedRSA", ".encryptedyourfiles", ".enigma", ".epic", ".evillock", ".exotic", ".exte", ".exx", ".ezz", ".fantom", ".fear", ".FenixIloveyou!!", ".file0locked", 
  ".filegofprencrp", ".fileiscryptedhard", ".filock", ".firecrypt", ".flyper", ".frtrss", ".fs0ciety", ".fuck", ".Fuck_You", ".fucked", ".FuckYourData" , ".fun", 
  ".flamingo", ".gamma", ".gefickt", ".gembok", ".globe", ".glutton", ".goforhelp", ".good", ".gruzin@qq_com" , ".gryphon", ".grinch", ".GSupport" , ".GWS", ".HA3", 
  ".hairullah@inbox.lv", ".hakunamatata", ".hannah", ".haters", ".happyday" ," .happydayzz", ".happydayzzz", ".hb15", ".helpdecrypt@ukr .net", ".helpmeencedfiles", 
  ".herbst", ".hendrix", ".hermes", ".help", ".hnumkhotep", ".hitler", ".howcanihelpusir", ".html", ".homer", ".hush", ".hydracrypt" , ".iaufkakfhsaraf", ".ifuckedyou", 
  ".iloveworld", ".infected", ".info", ".invaded", ".isis" , ".ipYgh", ".iwanthelpuuu", ".jaff", ".java", ".JUST", ".justbtcwillhelpyou", ".JLQUF", ".jnec", ".karma", 
  ".kb15", ".kencf", ".keepcalm", ".kernel_complete", ".kernel_pid", ".kernel_time", ".keybtc@inbox_com", ".KEYH0LES", ".KEYZ" , "keemail.me", ".killedXXX", ".kirked", 
  ".kimcilware", ".KKK" , ".kk", ".korrektor", ".kostya", ".kr3", ".krab", ".kraken", ".kratos", ".kyra", ".L0CKED", ".L0cked", ".lambda_l0cked", ".LeChiffre", ".legion",
  ".lesli", ".letmetrydecfiles", ".letmetrydecfiles", ".like", ".lock", ".lock93", ".locked", ".Locked-by-Mafia", ".locked-mafiaware", ".locklock", ".locky", ".LOL!", ".loprt", 
  ".lovewindows", ".lukitus", ".madebyadam", ".magic", ".maktub", ".malki", ".maya", ".merry", ".micro", ".MRCR1", ".muuq", ".MTXLOCK", ".nalog@qq_com", ".nemo-hacks.at.sigaint.org", 
  ".nobad", ".no_more_ransom", ".nochance" , ".nolvalid", ".noproblemwedecfiles", ".notfoundrans", ".NotStonks", ".nuclear55", "nuclear", ".obleep", ".odcodc", ".odin", ".oled",
  ".OMG!", ".only-we_can-help_you", ".onion.to._", ".oops", ".openforyou@india.com", ".oplata@qq.com" , ".oshit", ".osiris", ".otherinformation", ".oxr", ".p5tkjw", ".pablukcrypt", 
  ".padcrypt", ".paybtcs", ".paym", ".paymrss", ".payms", ".paymst", ".payransom", ".payrms", ".payrmts", ".pays", ".paytounlock", ".pdcr", ".PEGS1", ".perl", ".pizda@qq_com", 
  ".PoAr2w", ".porno", ".potato", ".powerfulldecrypt", ".powned"," .pr0tect", ".purge", ".pzdc", ".R.i.P", ".r16m" , ".R16M01D05", ".r3store", ".R4A" , ".R5A", ".r5a", ".RAD" , 
  ".RADAMANT", ".raid10",".ransomware", ".RARE1", ".rastakhiz", ".razy", ".RDM", ".rdmk", ".realfs0ciety@sigaint.org.fs0ciety", ".recry1", ".rekt", ".relock@qq_com", ".reyptson", 
  ".remind", ".rip", ".RMCM1", ".rmd", ".rnsmwr", ".rokku", ".rrk", ".RSNSlocked" , ".RSplited", ".sage", ".salsa222", ".sanction", ".scl", ".SecureCrypted", ".serpent", ".sexy", 
  ".shino", ".shit", ".sifreli", ".Silent", ".sport", ".stn", ".supercrypt", ".surprise", ".szf", ".t5019", ".tedcrypt", ".TheTrumpLockerf", ".thda", ".TheTrumpLockerfp", 
  ".theworldisyours", ".thor", ".toxcrypt", ".troyancoder@qq_com", ".trun", ".trmt", ".ttt", ".tzu", ".uk-dealer@sigaint.org", ".unavailable", ".vault", ".vbransom", ".vekanhelpu", 
  ".velikasrbija", ".venusf", ".Venusp", ".versiegelt", ".VforVendetta", ".vindows", ".viki", ".visioncrypt", ".vvv", ".vxLock", ".wallet", ".wcry", ".weareyourfriends", ".weencedufiles", 
  ".wflx", ".wlu", ".Where_my_files.txt", ".Whereisyourfiles", ".windows10", ".wnx", ".WNCRY", ".wncryt", ".wnry", ".wowreadfordecryp", ".wowwhereismyfiles", ".wuciwug", ".www", ".xiaoba", 
  ".xcri", ".xdata", ".xort", ".xrnt", ".xrtn", ".xtbl", ".xyz", ".ya.ru", ".yourransom", ".Z81928819", ".zc3791", ".zcrypt", ".zendr4", ".zepto", ".zorro", ".zXz", ".zyklon", ".zzz" , 
  ".zzzzz"]

class MyEventHandler(FileSystemEventHandler):

    def __init__(self, q):
        # Save a reference to the queue so it can be accessed
        # by on_any_event().
        self._q = q
        super().__init__()
            
    def on_any_event(self, event):
        # Figure out the name of the event.
        action = {
            EVENT_TYPE_CREATED: "Created",
            EVENT_TYPE_DELETED: "Deleted",
            EVENT_TYPE_MODIFIED: "Modified",
            EVENT_TYPE_MOVED: "Moved",
        }[event.event_type]
         
        # If it is a movement, append the destination path.
        if event.event_type == EVENT_TYPE_MOVED:
            action += f" ({event.dest_path})"
        
        # Checks for the specified file extensions above
        if not event.is_directory and event.src_path.endswith(str(ransomware_dictionary)):
            print(f"Suspicious file detected: {event.src_path}")
        if event.event_type == EVENT_TYPE_MODIFIED:
            pygame.mixer.init()
            pygame.mixer.music.load('C:\\Users\\trust\\Desktop\\competition\\python version\\detection\\alarm.mp3')
            pygame.mixer.music.play()
            
        # Get information about all processes
        process_list = []
        for process in psutil.process_iter():
            try:
                process_list.append({
                    'pid': process.pid,
                    'name': process.name(),
                    'cpu_percent': process.cpu_percent(),
                    'memory_percent': process.memory_percent(),
                    'status': process.status(),
                    'threads':process.num_threads(),
                    'subprocesses': [],
                })
            except psutil.Error:
                # psutil.Error is thrown for processes that have terminated or cannot be accessed
                pass

        # Check for suspicious processes
        suspicious_processes = []
        for process_info in process_list:
            if (process_info['cpu_percent'] > 5 and process_info['name'] not in ["System Idle Process", "System"]):
                suspicious_processes.append(process_info)

        # Print information about suspicious processes
        for process_info in suspicious_processes:
            # Create a PrettyTable object
            table = PrettyTable()

            # Set the table headers
            table.field_names = ['PID', 'NAME', 'CPU Usage', 'MEMORY PERCENT', 'STATUS', 'THREADS']

            # Loop through the list of suspicious processes and add each one to the table
            for process in suspicious_processes:
                table.add_row([
                            process['pid'],
                            process['name'], 
                            format(process['cpu_percent'], '.2f')+'%',
                            format(process['memory_percent'], '.2f')+'%',
                            process['status'],
                            process['threads']
                            ])

            # Print the table
            print(table)
            #print(f"SUSPICIOUS PROCESS: PID: {process_info['pid']} | Name: {process_info['name']}")
            #print(f"Command line: {' '.join(process_info['cmdline'])}")
            #print(f"CPU usage: {process_info['cpu_percent']}% | Memory usage: {process_info['memory_percent']}%")
            
        
        # Put the event information in the queue to be processed
        # by loop_observer() in the main thread.
        # (It is not convenient to modify a Tk widget from a
        # secondary thread.)
        self._q.put((
            # Name of the modified file.
            Path(event.src_path).name,
            # Action executed on that file.
            action,
            # The current time.
            datetime.datetime.now().strftime("%H:%M:%S")
        ))


def process_events(observer, q, modtree):
    # Make sure the observer is still running.
    if not observer.is_alive():
        return
    try:
        # Try to get an event from the queue.
        new_item = q.get_nowait()
    except queue.Empty:
        # If there is no event, just continue.
        pass
    else:
        # If an event was retrieved from the queue, append insert it
        # into the treeview.
        modtree.insert("", 0, text=new_item[0], values=new_item[1:])
    # Check again in half a second (500 ms).
    root.after(2000, process_events, observer, q, modtree)
    


#### ML CODE FOR DETECTION
def get_entropy(data):
    """Get entropy of file"""
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy


def get_resources(pe):
    """Extract resources: [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception:
            return resources
    return resources


def get_version_info(pe):
    """Return version information"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


def extract_infos(fpath):
    """Extract information about file"""
    res = {}
    pe = pefile.PE(fpath)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # Sections
    res['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x: x.get_entropy(), pe.sections))
    res['SectionsMeanEntropy'] = sum(entropy) / float(len(entropy))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
    res['SectionsMeanRawsize'] = sum(raw_sizes) / float(len(raw_sizes))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
    res['SectionsMeanVirtualsize'] = sum(
        virtual_sizes) / float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    # Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = len(
            list(filter(lambda x: x.name is None, imports)))
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    # Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        res['ExportNb'] = 0
    # Resources
    resources = get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        entropy = list(map(lambda x: x[0], resources))
        res['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x: x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    # Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
  
    except pefile.PEFormatError:
        # The file is not a valid PE file, so extract whatever features are available
        # Example: Extract the file size as a feature
        res['size'] = os.path.getsize(fpath) 
        
    return res
        
        
def flag_as_malware(pth):
    # Warn the user that malware has been found
    print("WARNING: Malware detected at {}".format(pth))
    
    # Add the file to the system's list of known malware
    with open('database/malware_database.txt', 'a') as f:
        f.write(f"{pth}\n")
    
    # Prompt the user for confirmation before deleting the file
    user_input = input("Do you want to delete this file? [y/n]")
    if user_input.lower() == 'y':
        # Delete the file
        os.remove(file_path)
        print("File deleted.")
    else:
        print("File not deleted.")


directory = 'E://'

# Load classifier and features
clf = joblib.load('classifier/svm_classifier.pkl')
features = pickle.loads(open('classifier/svm_features.pkl', 'rb').read())


malware_found = False

file_paths = []
# Iterate over all root directories in the drive
for root, directories, files in os.walk(directory):
  # Iterate over all files in the current root directory
  for file in files:
    # Get the full file path by joining the root and file name
    file_path = os.path.join(root, file)
    # Add the file path to the list
    file_paths.append(file_path)

# Join the file paths into a single string separated by newlines
file_string = '\n'.join(file_paths)

# Save the file string to a text file
with open('database/file_list.txt', 'w') as f:
    f.write(file_string)
    
# Load file string from text file
with open('database/file_list.txt', 'r') as f:
    file_string = f.read()

# Split file string into a list of file paths
file_paths = file_string.split('\n')

for pth in file_paths:
    try:
        data = extract_infos(pth)

        pe_features = list(map(lambda x: data[x], features))

        res = clf.predict([pe_features])[0]
        
        print('\nThe file %s is %s' % (os.path.basename(pth), ['malicious', 'legitimate'][res]))
        if res < len(['malicious']):
            if ['malicious'][res]:
                flag_as_malware(pth)
                malware_found = True
                    
    except pefile.PEFormatError:
        continue
  



root = tk.Tk()
root.config(width=600, height=500)
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
root.title("Real Time Event Logging")

modtree = ttk.Treeview(columns=("action", "time",))
modtree.heading("#0", text="File")
modtree.heading("action", text="Action")
modtree.heading("time", text="Time")
modtree.grid(column=0, row=0, sticky="nsew")

# Watchdog event observer.
observer = Observer()
# This queue acts as a communication channel between the observer and the Tk application.
q = queue.Queue()
# Monitor all events on local drive C: OR E: (on Windows).
observer.schedule(MyEventHandler(q), directory, recursive=True)
#observer.schedule(MyEventHandler(q), ".", recursive=False)
observer.start()
# Schedule the function that processes the observer events.
root.after(1, process_events, observer, q, modtree)
root.mainloop()
observer.stop()
observer.join()