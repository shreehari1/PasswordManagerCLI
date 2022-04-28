#!/usr/bin/python3

import ossaudiodev
import sys
import clipboard
import json
from emoji import emojize
from asyncore import read,write
from getpass import getpass
from os.path import exists
from hashlib import sha256
from base64 import b64encode, b64decode

class CredManager:

    DATA_FILE = "data"
    MASTER_PASSWORD = "masterPassword"
    secrets = ""
    pwd = ""
    data = ""

    def __init__(self):
        if exists(CredManager.DATA_FILE) == True:
            CredManager.data = self.decodeData()
            self.parseData()
        else:
            self.initialSetup()
       
    def initialSetup(self):
        CredManager.data ={"secrets": {}, "passwords": {}}
        self.parseData()
        self.generateSecrets()
        self.addingPasswords()
        exit()

    def parseData(self):        
        CredManager.secrets = CredManager.data["secrets"]
        CredManager.pwd = CredManager.data["passwords"]

    def generateSecrets(self):
        while(1):
            masterPassword = getpass(emojize(":key: Enter [MASTER password]: "))
            repeat = getpass(emojize(":key: Confirm [MASTER password]: "))
            if masterPassword == repeat:
                secretKeyHash = self.getHashPassword(masterPassword)
                self.updateSecrets(CredManager.MASTER_PASSWORD,secretKeyHash)
                print(emojize(":locked_with_key: [Master password] setup complete"))
                break
            else:
                print(emojize(":cross_mark: Password mismatch try again!"))
            

    def verifyCredentials(self):
        passwd = getpass(emojize(":key: [MASTER password]: "))
        if self.getHashPassword(passwd) == CredManager.secrets[CredManager.MASTER_PASSWORD]:
            return True
        else:
            print(emojize(":cross_mark:  Password incorrect try again!"))
            return False

    def getHashPassword(self,masterPassword):
        return sha256(masterPassword.encode()).hexdigest()

    def updateSecrets(self,secretKey,secretValue):
        CredManager.secrets[secretKey] = secretValue

    def updatePassword(self,app,password):
        CredManager.pwd[app]=password
        print(emojize(":check_box_with_check:  Password is set for "+ app))

    def addPassword(self,app):
        if app not in CredManager.pwd:
            password = getpass("Enter the password for "+app+" : ")
            self.updatePassword(app,password)
        else:
            print(emojize(":warning:  Password already exists for this Application!"))

    def addingPasswords(self,app=None):
        if app:
            self.addPassword(app)
        else:
            while("Y" == input("Press 'Y' to add Application:").upper()):
                app = input("Enter the Application name: ")
                self.addPassword(app)

    def editPassword(self,app):
        if app in CredManager.pwd:
            password = getpass("Enter the password for "+app+" : ")
            self.updatePassword(app,password)
        else:
            print(emojize(":warning:  Password entry of this Application doesn't exist!"))


    def editingPasswords(self,app=None):
        if app:
            self.editPassword(app)
        else:
            while("Y" == input("Press 'Y' to edit Application password:").upper()):
                app = input("Enter the Application name: ")
                self.editPassword(app)

    def deletePassword(self,app):
        if app in CredManager.pwd:
            del CredManager.pwd[app]
        else:
            print(emojize(":warning:  Password entry of this Application doesn't exist!"))

    def deletingPasswords(self,app=None):
        if app:
            self.deletePassword(app)
        else:
            while("Y" == input("Press 'Y' to delete Application entry:").upper()):
                app = input("Enter the Application name: ")
                self.deletePassword(app)

    def listApps(self):
        pwdList= list(CredManager.pwd.keys())
        if len(pwdList) == 0:
            print(emojize(":warning:  No entries found!"))
        else: 
            print(emojize(":locked: Application list:"))
            for i in range(len(pwdList)):
                print(emojize("   :old_key: "),pwdList[i])

    def arguments(self,option,app=None):
        if option == "-h":
            self.getOptions()
        elif option == "-v":
            print(emojize(":gear:  Version 0.1.0"))
        elif self.verifyCredentials():
            if option == "-e":
                self.editingPasswords(app)
            elif option == "-d":
                self.deletingPasswords(app)
            elif option == "-a":
                self.addingPasswords(app)
            elif option == "-l":
                self.listApps()
            elif option == "-M":
                self.generateSecrets()
            else:
                self.getPassword(option)
            

    def getPassword(self,app):
        if app in CredManager.pwd:
            clipboard.copy(CredManager.pwd[app])
            print(emojize(":check_mark_button: "+app+" password copied!"))
        else:
            print(emojize(":warning:  Incorrect arguements"))
            print(emojize(":blue_book: Use [-h] argument for usage information"))

    def getOptions(self):
        print(emojize("Credential manager CLI :locked_with_key:"))
        print(emojize("Usage:hammer_and_wrench: :"))
        print("credManagerCLI [AppName] \t\t Copy password of Application")
        print("credManagerCLI [arguments] [AppName] \t With arguements modify Application specific entry")
        print("credManagerCLI [arguments] \t\t With arguements modify multiple Application entries")
        print()
        print(emojize("Arguements:wrench::"))
        print("  -M \t\t Change [Master Password]")
        print("  -v \t\t Application version")
        print("  -l \t\t List all Application entries")
        print("  -a \t\t Add multiple Application entries")
        print("  -e \t\t Edit multiple Application entries")
        print("  -d \t\t Delete multiple Application entries")
        print()
        print("  -a  [AppName]  Add specific Application entry")
        print("  -e  [AppName]  Edit specific Application entry")
        print("  -d  [AppName]  Delete specific Application entry")
        print()
        print("Use simple and short Application names for ease of use")
        print("Use [-l] arguement to view all the Application entries")

    def decodeData(self):
        f= open(CredManager.DATA_FILE,"rb")
        s = f.read()
        f.close()
        dec = b64decode(s).decode("utf-8")
        data = json.loads(dec)
        return data

    def encodeData(self):
        enc = b64encode(json.dumps(CredManager.data).encode("utf-8"))
        f = open(CredManager.DATA_FILE,"wb")
        f.write(enc)
        f.close()

    # def printDecodedData(self):
    #     print("Data : "+ str(CredManager.data))
    #     print("Secrets : "+ str(CredManager.secrets))
    #     print("Passwords : "+ str(CredManager.pwd))
    
    def __del__(self):
        self.encodeData()


cred = CredManager()

if len(sys.argv) == 2:
    cred.arguments(str(sys.argv[1]))
elif len(sys.argv) == 3:
    cred.arguments(str(sys.argv[1]),sys.argv[2])
else:
    print(emojize(":cross_mark: Missing/Incorrect arguements"))
    print(emojize(":blue_book: Use [-h] argument for usage information"))

# cred.printDecodedData()
del cred
