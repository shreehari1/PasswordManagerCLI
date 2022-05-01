#!/usr/bin/python3

import binascii,os
import sys
import clipboard
import json
from emoji import emojize
from asyncore import read,write
from getpass import getpass
from os.path import exists
from hashlib import sha256
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from pbkdf2 import PBKDF2

class PasswordManager:

    DATA_FILE = "data"
    SECRET_KEY_VAR = "secretKey"
    SECRET_SALT_VAR = "secretSalt"
    MASTER_PASSWORD = ""
    secrets = ""
    pwd = ""
    data = ""

    def __init__(self):
        if exists(PasswordManager.DATA_FILE) == True:
            PasswordManager.data = self.decodeData()
            self.parseData()
        else:
            self.initialSetup()
       
    def initialSetup(self):
        PasswordManager.data ={"secrets": {}, "passwords": {}}
        self.parseData()
        self.generateSecrets()
        self.addApps()
        exit()

    def parseData(self):        
        PasswordManager.secrets = PasswordManager.data["secrets"]
        PasswordManager.pwd = PasswordManager.data["passwords"]

    def generateSecrets(self):
        while(1):
            newSecretKey = getpass(emojize(":key: Enter [MASTER password]: "))
            repeatNewSecretKey = getpass(emojize(":key: Confirm [MASTER password]: "))
            if newSecretKey == repeatNewSecretKey:
                newSecretSalt = os.urandom(16)
                PasswordManager.MASTER_PASSWORD = newSecretKey
                pwdList= list(PasswordManager.pwd.keys())
                if len(pwdList) != 0:
                    # call method re-encrpt all the stored passwords with new password
                    self.reEncryptAll(newSecretKey,newSecretSalt)                
                secretKeyHash = self.getHashPassword(newSecretKey)
                self.updateSecrets(PasswordManager.SECRET_KEY_VAR,secretKeyHash)
                self.updateSecrets(PasswordManager.SECRET_SALT_VAR,str(binascii.hexlify(newSecretSalt),"ascii"))
                print(emojize(":locked_with_key: [Master password] setup complete"))
                break
            else:
                print(emojize(":cross_mark: Password mismatch try again!"))
            

    def verifyCredentials(self):
        PasswordManager.MASTER_PASSWORD = getpass(emojize(":key: [MASTER password]: "))
        if self.getHashPassword(PasswordManager.MASTER_PASSWORD) == PasswordManager.secrets[PasswordManager.SECRET_KEY_VAR]:
            return True
        else:
            print(emojize(":cross_mark:  Password incorrect try again!"))
            return False

    def getHashPassword(self,masterPassword):
        return sha256(masterPassword.encode()).hexdigest()

    def updateSecrets(self,secretKey,secretValue):
        PasswordManager.secrets[secretKey] = secretValue

    def updatePassword(self,app,password):
        PasswordManager.pwd[app]=password
        print(emojize(":check_box_with_check:  Password set for "+ app))

    def addPassword(self,app):
        if app not in PasswordManager.pwd:
            password = getpass("Enter the password for "+app+" : ")
            encryptedPassword=self.encrypt(password)
            self.updatePassword(app,encryptedPassword)
        else:
            print(emojize(":warning:  Password already exists for this Application!"))

    def addApps(self,app=None):
        if app:
            self.addPassword(app)
        else:
            while("Y" == input("Press 'Y' to add Application:").upper()):
                app = input("Enter the Application name: ")
                self.addPassword(app)

    def editPassword(self,app):
        if app in PasswordManager.pwd:
            password = getpass("Enter the password for "+app+" : ")
            encryptedPassword=self.encrypt(password)
            self.updatePassword(app,encryptedPassword)
        else:
            print(emojize(":warning:  Password entry of this Application doesn't exist!"))


    def editApps(self,app=None):
        if app:
            self.editPassword(app)
        else:
            while("Y" == input("Press 'Y' to edit Application password:").upper()):
                app = input("Enter the Application name: ")
                self.editPassword(app)

    def deletePassword(self,app):
        if app in PasswordManager.pwd:
            del PasswordManager.pwd[app]
        else:
            print(emojize(":warning:  Password entry of this Application doesn't exist!"))

    def deleteApps(self,app=None):
        if app:
            self.deletePassword(app)
        else:
            while("Y" == input("Press 'Y' to delete Application entry:").upper()):
                app = input("Enter the Application name: ")
                self.deletePassword(app)

    def listApps(self):
        pwdList= list(PasswordManager.pwd.keys())
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
            print(emojize(":gear:  Version 1.0.0"))
        elif self.verifyCredentials():
            if option == "-e":
                self.editApps(app)
            elif option == "-d":
                self.deleteApps(app)
            elif option == "-a":
                self.addApps(app)
            elif option == "-l":
                self.listApps()
            elif option == "-M":
                self.generateSecrets()
            else:
                self.getPassword(option)
            

    def getPassword(self,app):
        if app in PasswordManager.pwd:
            clipboard.copy(self.decrypt(app))
            print(emojize(":check_mark_button: "+app+" password copied!"))
        else:
            print(emojize(":warning:  Incorrect arguements"))
            print(emojize(":blue_book: Use [-h] argument for usage information"))

    def getOptions(self):
        print(emojize("Password Manager CLI :locked_with_key:"))
        print(emojize("Usage:hammer_and_wrench: :"))
        print("pmcli [AppName] \t\t Copy password of Application")
        print("pmcli [arguments] [AppName] \t With arguements modify Application specific entry")
        print("pmcli [arguments] \t\t With arguements modify multiple Application entries")
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
        print()

    def reEncryptAll(self,newSecretKey,newSecretSalt):
        for app in PasswordManager.pwd.keys():
            password = self.decrypt(app)
            encryptedPassword =self.encryptWithNewSecrets(password,newSecretKey,newSecretSalt)
            self.updatePassword(app,encryptedPassword)

    def encryptWithNewSecrets(self,passwordToEncrypt,newSecretKey,newSecretSalt):
        secretKey = PBKDF2(newSecretKey,newSecretSalt).read(32)
        encryptedPassword = self.encrypt_AES_GCM(passwordToEncrypt,secretKey)
        return encryptedPassword

    def encrypt(self,passwordToEncrypt):
        secretKey = PBKDF2(PasswordManager.MASTER_PASSWORD, binascii.unhexlify(bytes(PasswordManager.secrets[PasswordManager.SECRET_SALT_VAR],"ascii"))).read(32)
        encryptedPassword = self.encrypt_AES_GCM(passwordToEncrypt,secretKey)
        return encryptedPassword


    def decrypt(self,app):
        secretKey = PBKDF2(PasswordManager.MASTER_PASSWORD, binascii.unhexlify(bytes(PasswordManager.secrets[PasswordManager.SECRET_SALT_VAR],"ascii"))).read(32)
        encryptedPassword=PasswordManager.pwd[app]
        password = self.decrypt_AES_GCM(encryptedPassword,secretKey)
        return password


    def encrypt_AES_GCM(self,password, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(bytes(password,"utf-8"))
        return (str(binascii.hexlify(ciphertext),"ascii"), str(binascii.hexlify(aesCipher.nonce),"ascii"), str(binascii.hexlify(authTag),"ascii"))

    def decrypt_AES_GCM(self,encryptedPassword, secretKey):
        (ciphertext, nonce, authTag) = encryptedPassword
        aesCipher = AES.new(secretKey, AES.MODE_GCM, binascii.unhexlify(bytes(nonce,"ascii")))
        password = aesCipher.decrypt_and_verify(binascii.unhexlify(bytes(ciphertext,"ascii")), binascii.unhexlify(bytes(authTag,"ascii")))
        return password.decode("utf-8")

    def decodeData(self):
        f= open(PasswordManager.DATA_FILE,"rb")
        s = f.read()
        f.close()
        dec = b64decode(s).decode("utf-8")
        data = json.loads(dec)
        return data

    def encodeData(self):
        enc = b64encode(json.dumps(PasswordManager.data).encode("utf-8"))
        f = open(PasswordManager.DATA_FILE,"wb")
        f.write(enc)
        f.close()
    
    def __del__(self):
        self.encodeData()


cred = PasswordManager()

if len(sys.argv) == 2:
    cred.arguments(str(sys.argv[1]))
elif len(sys.argv) == 3:
    cred.arguments(str(sys.argv[1]),sys.argv[2])
else:
    print(emojize(":cross_mark: Missing/Incorrect arguements"))
    print(emojize(":blue_book: Use [-h] argument for usage information"))

del cred
