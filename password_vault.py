import os
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64decode
import json
from base64 import b64encode
import os.path
import hashlib
import random
import string
import sys


#encryptFile: String(bytes) X String(bytes) -> JSON object of representing a zipped dictionary of 4 Key-Value Pairs
# encryptFile: The plaintext vault x The encryption key -> The encrypted vault represented as a zipped dictionary of 4 Key-Value Pairs
# The keys for the JSON zipped dictionary will be "nonce", "header", "ciphertext", and "tag"
# the tag here represents the message authentication code or MAC
# Use AES GCM for encryption
# Use the binary of Empty String as the "header" needed for AES GCM
def encryptFile(plaintextData,key):
    """Your code goes"""
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintextData)
    header = b''

    nonce_b64 = b64encode(nonce).decode('utf-8')
    ciphertext_b64 = b64encode(ciphertext).decode('utf-8')
    header_b64 = b64encode(header).decode('utf-8')
    tag_b64 = b64encode(tag).decode('utf-8')

    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [nonce_b64, header_b64, ciphertext_b64, tag_b64]
    encryptionResults = json.dumps(dict(zip(json_k, json_v)))
    return encryptionResults

# decryptFile: Encrypted JSON Object X String(bytes) -> String(bytes)
# decryptFile: Encrypted vault as a JSON object X the symmetric decryption key -> Just the plaintext (not nonce, header, or tag)
def decryptFile(encryptedJson,key):
    jsonObject = json.loads(encryptedJson)
    
    nonceEncoded = jsonObject["nonce"].encode('utf-8')
    ciphertextEncoded = jsonObject["ciphertext"].encode('utf-8')
    tagEncoded = jsonObject["tag"].encode('utf-8')
    nonce = b64decode(nonceEncoded)
    ciphertext = b64decode(ciphertextEncoded)
    tag = b64decode(tagEncoded)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decryptionResults = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
    except ValueError:
        print("Incorrect username or vault file corrupted.")
        sys.exit(0)

    return decryptionResults

#computerMasterKey: String -> String(bytes)
# This function calculates the encryption key from the input password
# Use the scrypt function with the appropriate arguments mentioned in the assignment document
def computerMasterKey(password):
    """Use salt from hw doc + 16 byte key + default arguments to generate key"""
    salt = "<\n<~\x0e\xeetGR\xfe;\xec_\xfc)8"
    keyLenBytes = 16 #Key size should be 16 bytes or 128 bits
    key = scrypt(password, salt, keyLenBytes, N = 2**14, r = 8, p = 1)
    return key

#decryptAndReconstructVault : String x String -> List(Strings)'
# decryptAndReconstructVault: Name of the encrypted vault file X the password -> The decrypt password vault
# each String in the output list essentially has the form: "username:password:domain"
def decryptAndReconstructVault(hashedusername, password):
    key = computerMasterKey(password)
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'

    with open(hashedusername, "r") as file:
        fileread = file.read()
    file.close()
    decryptedresults = decryptFile(fileread, key)
    decodedContent = decryptedresults.decode('utf-8')

    """Check if beginning of decodedContent contains magic String"""
    if(decodedContent[:len(magicString)] == magicString):
        decodedContent = decodedContent[len(magicString):] #If magic string exists, get rid of it
    else:
        print("Password does not match.")
        sys.exit(0) #Magic string did not exist, throw error

    passwordvault = []
    for line in decodedContent.splitlines():
        passwordvault.append(line)
    return passwordvault

# checkVaultExistenceOrCreate: String x String -> String x String x String x List(Strings)
# In all honesty, the function does not explicitly take any arguments
# It gives a user the option to entry its username and password
# It then checks to see whether a password vault exists for the user name (Is there a file with the name SHA256(username)?)
# If it exists, then the decrypted password vault is returned
# Otherwise, a new password vault is created for the user
# The return value of the function is tuple <username, password, password vault file name, the plaintext password vault>
# The plaintext password vault is nothing but a List of strings where each string has the form: "username:password:domain"
def checkVaultExistenceOrCreate():
    passwordvault = []
    while True:
        username = input('enter vault username: ')
        password = input('enter vault password: ')
        if username and password:
            break

    encodedUsername = username.encode('utf-8')
    hashedusername = hashlib.sha256(encodedUsername).hexdigest()
    if (os.path.exists(hashedusername)):
        passwordvault = decryptAndReconstructVault(hashedusername, password)
    else:
        print("Password vault not found, creating a new one") #Need to create new one
        open(hashedusername, "w")

    return username, password, hashedusername, passwordvault

# generatePassword: VOID -> STRING
# When called this function returns a random password
def generatePassword():
    """Generate 16 character random password from A-Z, a-z, 0-9"""
    result = ""
    for i in range(16):
        setNum = random.randint(0,2)
        if(setNum == 0):
            rndChar = chr(ord('A') + random.randint(0, 25))
        elif(setNum == 1):
            rndChar = chr(ord('a') + random.randint(0, 25))
        else:
            rndChar = chr(ord('0') + random.randint(0, 9))
        result += rndChar
    return result


# AddPassword : List(String) -> VOID
# AddPassword : PLAINTEXT Password vault -> VOID
# It gives a user prompt to add a username, password, and a domain
# It then adds the triple to the Password vault
def AddPassword(passwordvault):
    while(True):
        username = input("Enter username: ")
        if ':' in username:
            print("Invalid username. Must not contain ':'. Try Again.")
        else:
            break

    while(True):
        password = input("Enter password: ")
        if ':' in password:
            print("Invalid password. Must not contain ':'. Try Again.")
        else:
            break

    while(True):
        domain = input("Enter domain: ")
        if ':' in domain:
            print("Invalid domain. Must not contain ':'. Try Again.")
        else:
            break
    
    line = username + ':' + password + ':' + domain
    passwordvault.append(line)
    print('Record Entry added')

# CreatePassword : List(String) -> VOID
# CreatePassword : PLAINTEXT Password vault -> VOID
# It gives a user prompt to add a username, and domain
# It randomly generates the password
# It then adds the triple <username:password:domain> to the Password vault
def CreatePassword(passwordvault):
    while(True):
        username = input("Enter username: ")
        if ':' in username:
            print("Invalid username. Try Again. Must not contain ':'")
        else:
            break
    
    while(True):
        domain = input("Enter domain: ")
        if ':' in domain:
            print("Invalid domain. Try Again. Must not contain ':'")
        else:
            break
    
    password = generatePassword()
    line = username + ':' + password + ':' + domain
    passwordvault.append(line)
    print('Record Entry added')


# UpdatePassword: List(String) -> VOID
# UpdatePassword: PLAINTEXT Password vault -> VOID
# It takes as input from the user the name of the domain to change password and the password to update it with.
# It then updates the password vault of the domain with the new password
def UpdatePassword(passwordvault):
    while(True):
        domain = input("Enter domain: ")
        if ':' in domain:
            print("Invalid domain. Must not contain ':'. Try Again.")
        else:
            break

    while(True):
        password = input("Enter new password: ")
        if ':' in password:
            print("Invalid password. Must not contain ':'. Try Again.")
        else:
            break
    
    for i in range(len(passwordvault)):
        firstIdx = passwordvault[i].index(':')
        secondIdx = passwordvault[i][firstIdx + 1:].index(':') + (firstIdx + 1)
        print(passwordvault[i][:firstIdx])
        print(passwordvault[i][firstIdx + 1:secondIdx])
        print(passwordvault[i][secondIdx + 1:])
        if(passwordvault[i][secondIdx + 1:] == domain):
            passwordvault[i] = passwordvault[i][:firstIdx + 1] + password + passwordvault[i][secondIdx:]
            break
    print('Record Entry Updated')

# LookupPassword: List(String) -> VOID
# LookupPassword: PLAINTEXT Password vault -> VOID
# It takes as input from the user the name of the domain
# It then prints the username and password of that domain
def LookupPassword(passwordvault):
    while(True):
        domain = input("Enter domain: ")
        if ':' in domain:
            print("Invalid domain. Must not contain ':'. Try Again.")
        else:
            break
    
    for i in range(len(passwordvault)):
        firstIdx = passwordvault[i].index(':')
        secondIdx = passwordvault[i][firstIdx + 1:].index(':') + (firstIdx + 1)
        if(passwordvault[i][secondIdx + 1:] == domain):
            print("username: " + passwordvault[i][:firstIdx])
            print("password: " + passwordvault[i][firstIdx + 1:secondIdx])
            break


# DeletePassword: List(String) -> VOID
# DeletePassword: PLAINTEXT Password vault -> VOID
# It takes as input from the user the name of the domain
# It then removes the entry of that domain from the password vault
def DeletePassword(passwordvault):
    while(True):
        domain = input("Enter domain: ")
        if ':' in domain:
            print("Invalid domain. Must not contain ':'. Try Again.")
        else:
            break
    
    idx = -1
    for i in range(len(passwordvault)):
        firstIdx = passwordvault[i].index(':')
        secondIdx = passwordvault[i][firstIdx + 1:].index(':') + (firstIdx + 1)
        if(passwordvault[i][secondIdx + 1:] == domain):
            idx = i
            break

    if(idx >= 0):
        passwordvault.remove(passwordvault[idx])
    print('Record Entry Deleted')


# displayVault : List(String) -> VOID
# Given the PLAINTEXT password vault, this function prints it in the standard output
def displayVault(passwordvault):
    print(passwordvault)

# EncryptVaultAndSave: List(String) x String x String -> VOID
# EncryptVaultAndSave: PLAINTEXT PASSWORD VAULT  x PASSWORD x PASSWORD VAULT FILE NAME -> VOID
# This function essentially prepends the magic string in a separate line with the
# PLAINTEXT password vault, then writes it back in the encrypted format to the encrypted password vault file ....
def EncryptVaultAndSave(passwordvault, password, hashedusername):
    writeString = ''
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'
    # writeString + magicString
    key = computerMasterKey(password)
    finalString = ''
    finalString = finalString + magicString

    for i in passwordvault:
        # record = i[0] + '\n'
        record = i + '\n'
        finalString = finalString + record

    finaldbBytes = bytes(finalString, 'utf-8')
    finaldbBytesEncrypted = encryptFile(finaldbBytes, key)

    with open(hashedusername, "w") as file:
        file.write(finaldbBytesEncrypted)
    file.close()
    print("Password Vault encrypted and saved to file")

def main():
    username, password, hashedusername, passwordvault = checkVaultExistenceOrCreate()
    while(True):
        print('Password Management')
        print('-----------------------')
        print('-----------------------')
        print('1 - Add password')
        print('2 - Create password')
        print('3 - Update password')
        print('4 - Lookup password')
        print('5 - Delete password')
        print('6 - Display Vault')
        print('7 - Save Vault and Quit')
        choice = input('')

        if choice == ('1'):
            AddPassword(passwordvault)
        elif choice == ('2'):
            CreatePassword(passwordvault)
        elif choice == ('3'):
            UpdatePassword(passwordvault)
        elif choice == ('4'):
            LookupPassword(passwordvault)
        elif choice == ('5'):
            DeletePassword(passwordvault)
        elif choice == ('6'):
            displayVault(passwordvault)
        elif choice == ('7'):
            EncryptVaultAndSave(passwordvault, password, hashedusername)
            quit()
        else:
            print('Invalid choice please try again')

"""# New Section"""
main()