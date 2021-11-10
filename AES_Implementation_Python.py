#Dependencies
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

#Allows for quick encoding of UTF-8 to bytes, used to prepare strings for encryption
def encode(data):
    data = data.encode("utf-8")
    return data

#Allows for quick decoding of bytes to UTF-8, used to print data without the 'b' in the front.
def decode(data):
    data = data.decode("utf-8")
    return data

#Generates Salt, can be modified if needed. 
#The generated salt needs to be stored somewhere accessible (e.g. database), as it's used to generate the key.
def generateSalt(bytes):
    salt = secrets.token_bytes(int(bytes))
    return salt

#Generates a random data key used to encrypt user data.
#Only the data key will need to be re-encrypted, instead of all the user data in case the password needs to be changed. Saves processing power.
def generateDataKey():
    userKey = Fernet.generate_key()
    return userKey

#Generates a user key based on a user password and a salt value.
def generateUserKey(password, salt):
    try:
        keyGen = PBKDF2HMAC(
        algorithm=hashes.SHA512_256(),
        length=32,
        salt = salt,
        iterations=999999,
        )
        key = base64.urlsafe_b64encode(keyGen.derive(password.encode("utf-8")))
        return key
    except:
        print("Error: Couldn't generate key...\n")
    
#Allows for encryption of data with the data key, allowing for safe storage of data.
#Allows for encryption of data key with the user key, this allows for safe storage of the data key. 
#Takes bytes as input.
def encrypt(data, key):
    try:
        fernet = Fernet(key)
        cipherText = fernet.encrypt(data)
        return cipherText
    except:
        print("Error: Couldn't encrypt data...\n")
    
#Allows for decryption of data with the data key.
#Allows for decryption of data key with the user key.
def decrypt(data, key):
    try:
        fernet = Fernet(key)
        plainText = fernet.decrypt(data)
        return plainText
    except:
        print("Error: Couldn't decrypt data...\n")

#Tests
def tests():
    password = 'password'
    data = encode('data 123\n 123')
    print(data)

#Main interface function
def interface():
    
    password = 'password'
    data = encode('data 123\ndata123')
    salt = generateSalt(128)
    dataKey = generateDataKey()
    print(decode(dataKey))
    userKey = generateUserKey(password, salt)
    data = encrypt(data, dataKey)
    print(decode(data))
    dataKey = encrypt(dataKey, userKey)
    print(salt)
    #userKey = generateUserKey(password, input("Please enter salt"))
    dataKey = decrypt(dataKey, userKey)
    data = decrypt(data, dataKey)
    print(decode(data))
    print(salt)


    

#Main
interface()
