import tarfile
import glob
import re
import os
import sys
import time

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5

def extract_tarfile(tar_filepath, dataset_path):
    # https://www.tutorialspoint.com/How-are-files-extracted-from-a-tar-file-using-Python
    # Extracting tar_file to get all the messages
    dataset = tarfile.open(tar_filepath)
    dataset.extractall(dataset_path)
    dataset.close()

def decrypt_rsa(private_key, cipher_text):
    # Decrypting RSA encryption with private_key and cipher_text
    decrypted_text = private_key.decrypt(cipher_text)
    return decrypted_text

def decrypt_aes_key(private_key_file_path, encrypted_aes_key_file_path):
    # Decrypting RSA encryption with private_key and cipher_text
    # Opens the files and calls decrypt_rsa for decryption
    private_key = RSA.importKey(open(private_key_file_path).read())
    with open(encrypted_aes_key_file_path, 'rb') as f:
        enc_session_key = f.read()

    try:
        decrypted_aes_key = decrypt_rsa(private_key, enc_session_key)
    except ValueError:
        return enc_session_key

    return decrypted_aes_key


def check_correct_aes_key(aes_key, correct_key_hash):
    # Checking if the decrypted_key matches the plain_AES_hash
    key_hash = MD5.new(aes_key).hexdigest()
    if key_hash == correct_key_hash:
        print('Key found')
    return key_hash == correct_key_hash

def find_correct_session_key(session_keys_folder_path, rsa_key_folder_path, correct_key_hash):
    # Looping through all the keys to find the correct session key
    session_keys_file_list = glob.glob(session_keys_folder_path + "*.eaes")
    print(f'\nNumber of asymmetric keys: {len(session_keys_file_list)} \n')
    print(f'\nNumber of symmetric key (counting both private and public): {len(session_keys_file_list) * 2} \n')
    print(f'\nNumber of symmetric key pairs: {len(session_keys_file_list)} \n')
    i = 0
    for session_key_file_path in session_keys_file_list:
        # Matching file numbers to find matching private key file for each encrypted session key
        file_num = re.findall("\d+", session_key_file_path)[0]
        private_rsa_key_file = f'private_key{file_num}.pem'
        private_key_file_path = rsa_key_folder_path + private_rsa_key_file

        aes_key = decrypt_aes_key(private_key_file_path, session_key_file_path)
        key_found = check_correct_aes_key(aes_key, correct_key_hash)

        if key_found:
            print("=="*20)
            print("Key is: ", aes_key)
            print("Private key: ", private_rsa_key_file)
            print("Session key file: ", session_key_file_path)
            print("=="*20)
            
            return aes_key
        
        i += 1
        if i % 20 == 0:
            print(f'{i} file decrypted')


def decrypt_message(key, enc_message):
    # Decrypt message using AES
    iv = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = aes_cipher.decrypt(enc_message)
    return decrypted_message

def check_correct_decrypted_message(decrypted_message, correct_message_hash):
    # Checking if decrypted message is correct
    message_hash = MD5.new(decrypted_message).hexdigest()
    if message_hash == correct_message_hash:
        print('Message found')
    return message_hash == correct_message_hash

def find_correct_message(enc_message_folder_path, key, correct_message_hash):
    # Looping through all the message files to find the decrypted message.
    enc_message_file_list = glob.glob(enc_message_folder_path + "*.emsg")
    print(f'\nNumber of messages: {len(enc_message_file_list)} \n')
    i = 0
    for enc_message_file_path in enc_message_file_list:
        with open(enc_message_file_path, 'rb') as f:
            enc_message = f.read()

        decrypted_message = decrypt_message(key, enc_message)
        message_found = check_correct_decrypted_message(decrypted_message, correct_message_hash)

        if message_found:
            print("=="*20)
            print("Message is: ", decrypted_message)
            print("Message file is: ", enc_message_file_path)
            print("=="*20)
            
            return decrypted_message
        
        # break
        i += 1
        if i % 1000 == 0:
            print(f'{i} file decrypted')
    
    return None


if __name__ == "__main__":
    if len(sys.argv)==2:
        dataset_path = sys.argv[1]
        tar_filepath = "./random_path"
    elif len(sys.argv) == 3:
        dataset_path = sys.argv[1]
        tar_filepath = './kritish-dataset3.tar.gz'
    else:
        print("Please specify either the path of the dataset folder or both targeted folder path and tar file path")
        print("Examples: ")
        print("python find_correct_message.py \"./lhakpa/dataset\"")
        print("python find_correct_message.py \"./lhakpa/dataset\" \"./tar_file.tar.gz\"")
        exit()

    # os.path.exists("./lhakp")
    if os.path.exists(dataset_path):
        print("Dataset folder found using the folder to find the message")
    else:
        if not os.path.exists(tar_filepath):
            print("Tar file not found")
            exit()
        
        print("Found tar file of messages, extracting data from it")
        start_time = time.time()
        extract_tarfile(tar_filepath, dataset_path)
        end_time = time.time()
        print(f"Execution time extraction of tar file: {end_time - start_time} seconds")

    session_keys_folder_path = f"./{dataset_path}/RSA/session_keys/"
    rsa_key_folder_path = f"./{dataset_path}/RSA/pairs/"
    enc_message_folder_path = f"./{dataset_path}/RSA/messages/"

    with open(f"./{dataset_path}/plain_AES_hash.md5", "r") as f:
        correct_key_hash = f.read()
    with open(f"./{dataset_path}/plain_master_message_hash.md5", "r") as f:
        correct_message_hash = f.read()

    start_time = time.time()
    print("\nDecrypting and finding the correct AES key")
    print("---"*10)
    aes_key = find_correct_session_key(session_keys_folder_path, rsa_key_folder_path, correct_key_hash)

    if aes_key:
        print("\nDecrypting and finding the correct message")
        print("---"*10)
        correct_message = find_correct_message(enc_message_folder_path, aes_key, correct_message_hash)
    else:
        print("\nCould not find the correct AES key")
    end_time = time.time()
    print('\n')
    print('---'*10)
    print(f"Execution time for identification: {end_time - start_time} seconds")
    print('---'*10)

