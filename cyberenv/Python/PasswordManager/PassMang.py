"""
 -- This is a password manager python script. Purpose is to learn how password manager operate for security operations with cryptography 
 -- Functionalities of this manager:
    - logging in 
    - adding and retrieving passwords 
    - display saved websites credentials 

-- When comppiled:
  -- json files will be created and stored in the same folder. 
  -- Encryption key will be generated and saved in a key file, stored in the same folder.
-- Passwords will be stored in a JSON File - encrypted 
-- login credentials will be stored in a JSON File as well
"""

# Import necessary librariers 
"""
    -- json -- encoding and decoding JSON data
    -- hashlib -- use for secure hash function
    -- getpass -- use for secure sensitive information capture without displaying input on the screen
    -- OS -- operating system 
    -- pyperclip -- use for clipboard operations, allowing copy and past actions 
    -- sys -- system functions and parameters 
    -- cryptography.fernet -- providing Fernet symmetric-key encryption method
""" 

import json 
import hashlib 
import getpass 
import os
import pyperclip
import sys 
from cryptography.fernet import Fernet 


# Add hash function 

def pwd_hash(passowrd):

    # Use sha256 hasing algorithm for password hasshing 

    hash_sha256 = hashlib.sha256()
    hash_sha256.update(passowrd.encode())
    
    return hash_sha256.hexdigest()

# Generate a encryption and decryption key 

def create_key():
    return Fernet.generate_key()

def initialize_cipher(key):
    return Fernet(key)

def encrypt(cipher, passwrd):
    return cipher.encrypt(passwrd.encode()).decode()

def decrypt(cipher, encrypt):
    return cipher.decrypt(encrypt.encode()).decode()


# Add registration function for our password manager 

def registration(username, admin_pass):

    # take in the user input for admin password and hash it
    # Apply a font for username and admin pass within 'user_data.json' file 
    # add user data into user data file if file exists, and handle if user file doesnt exist
    Hashed_MP = pwd_hash(admin_pass)
    user_data = {'username': username, 'admin_pass': Hashed_MP}

    file = 'user_data.json'
    if os.path.exists(file) and os.path.getsize(file) == 0:
        with open(file, 'w') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!\n")
    else:
        with open(file, 'x') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!\n")

        


# Add logging in fnction 
def login(username, input_pass):
    
    # Handle user login with credentials 
    # open user_data file to load user login 
        # retrieve the stored hashed admin pass 
        # hash thecurrent inptted pass 
        # compare hash values of the input admin_pass 
            # if input user login credentials matches then print login successful 

    # If credentials are inccorrect then print appropriate message
    # hasndle exceptons for any other inputs
    try:
        with open('user_data.json', 'r') as file:
            user_data = json.load(file)
        
        stored_hashed_pwd = user_data.get('admin_pass')
        entered_hashed_pwd = pwd_hash(input_pass)

        if username == user_data.get('username') and entered_hashed_pwd == stored_hashed_pwd:
            print(f"\n[+] Login Successful! Welcome Back {username}!")
        else:
            print("\n[-] Invalid username or password.\n")
            sys.exit()
    except Exception:
        print("\n[-] Please register a username and password")
        sys.exit


# View website saved credentials 
def website_cred():

    # Check saved website that have been stored 
    # saved websites names are stored in "passwords" json file 
    # retrieve webstie naame from file and print all saved websties from a initialized list
    try:
        with open('passwords.json', 'r') as data:
            view = json.load(data)
            print("\nWebsites saved...\n")
            
            for sites in view:
                print(sites[ 'website' ])
            print('\n')
    except FileNotFoundError:
        print("\n[-] You have not saved any pass in a website")

# Add key generation 

key_file = 'encrypt_key.key'

if os.path.exists(key_file):
    with open(key_file, 'rb') as key_file:
        key = key_file.read()
else:
    key = create_key()

    with open(key_file, 'wb') as key_file:
        key_file.write(key)

cipher = initialize_cipher(key)


def update_Passwrd(web, old_passwrd, new_passwrd):
    if not os.path.exists('passwords.json'):
        print("[-] No saved passwords")
        return
    
    try:
        with open('passwords.json', 'r') as file:
            passwrds = json.load(file)
    except json.JSONDecodeError:
        passwrds = []

    
    found = False 
    for data in passwrds:
        if data['website'] == web:
            
            current_pass = decrypt(cipher, encrypt=data['password'])
            if current_pass == old_passwrd:
                data['passwords'] = encrypt(cipher, new_passwrd)
                found = True
            else:
                print("[-] Provious password must match")
                return

    if found:
        with open('passwords.json', 'w') as file:
            json.dump(passwrds, file, indent=4)
        print(f"[+] {web} password successfully added.")
    else:
        print("[-] Website not fonud or does not exist")            


# Add function to add passwords 
def passwrd_add(website, passwrd):

    if not os.path.exists('passwords.json'):
        pass_list = []
    else:
        try:
            with open('passwords.json') as file:
                pass_list = json.load(file)
        except json.JSONDecodeError:
            pass_list = []

    encrypt_passwrd = encrypt(cipher, passwrd)
    passwrd_entry = {'website': website, 'password': encrypt_passwrd}
    pass_list.append(passwrd_entry)

    with open('passwords.json' ,'w') as file:
        json.dump(pass_list, file, indent=4)


# Add function to retrieve password 
def retrieve_pass(website):
    if not os.path.exists('passwords.json'):
        return None
    
    try:
        with open('passwords.json', 'r') as file:
            info = json.load(file)
    except json.JSONDecodeError:
        info = []

    for data in info:
        if data['website'] == website:
            decrypt_pass = decrypt(cipher, encrypt=data['password'])
            return decrypt_pass
        
    return None

def main():

    # Apply Menu option for first page user interface 
    # This menu includes:
    """
        - User login -- requires username and admin password 
        - Register   -- user registers admin username and password 
        - Exit       -- user option to exit password manager/program

    """


    while True:
        print("\n\n")
        print("-------Welcome to P-MANAGER--------\n\n")
        print("1. Login")
        print("2. Register")
        print("3. Exit")
        print("\n\n")

        option = input("Choose an option: ")
        # Handle user log in
        # handle file system existence 
            # if file exists then allow user to enter log in credentials 
            # else notifiy user to register an account and exit program

        if option == '1':
            file = 'user_data.json'

            if os.path.exists(file):
                username  = input("\nEnter username: ")
                admin_pass = getpass.getpass("Enter admind password: ")
                login(username,admin_pass)

            else:
                print("\n[-] Please register an account.\n")
                sys.exit()


            # Once user credentials are verified, prop up submenu for password manager 
            # Menu should include:                
                """
                    -- Password Addition - user adds password with associated website or app
                    -- Retrieve password - user retrieves stored password by inputting stored website or app information
                    -- Password Change   - user changes password credentials for a stored password with associated website or app
                    -- Exit              - user exits submenu and returns to main main 
                """

            while True:
                print("\n\n")
                print("1. Add Password")
                print("2. Retrieve Password")
                print("3. Saved Websites")
                print("4. Change Password")
                print("5. Exit")
                print("\n\n")

                choice = input("Choose option: ")

                if choice == '1':
                    web = input("\nProvide Website or App: ")
                    passwrd = getpass.getpass("Enter password: ")

                    passwrd_add(web, passwrd)
                    print("\n[+] Password added successfully!\n\n")

                elif choice == '2':
                    web = input("Provide website: ")
                    decryp_pass = retrieve_pass(web)
                    
                    if web and decryp_pass:
                        pyperclip.copy(decryp_pass)
                        print(f"\n[+] Password for {web}: {decryp_pass}\n[+] Password copied to clipboard.\n")
                    else:
                        print("\n[-] Password not found or doesn't exists.")
                        print("\n[-] Check saved websites with option 3.\n")
                
                elif choice == '3':
                    website_cred()

                elif choice == '4':
                    web = input("Provide website or App: ")
                    old_passwrd = getpass.getpass("Provide old password: ")
                    nnew_passwrd = getpass.getpass("Provide new password: ")
                    update_Passwrd(web, old_passwrd, nnew_passwrd)

                elif choice == '5':
                    break;

        # Handle user registration
        elif option == '2': 
            file = 'user_data.json'

            if os.path.exists(file) and os.path.getsize(file) != 0:
                print("\n[-] Admin user aleady exists")
                sys.exit()

            else:
                username = input("\nEnter username: ")
                admin_pass = getpass.getpass("Enter admin passowrd: ")
                registration(username, admin_pass)

        elif option == '3':
            break

    
    

if __name__ == "__main__":
    main()







