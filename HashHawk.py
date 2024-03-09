#!/bin/python3
import sys
import random
import string
from hashlib import md5, sha1, sha224, sha256, sha384, sha512


def generate():
    password = ''
    generated_chars = ''
    special_char_list = ["!","?","#","*","@",]

    # creates a character list of 30-40 random characters.
    for i in range(10,20):
       generated_chars = generated_chars + str(random.randint(1,10))
    for i in range(12, 22):
        generated_chars = generated_chars + random.choice(string.ascii_letters)

    # chooses 7-9 random characters from the random character list
    for i in range(random.randint(7,9)):
        password = password + generated_chars[random.randint(0, len(generated_chars) - 1)]

    # inserts a special character into a random index of the generated password.
    random_index = random.randint(0, len(password) - 1)
    random_special_char = special_char_list[random.randint(0, len(special_char_list) - 1)]
    password = password[:random_index] + random_special_char + password[random_index:]

    
    print(f'Your new generated password is: {password}')



# from hashlib import md5, sha1, sha224, sha256, sha384, sha512
def hashPassword():
    print('Please enter password to hash:', end='')
    password = input(" ")

    # md5
    result = md5(password.encode())
    print(f'MD5 Hash:  {result.hexdigest()}')
    # sha1
    result = sha1(password.encode())
    print(f'SHA1 Hash:  {result.hexdigest()}')
    # sha224
    result = sha224(password.encode())
    print(f'SHA224 Hash:  {result.hexdigest()}')
    # sha256
    result = sha256(password.encode())
    print(f'SHA256 Hash:  {result.hexdigest()}')
    # sha384
    result = sha384(password.encode())
    print(f'sha384 Hash:  {result.hexdigest()}')
    # sha512
    result = sha512(password.encode())
    print(f'SHA512 Hash:   {result.hexdigest()}')
    

def checkPassword():
    print('Please enter password to check if leaked:', end='')
    password = input(" ")
    
    try:
        rockyou = "testingWordlist.txt"
        with open(rockyou, "r") as rockyou:
            for word in rockyou:
                if password.strip() == word.strip():
                    print("")
                    print(f"Your password was already involved in a dataleak. Please change your password.")
                    return
        print("")
        print("Your password was not found in our leaked password wordlist.")      

    except FileNotFoundError:
        print(f"Error: The wordlist file '{rockyou}' does not exist.")

    except PermissionError:
        print(f"Error: Permission denied. Unable to open the file '{rockyou}'.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")


def hashType():
    # Map hash types to their corresponding hashlib functions
    password_hash = input("Enter the password hash to analyze: ")
    found = False
    if len(password_hash) == 128:
        print("Hash type: SHA512")
        found = True
    elif len(password_hash) == 96:
        print("Hash type: SHA384")
        found = True
    elif len(password_hash) == 64:
        print("Hash type: SHA256")
        found = True
    elif len(password_hash) == 40:
        print("Hash type: SHA1")
        found = True
    elif len(password_hash) == 32:
        print("Hash type: MD5")
        found = True
    elif len(password_hash) == 56:
        print("Hash type: SHA224")
        found = True
    else:
        print("Could not detect hash type. :(")

    if found:
        print("Hash length:", len(password_hash))
        print("Hash:", password_hash)
        print("")
        user_input = input("Would you like to try to crack the hash? (y/n): ")
        if user_input.lower() == "y":
            hashCrack(password_hash)


def hashCrack(passHash=None):
    if not passHash:
        passHash = input("Enter password hash: ")

    hash_length = len(passHash)
    hash_algorithms = {
        32: md5,
        40: sha1,
        56: sha224,
        64: sha256,
        96: sha384,
        128: sha512
    }

    if hash_length not in hash_algorithms:
        print("Could not detect hash type. :(")
        return

    algorithm = hash_algorithms[hash_length]

    with open("testingWordlist.txt", "r") as wordList:
        for word in wordList:
            word = word.strip()
            guess = algorithm(word.encode("utf-8")).hexdigest()

            if guess == passHash:
                print("Password is:", word)
                return

    print("Password not found")

# todo:
# hashpassword -h DONE
# generate -g DONE
# checkpassword -c DONE
# hashtype -t DONE
# crackhash -ch DONE
# -manpage
# -help
# gradePassword -gp
# time2crack -t2c


def main():
    # sys.argv[0] = the actual script running  ----  ex: python3 HashHawk.py -hc
    try:
        argument = sys.argv[1]
        options_map = {
            "-g": generate,
            "-h": hashPassword,
            "-c": checkPassword,
            "-t": hashType,
            "-hc": hashCrack
        }


        if argument in options_map:
            options_map[argument]()
        else:
            print("Option not found. Please use the manpage more information. -manpage")

    except IndexError:
        print("Please enter an option. ex: python3 HashHawk.py -manpage")

if __name__ == "__main__":
    main()