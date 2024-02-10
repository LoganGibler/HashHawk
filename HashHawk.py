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




def main():
    # sys.argv[0] = the actual script running  ----  ex: python3 HashHawk.py -hc
    argument = sys.argv[1]
    options_map = {
        "-g": generate,
        "-h": hashPassword
    }

    if argument in options_map:
        options_map[argument]()

        

if __name__ == "__main__":
    main()