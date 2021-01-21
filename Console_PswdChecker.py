# please follow steps to understand the flow of a code.
import requests
import hashlib
import sys

'''
    step 9 - receiving first five characters of our hashed password.
    step 10 - assingning the api url and hashed password
    step 11 - requesting and fetching all the hashed passowrds from api which matches our hashed password and assigning   
              it to a variable 'res'. 
    step 12 - checking if the returned result from api gives status code 200
            - 200 status code indicates that the request has succeeded.
    step 13 - if status code of result is not 200 then the following error will be raised.
    step 14 - returning res which contains all the hashed passwords followed by :count to pwnd_api_check function.
            - for example :- CBFDAC6008F9CAB4083784CBD1874F76618D2A97:100
            - here 100 will be the count of how many times a password has been pwnd.
'''


def requests_api_data(query_char):  # 9
    url = 'https://api.pwnedpasswords.com/range/' + query_char  # 10
    res = requests.get(url)  # 11
    if res.status_code != 200:  # 12
        raise RuntimeError(
            f'Error fetching:{res.status_code}, check the api and try again')  # 13
    return res  # 14


'''
    step 16 - hashes : all the response hashes
            - hash_to_check : tail hash of our password
    step 17 - as mentioned in the 14th step the response hashes will in the form of    
              CBFDAC6008F9CAB4083784CBD1874F76618D2A97:100 
            - we need to split the hash from count 
            - line.split(':') the seperator based on which we split iis ':'.
    step 18,19,20,21 - loop through splited hash(h) and count one by one and if hash(h) matches to hash_to_check(tail) 
                       then return the count else return 0 to pwnd_api_ckeck function. 
'''


def get_password_leaks_count(hashes, hash_to_check):  # 16
    hashes = (line.split(':') for line in hashes.text.splitlines())  # 17
    for h, count in hashes:  # 18
        if h == hash_to_check:  # 19
            return count  # 20
    return 0  # 21


'''
    step 5 - receiving one password at one time 
    step 6 - here the password will be converted to hash using hashlib module.
           - encode() : Converts the string into bytes to be acceptable by hash function.
           - hexdigest() : Returns the encoded data in hexadecimal format.
           - upper() : converts tha hashed password to uppercase.
    step 7 - here the hashed passowrd will be divided into 2 parts, that is first 5 characters into one part and rest
             character into second part.
    step 8 - passing the first 5 characters of our hash to the requests_api_data function and assigning it to variable   
             named 'response'.
    step 15 - passing the tail of our password and the all response hashes which we fetched from password api to 
              get_password_leaks_count function.
            - returning it to the function main function
'''


def pwnd_api_check(password):  # 5
    sha1_password = hashlib.sha1(
        password.encode('utf-8')).hexdigest().upper()  # 6
    first5_char, tail = sha1_password[:5], sha1_password[5:]  # 7
    response = requests_api_data(first5_char)  # 8
    return get_password_leaks_count(response, tail)  # 15


'''
    step 2 - main(args) here args is a list of all the passwords passed through console.
    step 3 & step 4 - each of the passwords will be looped and sent to pwnd_api_check function to check how many times a 
                      password has been pwnd.
    step 22,23,24 - if count not equal to 0 then print 'need to change the password' else print 'password not found carry 
                    on'.
'''


def main(args):  # 2
    for password in args:  # 3
        count = pwnd_api_check(password)  # 4
        if count:  # 22
            print(
                f'{password}:-was found {count} many times...you should probably change your password')  # 23
        else:
            print(f'{password}:-was not found. Carry on')  # 24


'''
    step 1 - is to accept the passwords as arguements through console
           - for example console_pswdchecker.py password1 password2 password3
           - this will be passed to main(sys.argv[1:])
           - here index 0 is the name of the file console_pswdchecker.py hence [1:] because the passwords index will 
             begin from 1
           - then the control will jump to main function           
'''
main(sys.argv[1:])  # 1
