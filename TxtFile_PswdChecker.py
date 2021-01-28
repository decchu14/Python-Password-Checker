# please follow steps to understand the flow of a code.
import requests
import hashlib
import sys

'''
    step 13 - receiving first 5 characters of our hashed password.
    step 14 - assingning the api url and hashed password
    step 15 - requesting and fetching all the tails of a hashed passowrds from api whose 1st 5 chars matches our hashed  
              password's 1st 5 chars and assigning it to a variable 'res'.
    step 16 - checking if the returned result from api gives status code 200
            - 200 status code indicates that the request has succeeded.
    step 17 - if status code of result is not 200 then the error will be raised.
    step 18 - returning res which contains all the tails of a hashed passwords followed by :count to pwnd_api_check 
              function.
            - for example :- CBFDAC6008F9CAB4083784CBD1874F76618D2A97:100 [tail:count]
            - here 100 will be the count of how many times a password has been pwnd.
'''


def requests_api_data(query_char):  # 13
    url = 'https://api.pwnedpasswords.com/range/' + query_char  # 14
    res = requests.get(url)  # 15
    if res.status_code != 200:  # 16
        raise RuntimeError(
            f'Error fetching:{res.status_code}, check the api and try again')  # 17
    return res  # 18


'''
    step 20 - hashes : all the tails of a response hashes
            - hash_to_check : tail hash of our password
    step 21 - as mentioned in the 14th step the response hashes will in the form of    
              CBFDAC6008F9CAB4083784CBD1874F76618D2A97:100 [tail:count]
            - we need to split the hash from count 
            - line.split(':')is the method. the seperator based on which we split is ':'.
    step 22,23,24,25 - loop through splited hash(h) and count one by one and if hash(h) matches to hash_to_check(tail) 
                       then return the count else return 0 to pwnd_api_ckeck function. 
'''


def get_password_leaks_count(hashes, hash_to_check):  # 20
    hashes = (line.split(':') for line in hashes.text.splitlines())  # 21
    for h, count in hashes:  # 22
        if h == hash_to_check:  # 23
            return count  # 24
    return 0  # 25


'''
    step 9 - receiving one password at one time 
    step 10 - here the password will be converted to hash using hashlib module.
           - encode() : Converts the string into bytes to be acceptable by hash function.
           - hexdigest() : Returns the encoded data in hexadecimal format.
           - upper() : converts tha hashed password to uppercase.
    step 11 - here the hashed passowrd will be divided into 2 parts, that is first 5 characters into one part and rest
             character sinto second part.
    step 12 - passing the first 5 characters of our hashed password to the requests_api_data function and assigning the    
             returned result to variable named 'response'.
    step 26 - passing the tail of our password and the all tail response hashes which we fetched from password api to 
              get_password_leaks_count function.
            - returning it to the main function
'''


def pwnd_api_check(password):  # 9
    sha1_password = hashlib.sha1(
        password.encode('utf-8')).hexdigest().upper()  # 10
    first5_char, tail = sha1_password[:5], sha1_password[5:]  # 11
    response = requests_api_data(first5_char)  # 12
    return get_password_leaks_count(response, tail)  # 26


'''
    step 2 - defining the function main()
    step 3 - here password.txt is the file in our PC in which we store our passwords.
           - store each password in each line
           - here the func open will open the txt file in read mode and will be assigned to variable called 'file'.
    step 4 - readline() will read each password line by line and store it in the form of list.
           - the list of passwords will be assigned to a variable called 'password_list'.
           - for example the list will look like ['password1 \n','password2 \n','password \n','\n']
           - yes the extra end line will be added to each password while running readlines().
    step 5, step 6  & step 7 - each of the passwords will be looped and removed the end line (\n) and sent to pwnd_api_check function to check how many times a 
                               password has been pwnd.
    step 27,28,29 - if count not equal to 0 then print 'need to change the password' else print 'password not found carry 
                    on'.
'''


def main():  # 2
    with open('password.txt', mode='r') as file:  # 3
        password_list = file.readlines()  # 4
        for password in password_list:  # 5
            pswd = password[:-1]  # 6
            count = pwnd_api_check(pswd)  # 7
            if count:  # 27
                print(
                    f'{pswd}was found {count} many times...you should probably change your password \n')  # 28
            else:
                print(f'{pswd}was not found. Carry on\n')  # 29


'''
    step 0 - this entire program will only execute if this file gets run and it wont if its imported into some other files
    step 1 - The main function call
           - then the control will jump to main function 
           - sys.exit() --  is just to make sure evrything gets          
'''
if __name__ == '__main__':  # 0
    sys.exit(main())  # 1
