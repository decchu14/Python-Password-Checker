# Python-Password-Checker


TITLE :- PASSWORD CHECKER

DESCRIPTION :- Script to check how many times a password has been hacked using Password API

ABOUT THE PROJECT :-

   In this project we are going to build a tool that can be used in real world to securely check if your passwords have ever been hacked. we are going to use 2 types of    methods:-
    
  * Using Console
  * Using Text File
  
  1) Using Console
  
     -> In first type we are going to enter the inputs through console.
  
     -> Here inputs means passwords.
     
     -> We can give any number of inputs by giving spaces.
     
  2) Using Text File
  
     -> In second type we are going to save our passwords in simple text file that is .txt . 
  
     -> We then open our text file and read our passwords line by line.
     
     -> Here also we can save any number of passwords.
     

DATA BREACH :-
   * Our passwords gets leaked all the time. 
   * Ever heard of Data breaches? A data breach is the intentional or unintentional release of secure or private/confidentional information to an untrusted environment.
     example:- facebook, linkdIn, yahoo etc, has been hacked with data breaches.
   * All these companies sometimes leaks their databases therefore, our usernames and passwords gets leaked to the public.
   * Hackers compile these lists of usernames and passwords and try to login to different services.
   

THE OFFICIAL WEBSITE :-
   * As explained above, there are databases or we can think them as massive excel files of all emails and passwords that have ever been leaked throughout the history.
   * Using these databases there is a website called https://haveibeenpwned.com/ created by Troy Hunt where we can check whether our emails or passwords have ever been        pawned or not.
   * But remember even though this website is trustworthy which also uses https a secured way of transferring data, yet we should not trust because the best security is      to not trust anything.
   * Because what happens here is, whenever we enter our passwords or emails it will be transferred to the servers somewhere around the world throught the internet 
   * And that is why we build our own tool in our own PC to securely check our passwords.
   * And this above mentioned website gives us a API called Password API using which we will be builiding our tool.
   
HASH Functions :-
   * One needs to always Hash or Encrypt their passwords before storing it.
   * A Hash function is simply a function that generates a value of fixed length for each given input.
   * There are many types of Hash functions such as SHA1, MD5, SHA256 etc. 
   * https://passwordsgenerator.net/sha1-hash-generator/ --->Using this website we can hash our passwords.
   * As mentioned before, the Password API uses SHA1 type for hashing the passwords.
   * For example, let password123 be a password, the hashed form is going to be 'CBFDAC6008F9CAB4083784CBD1874F76618D2A97'. And no matter how many times I give                password123 the hashed form is going to be the same, This technique is called Idempotent.
    
THE REQUIRED TOOLS :-

   * sys module : The sys module is built in module which comes along with python interpreter.
   
   * requests module : The requests module is not a built in module, This module needs to be downloaded.
   
         pip install requests
         
         
   * hashlib module : The hashlib module is not a built in module, this module needs to be downloaded.
   
         pip install hashlib
         
         
THE PASSWORD API :-
   
      import requests
      url = 'https://api.pwnedpasswords.com/range/' + [hashedpassword]
      res = requests.get(url)

   * The first step is to import a requests module.
   * The requests module is going to allow us to make a request to haveibeenpwnd website through browser.
   * Its kinda like having browser without a actual browser.
   
   * The second step is to assign a Password API url to a variable named 'url'.
   * Here hashedpassword is the hashed form of your password.
   * As the example mentioned above, the hashed password for 'password123' is 'CBFDAC6008F9CAB4083784CBD1874F76618D2A97'.
   * But in the url we just pass the 5prefix of your hashed password.
   * So the code will basically look like,
   
         import requests
         url = 'https://api.pwnedpasswords.com/range/' + 'CBFDA'
         res = requests.get(url)
         
    
   
   
   
   
