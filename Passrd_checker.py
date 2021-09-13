# https://haveibeenpwned.com/
# k anonymity : k-anonymity is a property possessed by certain anonymized data.
# SHA1 Hash generator :: https://passwordsgenerator.net/sha1-hash-generator/

import requests # to establish  a request over internet
import hashlib # inbuilt module to generate hash key
from pathlib import Path
import sys # used to execute system command

def requesting_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char  # uses only first 5 character of hash key
    resp = requests.get(url)
    # the response ('resp') should be near 200 but not over 400
    if resp.status_code!=200:
        print(f'Error fetching{resp.status_code}, Check the API again')
        # we can also do like "raise RuntimeError(f'Error fetching{ resp.status_code}, Check the API again' )"
    return resp

def password_breach_count(hashes, checking_hash):   
    hashes = (line.split (':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h==checking_hash:
            return count
    return 0

def pwned_api_check(password):
    # password.encode('utf-8') is to encode the text in "utf-8" format
    # hashlib.sha1(password.encode('utf-8')) - give the hash key
    # hexdigest - is used to display in hexadecimal digit
    # upper() - used to convert all the hexadecimal  in capatil letter
    sha1_passrd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5, after_5 = sha1_passrd[:5],sha1_passrd[5:]
    # get the response of Hash key similar to the first 5 character.
    response = requesting_api_data(first_5)
    return password_breach_count(response,after_5)

#1. User input - single password as a time
while True:
    passrd = input('Enter the Paswword: ')
    count = pwned_api_check(passrd)
    if count:
        print(f'"{passrd}" is in breached {count} times, Hence should not be used')
    else:
        print(f"'{passrd}' is not found in breaching list, hence can be used")

#2. password checking using a file
'''
passrd = Path('pasrd.txt').read_text()
count = pwned_api_check(passrd)
if count:
    print(f'"{passrd}" is breached {count} times, Hence should not be used')
else:
    print(f"'{passrd}' is not found in breaching list, hence can be used")
'''
#3. password checking from command prompt
'''
def main(argv):
    for passrd in argv:
        count = pwned_api_check(passrd)
        if count:
            print(f'{passrd} is breached {count} times, Hence should not be used')
        else:
            print(f"'{passrd}' is not found in breaching list, hence can be used")

if __name__=='__main__':
    main(sys.argv[1:])
'''