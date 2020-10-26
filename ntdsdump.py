import os
import subprocess
import getopt, sys
import re
from io import BytesIO

def helpmsg():
    print('ntdsdump v4.0 - Copyright JJOPentester Enterprise\n')
    print('Usage: python3 ntdsdump.py --pot=potfile --ntds=ntdsfile')
    print('The following output files will be automatically generated:')
    print('\tntdsdump.txt - Formatted text file with the results of your audit')
    print('\tCrackedAccounts.txt - List of accounts with cracked password hashes\n')
    print('Please note that existing files will be overwritten. As such, please make sure you have backed up your output files before rerunning this script.')
    print('If you come across any bugs running this tool, please raise an issue in our Github repo')
    
def welcomemsg():
    print('/ * * * * * * * * * * * * * * * * * * * * * * * * * * \\')
    print('+ JJOPentester tools - Internal password audit parser +')
    print('+ Author: Joseph Ooi                                  +')
    print('+ Version: 4.0 - Last updated: 20th September 2020    +')
    print('+ Github Repository: https://github.com/jjopentester  +')
    print('+ This is a simple tool to parse your password audit  +')
    print('+ results and output them in a nicely formatted file  +')
    print('+ Please report any bugs you come across to the repo  +')
    print('\\ * * * * * * * * * * * * * * * * * * * * * * * * * * /\n')

ntdsfile = ''
potfile = ''
outputfile = None
crackresults = { }
finalresults = { }
sortedresults = { }
WINDOWS_LINE_ENDING = b'\r\n'
UNIX_LINE_ENDING = b'\n'
crackedaccountsnum = 0

# get full arguements
full_cmd_arguements = sys.argv
# get rid of the first arguement
arguement_list = full_cmd_arguements[1:]

# define valid command line arguements
short_options = "hvn:p:"
long_options = ["help","verbose","ntds=","pot="]

try:
    arguements, values = getopt.getopt(arguement_list, short_options, long_options)
except getopt.error as err:
    # output error, and return with an error code
    print(str(err))
    helpmsg()
    sys.exit(2)

for current_arguement, current_value in arguements:
    if current_arguement in ("-h", "--help"):
        helpmsg()
        sys.exit()
    elif current_arguement in ("-n", "--ntds"):
        ntdsfile = current_value
    elif current_arguement in ("-p", "--pot"):
        potfile = current_value
        
# Some error checking
if not os.path.exists(ntdsfile):
    print('The ntds file do not exist. Are you sure you are supplying the correct file?\n')
    helpmsg()
    sys.exit(2)

if os.stat(ntdsfile).st_size == 0:
    print('The ntds file provided is empty. Are you sure you are supplying the correct file?\n')
    helpmsg()
    sys.exit(2)

if not os.path.exists(potfile):
    print('The pot file do not exist. Are you sure you are supplying the correct file?\n')
    helpmsg()
    sys.exit(2)

if os.stat(potfile).st_size == 0:
    print('The pot file provided is empty. Are you sure you are supplying the correct file?\n')
    helpmsg()
    sys.exit(2)

if ntdsfile is None:
    print('Compulsory ntds file is missing, specify it with the --ntds flag...')
    sys.exit(2)
if potfile is None:
    print('Compulsory pot file is missing, specify it with the --pot flag...')
    sys.exit(2)
    
# lets get started

welcomemsg()

with open('ntdsdump.txt', 'w') as fileobject:
    fileobject.write('Password statistic file - JJOPentester Tools @ https://jjopentester.com\n\n')
with open('CrackedAccounts.txt', 'w') as fileobject:
    fileobject.write('List of accounts with weak passwords\n\n')

# Read the provided pot file, do some clean up, store in a dictionary, add failsafe to check hash format
with open(potfile, 'r') as fileobject_pot:
    potlines = fileobject_pot.readlines()
    for x in potlines:
        # remove trailing new line characters and split with delimeter ':'
        hashraw, password = x.rstrip('\n').split(':')
        # split hashraw with delimeter '$'
        temp, hashformat, hashvalue = hashraw.split('$')
        # save these in the crackresults dict
        crackresults[hashvalue] = password
        
        if hashformat != 'NT':
            print('Expected hash format of NT, but getting', hashformat, 'instead. Gracefully exiting...')
            sys.exit(2)

# Print some cool looking headers
print('[!] Alrighty, here is your nicely formatted results...\n')

with open('ntdsdump.txt', 'a') as fileobject:
    fileobject.write('{0:40} {1:25} {2}\n'.format('Password hash', 'Cleartext Password', 'Reuse Number'))
print('{0:40} {1:25} {2}'.format('Password hash', 'Cleartext Password', 'Reuse Number'))

# Count the number of password reuse
# Write to CrackAccounts.txt
# for loop through the dict, read ntds file, check if ntdshash == dicthash and + 1, output total
for resultshash, password in crackresults.items():
    with open(ntdsfile, 'r') as fileobject_ntds:
        ntdslines = fileobject_ntds.readlines()
        reusenum = 0
        totalaccountsnum = 0
        for x in ntdslines:
            totalaccountsnum += 1
            ntdsnames = x.rstrip('\n').split(':')[0].split('\\')[-1]
            ntdshash = x.rstrip('\n').split(':')[3]
            if resultshash == ntdshash:
                with open('CrackedAccounts.txt', 'a') as fileobject:
                    fileobject.write('{0}\n'.format(ntdsnames))
                reusenum += 1
                crackedaccountsnum += 1
        
        finalresults[resultshash] = reusenum

# Sort the reuse number in decreasing value and store in the dict sortedresults
sortedresults = sorted(finalresults.items(), key=lambda x: x[1], reverse=True)

# Sort and overwrite CrackAccounts.txt
with open('./CrackedAccounts.txt', 'r') as fileobject_crackedaccounts:
    crackedlines = fileobject_crackedaccounts.readlines()
    crackedlines.sort()
with open('./CrackedAccounts.txt', 'w') as fileobject_crackedaccounts:
    for i in range (len(crackedlines)):
        fileobject_crackedaccounts.write(crackedlines[i])

# Results section
for finalhash, finalreuse in sortedresults:
    for crackedhash, password in crackresults.items():
        # 31d6cfe0d16ae931b73c59d7e0c089c0 is a hash with empty password, skipping...
        if crackedhash == finalhash and crackedhash != '31d6cfe0d16ae931b73c59d7e0c089c0':
            with open('ntdsdump.txt', 'a') as fileobject:
                fileobject.write('{0:40} {1:25} {2}\n'.format(finalhash, password, finalreuse))
                print('{0:40} {1:25} {2}'.format(finalhash, password, finalreuse))

# Check if there are any accounts with reversible passwords stored
reversiblefile = ntdsfile + '.cleartext'

if os.stat(reversiblefile).st_size != 0:
    print('\n\nPasswords stored as reversible hash...')
    print('{0:40} {1:25}'.format('Username', 'Cleartext Password'))
    with open('ntdsdump.txt', 'a') as fileobject:
        fileobject.write('\n\nPasswords stored as reversible hash...\n')
        fileobject.write('{0:40} {1:25}\n'.format('Username', 'Cleartext Password'))
    with open(reversiblefile, 'r') as fileobject_reverse:
        reversibleline = fileobject_reverse.readlines()
        for x in reversibleline:
            username, u1, clearpassword = x.rstrip('\n').split(':')
            print('{0:40} {1:25}'.format(username.split('\\')[1], clearpassword))
            crackedaccountsnum += 1
            with open('ntdsdump.txt', 'a') as fileobject:
                fileobject.write('{0:40} {1:25}\n'.format(username.split('\\')[1], clearpassword))

with open('ntdsdump.txt', 'a') as fileobject:
    fileobject.write('\nFinal statistics: ~{0:0.2f}% of accounts cracked ({1} out of {2})\n'.format(crackedaccountsnum/totalaccountsnum*100, crackedaccountsnum, totalaccountsnum))
print('\nFinal statistics: ~{0:0.2f}% of accounts cracked ({1} out of {2})'.format(crackedaccountsnum/totalaccountsnum*100, crackedaccountsnum, totalaccountsnum))
