# ntdsdump
Simple python3 script to parse pot and ntds file and output nicely formatted report.

For extensive guide on internal password auditing, with the use of this script, see the below blogpsot:

https://jjopentester.com/comprehensive-password-cracking-guide/

Usage: python3 ntdsdump.py --pot=potfile --ntds=ntdsfile

The following output files will be automatically generated:

  	ntdsdump.txt - Formatted text file with the results of your audit

  	CrackedAccounts.txt - List of accounts with cracked password hashes


Please report any bugs you encounter by creating an issue. Much appreciated!
