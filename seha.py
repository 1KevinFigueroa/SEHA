#!/usr/bin/env python3

import requests as req
import colorama as cr
from colorama import Fore, Back, Style

cr.init()

banner = '''

.:::::::.  .,:::::  :::   :::    :::.
  `     `  |``````  .;;   ;;.    ::`::
;;;        ||      ,[[[,,,]]],  ,[[  ]],
'[=/[[[[,  ||$$$$  '$$$,,,$$$' a$$$aaa$$$a
  """    $ ||       |||   |||   ***   ***
88b     dp |        88b   88b   888   888
 "YMmMY"   ||MMMMM  MMM   MMM   YMM   MMY

 Security Evaluation  Header  Analyzer
'''


print(Fore.YELLOW + banner + Style.RESET_ALL)
print("[+] TARGET to SCAN:")
tURL = str(input())
resp = req.get(tURL)


pStatus = str(resp.status_code)
hInfo = resp.headers
eType = str(resp.encoding)
print(Fore.GREEN + "\nTARGET REQUEST HEADERS from:" + Fore.GREEN + "|-->>> " + Fore.YELLOW + tURL + Style.RESET_ALL)
print(Fore.GREEN + "Page Status: " + Style.RESET_ALL + pStatus)
print(Fore.GREEN + "Encoding Type: " + Style.RESET_ALL + eType)


for key, value in hInfo.items():
    print(Fore.GREEN + key + Style.BRIGHT + Fore.YELLOW + " => " + Style.RESET_ALL + value)

print("\n Security Evaluation Header Analyzer of " + Fore.GREEN + "|->> " + Style.BRIGHT + Fore.YELLOW + tURL + Style.RESET_ALL)
print(Style.BRIGHT + Fore.YELLOW + "-----------------------------------------------------------------------" + Style.RESET_ALL)

hstsFields = 'Strict-Transport-Security' 
hstsFields2 = 'strict-transport-security'
cspFields = 'Content-Security-Policy'
cspFields2 = 'content-security-policy'
xfoFields = 'X-Frame-Options'
xfoFields2 = 'x-frame-options'
acaoFields = 'Access-Control-Allow-Origin'
acaoFields2 = 'access-control-allow-origin'
xctoFields = 'X-Content-Type-Options'
xctoFields2 = 'x-content-type-options'
corsFields = 'Cross-Origin-Resource-Policy'
corsFields2 = 'cross-origin-resource-policy'
referrerFields = 'Referrer-Policy'
referrerFields2 = 'referrer-policy'
permissionFields = 'Permissions-Policy'
permissionFields2 = 'permissions-policy'
clearFields = 'Clear-Site-Data'
clearFields2 = 'Clear-Site-Data'
serFields = 'Server'
serFields2 = 'server'
xssFields = 'X-XSS-Protection'
xssFields2 = 'x-xss-protection'
ectFields = 'Expect-CT'
ectFields2 = 'expect-ct'
xpowFields = 'X-Powered-By'
xpowFields2 = 'x-powered-by'

# configuration coming soon!
#config = {'Strict-Transport-Security' : 'max-age:31536000; includeSubdomains; preload'}
#

checkFields = dict(hInfo)

if (hstsFields not in checkFields.keys() and hstsFields2 not in checkFields.keys()):
    print(Style.BRIGHT + Fore.RED + "[-]" + Fore.YELLOW + " Security " + hstsFields + " Header (HSTS): " + Style.BRIGHT + Fore.RED + "NOT SET" + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.CYAN + " |=> " + Fore.YELLOW + "[" + Fore.CYAN + "INFO" + Fore.YELLOW + "] " + Style.RESET_ALL + Fore.CYAN + hstsFields + " " + Style.RESET_ALL + Back.YELLOW + Fore.RED + "MISCONFIGURATION FOUND" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + hstsFields + " Header (HSTS): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)



if (cspFields not in checkFields.keys() and cspFields2 not in checkFields.keys()):
    print(Style.BRIGHT + Fore.RED + "[-]" + Fore.YELLOW + " Security " + cspFields + " Header (CSP): " + Style.BRIGHT + Fore.RED + "NOT SET" + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.CYAN + " |=> " + Fore.YELLOW + "[" + Fore.CYAN + "INFO" + Fore.YELLOW + "] " + Style.RESET_ALL + Fore.CYAN + cspFields + " " + Back.YELLOW + Fore.RED + "MISCONFIGURATION FOUND" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + cspFields + " Header (CSP): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)



if (acaoFields not in checkFields.keys() and acaoFields2 not in checkFields.keys()):
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + "Security " + acaoFields + " Header (ACAO): " + Style.BRIGHT + Fore.RED + "NOT SET" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + acaoFields + " Header (ACAO): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)



if (xfoFields in checkFields.keys() or xfoFields2 in checkFields.keys()):
    print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + xfoFields + " Header (XFO): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + "Security " + xfoFields + " Header (XFO): " + Fore.RED + "NOT SET " + Style.RESET_ALL)



if (xctoFields in checkFields.keys() or xctoFields2 in checkFields.keys()):
    print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + xctoFields + " Header (XCTO): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + "Security " + xctoFields + " Header (XCTO): " + Fore.RED + "NOT SET" + Style.RESET_ALL)



if (corsFields in checkFields.keys() or corsFields2 in checkFields.keys()):
    print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + corsFields + " Header (CORS): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + "Security " + corsFields + " Header (CORS): " + Fore.RED + "NOT SET" + Style.RESET_ALL)



if (referrerFields in checkFields.keys() or referrerFields2 in checkFields.keys()):
     print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + referrerFields + " Header (RP): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + "Security " + referrerFields + " Header (RP): " + Fore.RED + "NOT SET" + Style.RESET_ALL)



if (permissionFields in checkFields.keys() or permissionFields2 in checkFields.keys()):
     print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + permissionFields + " Header (PP): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + "Security " + permissionFields + " Header (PP): " + Fore.RED + "NOT SET" + Style.RESET_ALL)


if (clearFields in checkFields.keys() or clearFields2 in checkFields.keys()):
     print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + clearFields + " Header (CSD): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + "Security " + clearFields + " Header (CSD): " + Fore.RED + "NOT SET" + Style.RESET_ALL)


if (xssFields in checkFields.keys() or xssFields2 in checkFields.keys()):
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + xssFields + " FOUND (XSS):" + Fore.GREEN + " SET " + Style.BRIGHT + Back.WHITE + Fore.RED + "DEPREACTED" +Style.RESET_ALL)

if (ectFields in checkFields.keys() or ectFields2 in checkFields.keys()):
    print(Style.BRIGHT + Fore.RED + "[-] " + Fore.YELLOW + ectFields + " FOUND (ECT):" + Fore.GREEN + " SET " + Style.BRIGHT + Back.WHITE + Fore.RED + "DEPREACTED" +Style.RESET_ALL)

if (serFields not in checkFields.keys() or serFields2 not in checkFields.keys()):
    print(Style.BRIGHT + Fore.RED + "[-]" + Fore.YELLOW + " Security " + serFields + " Header (SVR): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.CYAN + " |=> " + Fore.YELLOW + "[" + Fore.CYAN + "OSINT INFO" + Fore.YELLOW + "] " + Style.RESET_ALL + Fore.CYAN + "Data Leakage" + " " + Back.YELLOW + Fore.RED + "MISCONFIGURATION FOUND" + Style.RESET_ALL)
else:
    print(Style.BRIGHT + Fore.GREEN + "[+] " + Style.RESET_ALL + Fore.YELLOW + "Security " + serFields + " Header (SVR): " + Style.BRIGHT + Fore.GREEN + "NOT SET" + Style.RESET_ALL)

if (xpowFields in checkFields.keys() or xpowFields2 in checkFields.keys()):
    print(Style.BRIGHT + Fore.RED + "[-]" + Fore.YELLOW + " Security " + xpowFields + " Header (XPOW): " + Style.BRIGHT + Fore.GREEN + "SET" + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.CYAN + " |=> " + Fore.YELLOW + "[" + Fore.CYAN + "OSINT INFO" + Fore.YELLOW + "] " + Style.RESET_ALL + Fore.CYAN + xpowFields + " " + Back.YELLOW + Fore.RED + "MISCONFIGURATION FOUND" + Style.RESET_ALL)

print(Fore.GREEN + "\n PROCESSING COMPLETED")
print('|~~>>>**********<<<--|\n')
