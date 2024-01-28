#!/usr/bin/env python3

import requests as req

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


print(banner)
print("[+] TARGET to SCAN:")
tURL = str(input())
resp = req.get(tURL)


pStatus = str(resp.status_code)
hInfo = resp.headers
eType = str(resp.encoding)
print("\nTARGET REQUEST HEADERS from:" + "|-->>> " + tURL)
print("Page Status: " + pStatus)
print("Encoding Type: " + eType)


for key, value in hInfo.items():
    print(key + " => " + value)

print("\n Security Evaluation Header Analyzer of " + "|->> " + tURL)
print("-----------------------------------------------------------------------")

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
    print("[-]" + " Security " + hstsFields + " Header (HSTS): " + "NOT SET")
    print(" |=> " + "[" + "INFO" + "] " + hstsFields + " " + "MISCONFIGURATION FOUND")
else:
    print("[+] " + "Security " + hstsFields + " Header (HSTS): " + "SET")



if (cspFields not in checkFields.keys() and cspFields2 not in checkFields.keys()):
    print("[-]" + " Security " + cspFields + " Header (CSP): NOT SET")
    print(" |=> " + "[" + "INFO" + "] " + cspFields + " " + "MISCONFIGURATION FOUND")
else:
    print("[+] " + "Security " + cspFields + " Header (CSP): " + "SET")

if (acaoFields not in checkFields.keys() and acaoFields2 not in checkFields.keys()):
    print("[-] " + "Security " + acaoFields + " Header (ACAO): " + "NOT SET")
else:
    print("[+] " + "Security " + acaoFields + " Header (ACAO): " + "SET")

if (xfoFields in checkFields.keys() or xfoFields2 in checkFields.keys()):
    print("[+] " + "Security " + xfoFields + " Header (XFO): " + "SET")
else:
    print("[-] " + "Security " + xfoFields + " Header (XFO): " + "NOT SET ")

if (xctoFields in checkFields.keys() or xctoFields2 in checkFields.keys()):
    print("[+] " + "Security " + xctoFields + " Header (XCTO): " + "SET")
else:
    print("[-] " + "Security " + xctoFields + " Header (XCTO): " + "NOT SET")

if (corsFields in checkFields.keys() or corsFields2 in checkFields.keys()):
    print("[+] " + "Security " + corsFields + " Header (CORS): " + "SET")
else:
    print("[-] " + "Security " + corsFields + " Header (CORS): " + "NOT SET")



if (referrerFields in checkFields.keys() or referrerFields2 in checkFields.keys()):
     print("[+] " + "Security " + referrerFields + " Header (RP): " + "SET")
else:
    print("[-] " + "Security " + referrerFields + " Header (RP): " + "NOT SET")

if (permissionFields in checkFields.keys() or permissionFields2 in checkFields.keys()):
     print( "[+] " + "Security " + permissionFields + " Header (PP): " + "SET")
else:
    print("[-] " + "Security " + permissionFields + " Header (PP): " + "NOT SET")


if (clearFields in checkFields.keys() or clearFields2 in checkFields.keys()):
     print( "[+] " + "Security " + clearFields + " Header (CSD): " + "SET")
else:
    print("[-] " + "Security " + clearFields + " Header (CSD): " + "NOT SET")


if (xssFields in checkFields.keys() or xssFields2 in checkFields.keys()):
    print("[-] " + xssFields + " FOUND (XSS):" + " SET " + "DEPREACTED")

if (ectFields in checkFields.keys() or ectFields2 in checkFields.keys()):
    print( "[-] " + ectFields + " FOUND (ECT):" + " SET " + "DEPREACTED")

if (serFields not in checkFields.keys() or serFields2 not in checkFields.keys()):
    print("[-]" + " Security " + serFields + " Header (SVR): " + "SET")
    print(" |=> " + "[" + "OSINT INFO" + "] " + "Data Leakage" + " " + "MISCONFIGURATION FOUND")
else:
    print("[+] " + "Security " + serFields + " Header (SVR): " + "NOT SET")

if (xpowFields in checkFields.keys() or xpowFields2 in checkFields.keys()):
    print("[-]" + " Security " + xpowFields + " Header (XPOW): " + "SET")
    print(" |=> " + "[" + "OSINT INFO" + "] " + " " + "MISCONFIGURATION FOUND")

print("\n PROCESSING COMPLETED")
print('|~~>>>**********<<<--|\n')
