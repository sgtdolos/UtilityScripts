import ssl
import OpenSSL
import socket
import time
from tkinter import *
from tkinter.filedialog import askopenfilename
import csv
import datetime
import os

Tk().withdraw()

#Ask for file containing list of URLs to check
print("\nSelect file with list of URLs: ")
url_list = askopenfilename()

#Open URL list file and split into separate lines 
with open(url_list, "r") as f:
    urls = f.read().splitlines()
f.close()

print('=' * 40)

#Function to get the SSL Certificate info
def get_cert_info(host, port=443):
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=host,
    )
    # 3 second timeout because Lambda has runtime limitations
    conn.settimeout(3.0)
    conn.connect((host, port))
    ssl_info = conn.getpeercert()
    
    return ssl_info

#Build output file name	
timestr = time.strftime("%Y%m%d-%H-%M-%S")
out_file = 'cert_check_' + timestr + '.csv'

#Open output file results will be written to
with open(out_file, 'w', newline="") as csvfile:
    #Build CSV headings
    fieldnames = ['URL', 'Subject', 'Issuer', 'Serial', 'Issued Date', 'Expiration Date']
    #Write CSV headings
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    #Loop over URLs
    for url in urls:
        try:
            #Build date format for Issued and Expiration dates
            ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'        
            #Get certificate info from URL
            cert_info = get_cert_info(url)
            
            #Loop over subject tuple and create subject dictionary
            subject = dict(x[0] for x in cert_info['subject'])
            #Create Subject CN variable
            issued_to = subject['commonName']
            #Loop over issuer tuple and create issuer dictionary
            issuer = dict(x[0] for x in cert_info['issuer'])
            #Create Issuer CN variable
            issued_by = issuer['commonName']
            #Pull serial in to variable
            serial = cert_info['serialNumber']
            issue_date = datetime.datetime.strptime(cert_info['notBefore'], ssl_date_fmt)
            valid = str(issue_date)
            cert_exp = datetime.datetime.strptime(cert_info['notAfter'], ssl_date_fmt)
            cert_expir= str(cert_exp)
            info_dict = {'URL' : url , 'Subject' : issued_to, 'Issuer': issued_by, 'Serial': serial, 'Issued Date': valid, 'Expiration Date': cert_expir}
            
            #Uncomment print statement below to print dictionary to be written to csv, useful if output info isn't as expected
            #print(info_dict)            
            
            #Write certificate info to CSV
            writer.writerow(info_dict)
            
            print(url + ' - completed successfully!')
            #print("=" * 40)
        except Exception as e:
            print(url + " - " + str(e))
            continue

print('=' * 40)
cwd = os.getcwd()
savepath = cwd + out_file
print("SSL Certificate info saved to ", savepath)