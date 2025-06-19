#! /usr/bin/python

import requests
import sys



def protocol(link):
    if "https://" in link:
        return(link.strip())
    elif "http://" in link:
        return(link.strip())
    else:
        url2="https://"+link
        return(url2.strip())

def poc(site,raw):
    print("[*] Generating POC")
    code = '<!DOCTYPE html>\n<html> \n <head><title>Clickjack test page</title></head> \n <body> \n <p>Website is vulnerable to clickjacking!</p> \n <p><b>X-Frame-Options: None </b></p> \n <iframe id="myIframe" sandbox="allow-forms allow-scripts" src="{}" width="500" height="500"></iframe> \n </body> \n</html>'.format(site)
    flnm=''.join(letter for letter in raw if letter.isalnum())
    filename=flnm+".html"
    h1=filename.replace("https","")
    with open(h1, "w") as file:
        file.write(code)
        file.close()
    print("[#] POC have been saved\n\n")

def main():
    
        b=sys.argv[1]
        a=open(b,"r").readlines()
        for i in a:        
            new=protocol(i)
            print("[$] URL "+new)
            try:
                res=requests.get(new,verify=False)
                
                if not "X-Frame-Options" in res.headers:
                    if not 'Content-Security-Policy' in res.headers:
                        print("[+] Possibly vulnerable")
                        poc(new,i)
                    elif 'Content-Security-Policy' in res.headers:
                        directives = res.headers.get('Content-Security-Policy').split(';')
                        for directive in directives:
                            if 'frame-ancestors' in directive:
                                print("[C] Content-Security-Policy: frame-ancestors script detected\n\n")
                else:
                    print("[-] Not vulnerable\n\n")
            except requests.exceptions.RequestException as e:
                print(f"An error occurred: {e}")



if __name__=='__main__':
    main()
