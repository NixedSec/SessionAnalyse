#!/usr/bin/env python3

#SessionAnalyse.py v0.2
#NixedSec

from sys import argv
import requests
from math import log2

IDlenMin = 0
IDlenMax = 0
characters = []
IDs = []
dupeIDs = []
header = { "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:10.0) Gecko/20100101 Firefox/108.0" }
count = 1000



def help():
    print('''SessionAnalyse is a tool to analyse a Session ID/cookie for potential weakness.
    The tool will attempt to work out its length(min, max), entropy, characters used and notify any repeated IDs.
    
    The default number of tests is 1000, though this can be set.
    The User-Agent can optionally be set if it is included in quotes: "USERAGENT"
    
    Use: SessionAnalyse SITE SESSIONCOOKIE COUNT(Optional) "USERAGENT"(Optional)
    ''')


def entropy():
    #log2(NumberOfCharacters^(LengthOfString))
    #https://en.wikipedia.org/wiki/Password_strength
    #Section: Random passwords
    #https://wikimedia.org/api/rest_v1/media/math/render/svg/d30dfce3e0cd67b4fc5b4410cd7d0d5e89781f6d
    
    
    ent = log2(pow(len(characters), IDlenMax))
    if (IDlenMax != IDlenMin):
        print ("Entropy of a " + str(IDlenMax) + " character ID is: " + str(ent) + " bits")
        
        ent = log2(pow(len(characters), IDlenMin))
        print ("Entropy of a " + str(IDlenMin) + " character ID is: " + str(ent) + " bits")
        
    else:
        print ("Entropy of a " + str(IDlenMax) + " character ID is: " + str(ent) + " bits")
        

def analyse(site, cookie):
    global IDlenMax
    global IDlenMin
    global characters
    global IDs
    global dupeIDs
    
    
    print("Site: " + site)
    print("Session ID: " + cookie)
    for i in range (0, count):
        r = requests.get(site, header)
        for item in r.headers.items():
            if (item[0] == "Set-Cookie"):
                if (cookie == item[1].split(';')[0].split('=')[0]):
                    value = item[1].split(';')[0].split('=')[1]
                    if not (value) in IDs:
                        IDs.append(value)
                    else:
                        print ("Duplicate ID: " + value)
                        print ("ID number: " + i)
                        dupeIDs.append(value)
                        
                    for character in value:
                        if not (character in characters):
                            characters.append(character)
                    
                    if (len(value) > IDlenMax):
                        IDlenMax = len(value)
                                         
                    if (i == 0): #set to initial size
                        IDlenMin = IDlenMax   
                        
                    if (len(value) < IDlenMin):
                        IDlenMin = len(value)
                        
    if (len(IDs) == 0):
        print ("Session ID not found, please ensure it the values are correct.")
    else:
        
        if (IDlenMax != IDlenMin):
            print ("\nShortest ID: " + str(IDlenMin))
            print ("\nLongest ID: " + str(IDlenMax))
        else:
            print ("\nID length: " + str(IDlenMax))
        
        print ("Number of characters in use: " + str(len(characters)))
        print ("Characters: " + str(sorted(characters)))
        
        if (len(dupeIDs) > 0):
            print ("Duplcate ID count: " + str(len(dupeIDs)))
            print ("Duplcate IDs: ")
            for dupe in dupeIDs:
                print (dupe)    
        else:
            print ("No duplicate IDs found in a set of " + str(count))     
        
        entropy()         


def start():
    global header
    global count
    try:
        site = argv[1]
        cookie = argv[2]
        
        if (len(argv) > 3):
            count = int(argv[3])
            
        if (len(argv) > 4):
            header["User-Agent"] = argv[4]
        
        analyse(site, cookie)
        
    except:
        help()
        raise SystemExit
    

start()
