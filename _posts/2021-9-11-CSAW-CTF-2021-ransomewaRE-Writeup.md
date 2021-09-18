---
layout: post
title: "CSAW CTF 2021: ransomwaRE Writeup"
---

# CSAW CTF 2021: ransomwaRE

```
Help! Your local convenience store is being held for ransom. Apparently this past July 11th a bunch of their documents got encrypted by the "Noes" gang. The business has backups for some of them, but not their flag file. This was the last straw for the manager, who tapped his slush fund and came to you for help rather than pay the ransom. Here are the files they had left in their directory along with the malware and the ransom notice. Can you REcover the flag?
```

For this reverse engineering challenge, part of CSAW CTF 2021, we are given a Windows Portable Executable (PE) file, as well as a zip file containing encrypted and unencrypted pdf files:
```
20180212_113048_Jones_C_ADMI2017_Ransomware.pdf.backup
2020_IC3Report.pdf.backup
9df65cc45479c058ef4a600c1e607fec44d83682db732f077817c58bed47a191.pdf.cryptastic
a25981adfb782d04cccfb2ad66ae8e63ead31f62fb898913f1ec99359f2e1c4b.pdf.cryptastic
cad0b75505847a4792a67bb33ece21ec9c7bd21395ca6b158095d92772e01637.pdf.cryptastic
ea6b505ffded681a256232ed214d4c3b410c8b4f052775eb7e67dcbd5af64e63.pdf.cryptastic
Screenshot_From_Manager.PNG
us-aers-ransomware.pdf.backup
```

It also contains a screenshot from the convenience store manager: 
![Screenshot From Manager]({{ site.baseurl }}/assets/ransomware/csaw2021_ransomware_screenshot.png)

The obvious first step is to open the executable in Ghidra. All of the locally defined functions have had their names stripped, but the program relies heavily on imports from Windows DLLs, notably crypto and HTTP-related functions. The Ghidra decompiler was very useful for this challenge, since these external function calls were the primary areas of interest when understanding the functionality of this program.

![Function Imports]({{ site.baseurl }}/assets/ransomware/imports.png)

The first step was to go through the each of the external function calls in the main function and give any of the interesting parameters or return values meaningful names by renaming the variables in Ghidra. Sometimes you can avoid searching for documentation by hovering your cursor over the function call, revealing a tooltip box with named parameters. 

The first thing of interest that happens in the program's `main` function is the initialization of a `_SYSTEMTIME` struct with by the `GetSystemTime` command. The day of the week, the month, the day, and the year are then copied from the struct into local variables, each of type `uint` (size: 4 bytes). It's important to note the organization of the local time variables in stack memory (seen boxed in red).

![Loading the SYSTIME struct]({{ site.baseurl }}/assets/ransomware/systime.png)

Next, the program calls a series of crypto functions necessary to hash a series of bytes. In this case, it is setting up a hash object for MD5 hashing the four local variables storing the date information. We know that it is using MD5 because of the `0x8003` parameter passed to `CryptCreateHash` (see Microsoft's [ALG_ID](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id) documentation). The address of the `dayofweek` variable is taken and cast to a byte pointer, and passed to the `CryptHashData` function, along with a parameter specifying that `0x10` (16) bytes should be hashed. Because each of the date-related local variables is 4 bytes long and they are adjacent in stack memory, this function is hashing those values as a 16-byte array. 

![Hashing the SYSTIME struct]({{ site.baseurl }}/assets/ransomware/hashtime.png)

This hash value is then parsed into a hexadecimal string representation, and then converted again into a Windows wide-string representation, as seen here in the call to `MultiByteToWideChar`. This wide-string is then passed as the only parameter to the function `FUN_140001e10`.


![Hash conversion to string to wide-string]({{ site.baseurl }}/assets/ransomware/charconversion.png)

### FUN_140001e10

The first thing that I noticed when looking at this function was the HTTP connection and request function calls to `rev.chal.csaw.io:8129`. A quick curl command revealed the following: 
```
$ curl -X GET rev.chal.csaw.io:8129/
<!doctype html>
<html>
  <head>
    <title>Dropper homepage</title>
  </head>
  <body>
    <p>This host is not meant to be visited by humans! Trust us, everything on this server is just old hash.</p>
  </body>
</html>
```

Nothing exciting here, although the part about old hash is interesting. Looking at the call to `WinHttpOpenRequest`, we see that the hashed hex string that was passed as a parameter to this function is also passed as a parameter in this GET request. 

![Requesting the encryptor]({{ site.baseurl }}/assets/ransomware/httprequest.png)

At this point, I decided to write a python script that emulates the behavior of the program by creating an identical byte representation of the four `_SYSTEMTIME` variables' memory layout using the very handy `p32` function from `pwntools`, which packs each of the integers into a 32-bit little-endian array of bytes, and hashing those bytes. I knew what time values to place here because the authors specified that the attack occurred on July 11 of this year. I then appended that hash to the HTTP connection URL for the GET request, and was able to successfully download a large, base64 encoded chunk of data, which I then decoded, revealing a second Portable Executable. 
{% highlight python %}
from pwn import *
from base64 import b64decode
import hashlib
import requests

############################
## PART 1: GET encryptor.exe
############################

# Create _SYSTEMTIME struct values and pack data into C struct form
# https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime
SUNDAY = 0
dayofweek = p32(SUNDAY)
month = p32(7)
year = p32(2021)
day = p32(11)

SYSTIME = dayofweek + month + year + day

# Calculate md5 sum of struct
datehash = hashlib.md5(SYSTIME).hexdigest()

# Download encryptor
r = requests.get(f"http://rev.chal.csaw.io:8129/{datehash}")

exe = b64decode(r.text)

f = open('encryptor.exe', 'wb')
f.write(exe)
{% endhighlight %}

At this point, I moved on to reversing the [encryptor]({{ site.baseurl }}/assets/ransomware/encryptor.exe), although there is still more interesting stuff to see in ransomwaRE.exe, such as the launching of the encryptor process and removal of the encryptor executable once it's execution is complete.

## Reversing the Encryptor

![Setting up directory path]({{ site.baseurl }}/assets/ransomware/dirpath.png)
The first thing that happens in the main function is the retrieval of the USERPROFILE environment variable, which provides the path to the user's Windows home directory. It then concatenates the `SecretCSAWDocuments` directory name to that path. Most interestingly, it calls the `Gin` function, which sets up the AES Cipher information for encrypting files later in the program. Importantly, this function is only called once during the program's execution. It returns a struct with a few pointers to allocated memory filled with pseudorandom bytes, and an `EVP_CIPHER` structure containing the implementation of an `EVP_aes_128_ctr` cipher. 

Next, the main function calls the `sendKey` routine, which uses HTTP libraries to send the cryptographic key, nonce, and a target ID to the dropper server via an HTTP GET query string. Again, this only occurs once. The main function then searches for all PDF files in the aforementioned directory, and passes their full path name to the `inkripshun` function, where an encrypted version of each matching file is created and named after the original file's SHA-256 hash. The original pdf is then deleted. However, the convenience store manager had some backups with a `.pdf.backup` extension that escapes the pattern matching...

![Finding PDF and encrypting them]({{ site.baseurl }}/assets/ransomware/file_encryption.png)

### Lagniappe: Bitwise Fun

Bitwise brain teaser: Can you tell what's going on here? This code pattern occurs in a few different places in the encryptor program.

![Mystery Hex]({{ site.baseurl }}/assets/ransomware/mysteryhex.png)

![Mystery Code]({{ site.baseurl }}/assets/ransomware/codepattern.png)

## Solving the Challenge

At this point, I tried to think of every way possible that I might be able to obtain the symmetric key and nonce, either from the program itself, or from an HTTP endpoint, but all of these roads led nowhere. Finally, I began to wonder if there might be a weakness in their cryptographic implementation. Much googling led me to discover that, in fact, AES CTR stream ciphers do have a weakness: 

![AES CTR Cipher Warning: reusing cryptographic keys and nonces is catastrophic]({{ site.baseurl }}/assets/ransomware/stackoverflow.png)

You should never reuse a key/nonce combination when using AES CTR stream ciphers! The plaintext data is XORed against the ciphertext directly, producing a ciphertext of the exact same length of the original. Furthermore, we can see that for all except one of the encrypted files, we have the plaintext original copy. 

![Backup file hashes vs encrypted file names]({{ site.baseurl }}/assets/ransomware/hashes.png)

We can exploit these conditions in the following way (my apologies to the math people out there for my poor proof) -  We have two encrypted messages that were encrypted using the same XOR symmetric key: 
```
enc1 = msg1 ^ key
enc2 = msg2 ^ key
```

If we XOR the encrypted bytes against each other, we have:
```
enc1 ^ enc2 ⟶ (msg1 ^ key) ^ (msg2 ^ key)
```
And because the XOR operator is associative, this can be reduced to:
```
enc1 ^ enc2 ⟶ msg1 ^ msg2
```
Since we know the plaintext content of one of the encrypted PDFs, we can fully decrypt the flag using the plaintext of another pdf, as seen in the second part of my exploit script:

{% highlight python %}
#####################################
## PART 2: DECRYPT FILES W/ XOR MAGIC
#####################################

msg1_plain = "files/2020_IC3Report.pdf.backup"
msg1_enc = "files/cad0b75505847a4792a67bb33ece21ec9c7bd21395ca6b158095d92772e01637.pdf.cryptastic"
flagciphertext = "files/ea6b505ffded681a256232ed214d4c3b410c8b4f052775eb7e67dcbd5af64e63.pdf.cryptastic"

f1 = open(msg1_enc, 'rb')
f2 = open(flagciphertext, 'rb')
f3 = open(msg1_plain, 'rb')

msg1_enc = f1.read()
flag_enc = f2.read()
msg1_plain = f3.read()

# XOR encrypted pdf with known cleartext against encrypted flag pdf.
blob = xor(msg1_enc, flag_enc)

# XOR the result of the previous operation against the known plaintext to
# obtain the bytes of the encrypted pdf. Trim the results to the length of the
# encrypted flag pdf.
flag = xor(blob, msg1_plain)[:len(flag_enc)]

f = open('flag.pdf', 'wb')
f.write(flag)
f.close(),
{% endhighlight %}

This produces a pdf containing our flag!
![Flag token]({{ site.baseurl }}/assets/ransomware/flag.png)

### Resources
- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR))
- [AES-CTR Cryptography: Reused Key Weakness - HackTheBox Cyber Apocalypse CTF - YouTube](https://www.youtube.com/watch?v=Gtfr1dBGzHg)
