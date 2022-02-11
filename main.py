import base64
import base58
import textwrap
import pytezos
import ecdsa
import os
from ecdsa.keys import VerifyingKey
from ecdsa.curves import NIST256p
import sys, getopt
from pytezos.encoding import base58_decode
from pytezos import Key
verbose=False
outputfile=''

def generateKey():
    newkey = Key.generate(curve=b'p2', export=True)
    secret_key=base58_decode(bytes(newkey.secret_key(),"UTF-8")).hex()
    header1="30"

    header2="0201010420"
    footer="A00A06082A8648CE3D030107A144034200"
    #public_key=base58.b58decode_check(newkey.public_key()).hex()
    public_key=base58.b58decode_check(newkey.public_key())[4:].hex()
    public_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=NIST256p)
    pub_key = public_key.to_string('uncompressed')
    print('full length is '+ str(len(header2+secret_key+footer+footer+pub_key.hex())))
    fulllen = hex(int(len(header2+secret_key+footer+pub_key.hex())/2))[2:]

    print(header2+secret_key+footer+footer+pub_key.hex())
  #  fulllen=hex(len(header2+secret_key+footer+pub_key.hex())/2)[2:]

    fullhexkey=header1+fulllen+header2+secret_key+footer+pub_key.hex()
    priv_keyb64=str(base64.b64encode(base64.b16decode(fullhexkey,casefold=True)))
    linelist=textwrap.wrap(priv_keyb64[2:len(priv_keyb64)-1],64)

    if verbose==True:
        print('Hash Before B64 Encoding:' + fullhexkey)
        print('Full length of file is' + fulllen)
        print('Writing to:'+outputfile)
        print('Secret key:' + secret_key)
        print('Public key:' + str(pub_key.hex()))
        print('Public key len:' + str((len(pub_key.hex()))))
        #print('Public key len (hex):' + hex((len(pub_key.hex()))))
        print('Secret key len:' + str((len(secret_key))))
        #print('Secret key len (hex):' + hex((len(secret_key))))
        print('Public key:' + str(pub_key.hex()))
        print('Base64:' + priv_keyb64)


    print(linelist)
    f=open(outputfile,"w")
    f.write("-----BEGIN EC PRIVATE KEY-----\n")
    for x in linelist:
        f.write(x+"\n")
    f.write("-----END EC PRIVATE KEY-----\n")
    f.close()
    os.system('openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ' + outputfile +' -out ' +outputfile +'pkcs8')

def parseargs(argv):
    opts, args = getopt.getopt(sys.argv[1:], "o:v", ["outputfile=", "verbose"])
    global verbose, outputfile
    for opt, value in opts:
        if (opt == "-o") or (opt == "--output"):
            outputfile = str(value)
        elif (opt == "-v") or (opt == "--verbose"):
            verbose = True

    print('output file is '+outputfile)
    print('Verbose mode is '+str(verbose))

if __name__ == "__main__":
   parseargs(sys.argv[1:])
   generateKey()


