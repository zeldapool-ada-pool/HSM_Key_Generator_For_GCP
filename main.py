import base64
import base58
import textwrap
import pytezos
import subprocess
import ecdsa
import os
from ecdsa.keys import VerifyingKey
from ecdsa.curves import NIST256p
import sys, getopt
from pytezos.encoding import base58_decode
from pytezos import Key
import tempfile
verbose = False

def generatekey():

    # Create the key in raw PEM form
    newkey = Key.generate(curve=b'p2', export=True)
    secret_key=base58_decode(bytes(newkey.secret_key(),"UTF-8")).hex()
    header1="30"
    header2="0201010420"
    footer="A00A06082A8648CE3D030107A144034200"
    public_key=base58.b58decode_check(newkey.public_key())[4:].hex()
    public_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=NIST256p)
    pub_key = public_key.to_string('uncompressed')
    debug('full length is '+ str(len(header2+secret_key+footer+footer+pub_key.hex())))
    fulllen = hex(int(len(header2+secret_key+footer+pub_key.hex())/2))[2:]
    debug(header2+secret_key+footer+footer+pub_key.hex())
    fullhexkey=header1+fulllen+header2+secret_key+footer+pub_key.hex()
    priv_keyb64=str(base64.b64encode(base64.b16decode(fullhexkey,casefold=True)))
    linelist=textwrap.wrap(priv_keyb64[2:len(priv_keyb64)-1],64)

    # If verbose mode then print out the details of the key
    debug('Hash Before B64 Encoding:' + fullhexkey)
    debug('Full length of file is' + fulllen)
    debug('Secret key:' + secret_key)
    debug('Public key:' + str(pub_key.hex()))
    debug('Public key len:' + str((len(pub_key.hex()))))
    debug('Secret key len:' + str((len(secret_key))))
    debug('Secret key len (hex):' + hex((len(secret_key))))
    debug('Public key:' + str(pub_key.hex()))
    debug('Base64:' + priv_keyb64)
    debug(linelist)

    # Temporary file to write the raw key to
    fd, path = tempfile.mkstemp()

    # Try / Finally Block is a safe way of creating a temp file that is cleaned on an ungraceful exit
    try:
        with os.fdopen(fd, 'w') as f:
            # Write the raw key to file
            debug ('Created temp file '+path)
            f.write("-----BEGIN EC PRIVATE KEY-----\n")
            for x in linelist:
                f.write(x+"\n")
            f.write("-----END EC PRIVATE KEY-----\n")
            f.close()

            TARGET_KEY = 'tmp.pkcs8'

            # Print out the command for making the base directory
            debug('Creating base directory: mkdir -m 700 -p +' + BASE_DIR)
            os.system('mkdir -m 700 -p ' + BASE_DIR)
            debug(opensslpath + ' pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ' + path +' -out ' + BASE_DIR + '/' + TARGET_KEY)
            os.system(opensslpath + ' pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in ' + path + ' -out ' + BASE_DIR + '/' + TARGET_KEY)
    finally:
        os.remove(path)

    debug('Wrote temp key to ' + BASE_DIR + '/' + TARGET_KEY)

    # Set up the various filenames and paths for wrapping the key
    PUB_WRAPPING_KEY = keywrapperpath
    TEMP_AES_KEY = BASE_DIR + '/temp_aes_key.bin'
    TEMP_AES_KEY_WRAPPED = BASE_DIR + '/temp_aes_key_wrapped.bin'
    TARGET_KEY_WRAPPED = BASE_DIR + '/target_key_wrapped.bin'
    RSA_AES_WRAPPED_KEY = '/tmp/wrapped-target-key.bin'

    # Old section - we were getting the key from gcp automatically but we actually want to take it from a local file (i.e. manually downloaded, whcih is compatible with the approach
    # Verbose print out of the GCloud KMS call
    #debug('gcloud kms import-jobs describe ' + importjob + ' --location global --keyring ' + keyring + ' --format="value(state)"')
    #debug('gcloud kms import-jobs describe --location=global --keyring='+ keyring +' --format="value(publicKey.pem)" '+ importjob + ' > ' + BASE_DIR + '/' + PUB_WRAPPING_KEY)
    # Call out for GCloud KMS SDK to describe the jobs and then output to a temporary wraping key
    #result = os.system('gcloud kms import-jobs describe ' + importjob + ' --location global --keyring '+ keyring + ' --format="value(state)"')
    #result = os.system('gcloud kms import-jobs describe --location=global --keyring='+ keyring +' --format="value(publicKey.pem)" '+ importjob + ' > ' + BASE_DIR + '/' + PUB_WRAPPING_KEY)


    # Verbose print out of variables being marshalled
    debug('Making folder for wrapped AES keys : mkdir -m u+wx -p ' + BASE_DIR + RSA_AES_WRAPPED_KEY)
    debug("PUB_WRAPPING_KEY: " + PUB_WRAPPING_KEY)
    debug("TARGET_KEY: " + TARGET_KEY)
    debug("BASE_DIR: " + BASE_DIR)
    debug("TEMP_AES_KEY_WRAPPED: " + TEMP_AES_KEY_WRAPPED)
    debug("RSA_AES_WRAPPED_KEY: " + RSA_AES_WRAPPED_KEY)
    debug('mkdir -m u+wx -p ' + BASE_DIR + RSA_AES_WRAPPED_KEY)
    os.system('mkdir -m u+wx -p ' + BASE_DIR + RSA_AES_WRAPPED_KEY)
    debug('Generating key and encrypting')
    debug(opensslpath + ' rand -out '+ TEMP_AES_KEY + ' 32')
    debug(opensslpath + ' rsautl -encrypt -pubin -inkey '+  PUB_WRAPPING_KEY + ' -in '+TEMP_AES_KEY + ' -out ' + TEMP_AES_KEY_WRAPPED +  ' -oaep')
    os.system(opensslpath + ' rand -out '+ TEMP_AES_KEY + ' 32')
    os.system(opensslpath + ' rsautl -encrypt -pubin -inkey '+  PUB_WRAPPING_KEY + ' -in '+TEMP_AES_KEY + ' -out ' + TEMP_AES_KEY_WRAPPED +  ' -oaep')
    debug(opensslpath +' enc -id-aes256-wrap-pad -iv A65959A6 -K $( hexdump -v -e \'/1 "%02x"\' < ' + TEMP_AES_KEY + ' ) -in '+ BASE_DIR + '/' + TARGET_KEY +' -out '+ TARGET_KEY_WRAPPED)
    os.system(opensslpath +' enc -id-aes256-wrap-pad -iv A65959A6 -K $( hexdump -v -e \'/1 "%02x"\' < ' + TEMP_AES_KEY + ' ) -in '+ BASE_DIR + '/' + TARGET_KEY +' -out '+ TARGET_KEY_WRAPPED)
    os.system('cat ' + TEMP_AES_KEY_WRAPPED + ' ' + TARGET_KEY_WRAPPED + '> ' + outputfile)
    os.system('rm -f -r ' + BASE_DIR)
    debug('cat ' + TEMP_AES_KEY_WRAPPED + ' ' + TARGET_KEY_WRAPPED + '> ' + outputfile)
    debug('rm -f -r ' + BASE_DIR)
    debug('Key has been wrapped. File is available at ' + outputfile)
    return outputfile

def importkey(keytoimport):
    debug('gcloud kms keys versions import --import-job ' + importjob +' --location global  --keyring ' + keyring + ' --key '+ keyname +' --algorithm ec-sign-p256-sha256  --rsa-aes-wrapped-key-file '+ keytoimport)
    os.system('gcloud kms keys versions import --import-job ' + importjob +' --location global  --keyring ' + keyring + ' --key '+ keyname +' --algorithm ec-sign-p256-sha256  --rsa-aes-wrapped-key-file '+ keytoimport)

def parseargs(argv):
    opts, args = getopt.getopt(sys.argv[1:], "o:p:f:k:n:i:w:vmg", ["--genkey", "--out=","--opensslpath","--keyring","--keyname", "--keyfilepath", "--importjob", "--genkey", "--wrappedkeypath","--importkey", "--verbose"])
    global verbose, importjob, keyring, opensslpath, outputfile, keyname, optype,genkey,importkeytocloud,suppliedkeyfilepath,keywrapperpath,genkey
    genkey=False
    importkeytocloud=False
    suppliedkeyfilepath=''
    generatedkey=''

    for opt, value in opts:
        if (opt == "-v") or (opt == "--verbose"):
            verbose = True
        elif (opt == "-k") or (opt == "--keyring"):
            keyring = str(value)
        elif (opt == "-i") or (opt == "--importjob"):
            importjob = str(value)
        elif (opt == "-p") or (opt == "--opensslpath"):
            opensslpath = str(value)
        elif (opt == "-o") or (opt == "--out"):
            outputfile = str(value)
        elif (opt == "-n") or (opt == "--keyname"):
            keyname = str(value)
        elif (opt == "-g") or (opt == "--genkey"):
            genkey = True
        elif (opt == "-m") or (opt == "--importkey"):
            importkeytocloud = True
        elif (opt == "-f") or (opt == "--keyfilepath"):
            suppliedkeyfilepath = str(value)
        elif (opt == "-w") or (opt == "--wrappedkey"):
            keywrapperpath = str(value)

    debug('Verbose mode is ' + str(verbose))
    debug('Keyring  is ' + keyring)
    debug('Import job  is ' + importjob)
    # debug('Import to cloud is' + importkeytocloud)
    # debug('Path to key wrrapper is' + keywrapperpath)


def debug(message):
    if verbose == True:
        print(message)

if __name__ == "__main__":
   parseargs(sys.argv[1:])

   global BASE_DIR
   BASE_DIR = '/tmp/wrap_tmp'

   # Generate the keys in PKCS8 format and return the path to them
   if genkey==True:
       debug("Generating pkcs8 format key")
       generatedkey = generatekey()
       debug("Path to generated key " + generatedkey)

   if suppliedkeyfilepath=='':
        suppliedkeyfilepath = generatedkey

   if importkeytocloud==True:
       importkey(suppliedkeyfilepath)
