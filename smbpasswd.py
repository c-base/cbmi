import passlib.hash

def lmhash(s):
    return passlib.hash.lmhash.encrypt(s).upper()

def nthash(s):
    return passlib.hash.nthash.encrypt(s).upper()
