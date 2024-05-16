import base64
from aries_askar import Key, KeyAlg
import base58
import hashlib
from   cryptography                                 import x509
from   cryptography.x509.oid                        import NameOID
from   cryptography.hazmat.primitives.asymmetric.ec import hashes
from   cryptography.hazmat.primitives.asymmetric    import ec
from   cryptography.hazmat.primitives               import serialization
from   jwt                                          import InvalidSignatureError

from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.did_info import DIDInfo
from ..config.injection_context import InjectionContext

# Supported elliptic curves
CURVE_P256      = "P256"
CURVE_P384      = "P384"
CURVE_P521      = "P521"
# CURVE_ED25519   = "Ed25519"

# Supported hashing algorithms
HASH_SHA256     = "SHA256"
HASH_SHA384     = "SHA384"
HASH_SHA512     = "SHA512"

EC_CURVE_NAMES = {
    256: "P-256",
    384: "P-384",
    521: "P-512",
}
SIGNING_ALGORITHMS = {
    256: "ES256",
    384: "ES384",
    521: "ES512",
}


def generateKeyPairSeed(curveName: KeyAlg, seed: bytes):

    key = Key.from_seed(curveName, seed) 
    #private_key_bytes = hashlib.sha256(seed).digest()
    #private_key_number = int.from_bytes(private_key_bytes, "big")

    #return ec.derive_private_key(private_key_number, ec.SECP256R1())
    return key 

def generateKeypair(curveName: str):
    """
    Generates a key pair using the specified algorithm.

    This function generates a public and private key pair using the algorithm specified by the curveName parameter.

    Args:
        curveName (str): The name of the key generation algorithm to use. 
        This should be a string representing a valid supported elliptic curve, such as 'P256', 'P384', 'P521' or 'Ed25519'.

    Returns:
        tuple: A tuple containing the generated private and public keys, in that order.

    Raises:
        ValueError: If the curveName parameter is not a recognized key generation algorithm.
    """
    keypair = None

    if   curveName.casefold() == CURVE_P256.casefold():
         keypair =   ec.generate_private_key(ec.SECP256R1())
    elif curveName.casefold() == CURVE_P384.casefold():
         keypair =   ec.generate_private_key(ec.SECP384R1())
    elif curveName.casefold() == CURVE_P521.casefold():
         keypair =   ec.generate_private_key(ec.SECP521R1())
    #elif curveName.casefold() == CURVE_ED25519.casefold():
    #     keypair =   Ed25519PrivateKey.generate()
    else:
        print("Unsupported curve name. Supported curve names are P256, P384, P521.") # and Ed25519
        return None

    return keypair


def keyFingerprint(pubkey):
    """
    This function generates a fingerprint for a given public key.

    Args:
        pubkey (PublicKey): The public key for which to generate a fingerprint.

    Returns:
        str: The SHA-256 hash of the DER-encoded public key, represented as a hexadecimal string.

    The function first serializes the public key into DER format. DER (Distinguished Encoding Rules) 
    is a binary format for data structures described by ASN.1. After serialization, it computes the 
    SHA-256 hash of the serialized key to generate a unique fingerprint.
    """
    der = pubkey.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()

def getVerkey(bytes):
    """
    This function returns the verification key of a given keypair.

    Args:
        keypair (EllipticCurvePrivateKey): The keypair for which to retrieve the verification key.

    Returns:
        EllipticCurvePublicKey: The verification key of the keypair.
    """
    return base58.b58encode(bytes).decode("utf-8")


def convertKey(pubkey, **options):
    """
    This function converts a public key into a dictionary containing its components.

    Args:
        pubkey (PublicKey): The public key to convert.
        **options: Additional options for the conversion.

    Returns:
        dict: A dictionary containing the key type ('kty'), curve name ('crv'), and the x and y 
              coordinates of the public key.

    The function first retrieves the public numbers of the key, which include the x and y coordinates 
    and the curve. It then converts these numbers into bytes and encodes them in base64 format. The 
    result is a dictionary that represents the public key in a more accessible format.
    """
    numbers = pubkey.public_numbers()
    size = (numbers.curve.key_size + 7) // 8    # ====================>>>> 
    x = numbers.x.to_bytes(size, "big")
    y = numbers.y.to_bytes(size, "big")
    return {
        "kty": "EC",
        "crv": EC_CURVE_NAMES[numbers.curve.key_size],
        "x": base64.urlsafe_b64encode(x).decode("ascii"),
        "y": base64.urlsafe_b64encode(y).decode("ascii"),
        **options,
    }


def serializePair(pubKey, pubkeyFileName, privKey, privkeyFileName):
    """
    This function serializes a public and private key pair and writes them to files.

    Parameters:
    pubKey : The public key to be serialized.
    pubkeyFileName : The name of the file where the serialized public key will be written.
    privKey : The private key to be serialized.
    privkeyFileName : The name of the file where the serialized private key will be written.

    Returns:
    tuple: A tuple containing None values, as the function's main purpose is to write to files and not to return any value.
    """
    return serializePubKey(pubKey, pubkeyFileName), serializePrivKey(privKey, privkeyFileName)


def serializePrivKey(privKey, privkeyFileName):
    """
    This function serializes a private key and writes it to a file.

    Parameters:
    privKey : The private key to be serialized.
    privkeyFileName : The name of the file where the serialized private key will be written.

    Returns:
    None: The function's main purpose is to write to a file and not to return any value.
    """
    privKey_enc = privKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(privkeyFileName, "wb") as f:
        f.write(privKey_enc)
        f.close()


def serializePubKey(pubKey, pubkeyFileName):
    """
    This function serializes a public key and writes it to a file.

    Parameters:
    pubKey : The public key to be serialized.
    pubkeyFileName : The name of the file where the serialized public key will be written.

    Returns:
    None: The function's main purpose is to write to a file and not to return any value.
    """
    pubkey_enc = pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(pubkeyFileName, "wb") as f:
        f.write(pubkey_enc)
        f.close()

    return None

def deserializePrivKey(privkeyFileName):
    """
    This function deserializes a private key from a file.

    Parameters:
    privkeyFileName : The name of the file where the serialized private key is stored.

    Returns:
    cryptography.hazmat.primitives.asymmetric.ec : The deserialized private key.
    """
    with open(privkeyFileName, "rb") as f:
        privKey = serialization.load_pem_private_key(f.read(), password=None)
        f.close()

    return privKey

async def write_did_to_wallet(wallet: BaseWallet, did: str, verkey: str, metadata: dict = None):
    """
    Write a new DID to the wallet.

    Args:
        context (InjectionContext): The context for dependency injection.
        did (str): The new DID to write.
        verkey (str): The verification key associated with the new DID.
        metadata (dict, optional): Metadata to associate with the new DID.
    """
    
    # Get the wallet instance from the context
    # wallet: BaseWallet = await context.inject(BaseWallet)

    # Create a DIDInfo instance
    did_info = DIDInfo(did, verkey, metadata) #, DIDMethod.WEB, KeyType.ED25519)

    # Write the new DID to the wallet
    await wallet.set_did_info(did_info)

 
async def generateDIDDocument(did, keyType, keypair, keyId=None): 

    document = {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}",
                "type": keyType, 
                "publicKey" : convertKey(
                    keypair.public_key(),
                    kid=keyId,
                    alg=SIGNING_ALGORITHMS[256],
                    #alg=SIGNING_ALGORITHMS[keypair.public_key().key_size],
                ),
            }
        ]
    }
    
    return "" 