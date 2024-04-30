from   cryptography                                 import x509
from   cryptography.x509.oid                        import NameOID
from   cryptography.hazmat.primitives.asymmetric.ec import hashes
from   cryptography.hazmat.primitives               import serialization
from   cryptography.hazmat.primitives.asymmetric    import ec
from   jwt                                          import InvalidSignatureError

# Supported hashing algorithms
HASH_SHA256     = "SHA256"
HASH_SHA384     = "SHA384"
HASH_SHA512     = "SHA512"

def create_csr( common_name, 
                country="CA", 
                state=None, 
                city=None, 
                organization=None, 
                organizational_unit=None, 
                email=None, 
                key=None):
    """
    Creates a Certificate Signing Request (CSR) with the provided details.

    This method generates a new CSR with the specified common name and optional 
    country, state, city, organization, organizational unit, and email.

    Args:
        common_name (str)                                   : The common name for the CSR (e.g., the fully-qualified domain name). This attribute is required.
        country (str, optional)                             : The two-letter ISO code for the country. Defaults to None.
        state (str, optional)                               : The full name of the state or province. Defaults to None.
        city (str, optional)                                : The name of the city. Defaults to None.
        organization (str, optional)                        : The name of the organization. Defaults to None.
        organizational_unit (str, optional)                 : The name of the organizational unit. Defaults to None.
        email (str, optional)                               : The email address. Defaults to None.
        key (cryptography.hazmat.primitives.asymmetric.ec)  : The private key to sign the CSR. Defaults to None. This attribute is required.
    Returns:
        x509.CertificateSigningRequest                      : The generated CSR.

    Raises:
        ValueError                                          : If the common_name is not a valid identification name, domain name or IP address.
    """

    if not common_name:
        raise ValueError("A Common Name is required")
    
    # Provide various details about who we are, to build a distinguished name fields.
    # Create the optional attributes for the CSR if they are provided. 
    # At the end, add the mandatory common name.
    attributes = []

    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))

    if state:
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))

    if city:
        attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))

    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    if organizational_unit:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))

    # Add the mandatory common name attribute to the CSR
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    
    # Add the extensions values to the CSR
    extensions = []

    if email:
        extensions.append(x509.RFC822Name(email))

    # Create the CSR builder with the provided details.
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attributes))

    # Add the extensions to the CSR if they are provided.
    if len(extensions) > 0:
        csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(extensions), critical=False)

    csr_builder = csr_builder.sign(key, hashes.SHA256())

    return csr_builder


def serializeCSR(csr, csrFileName):
    """
    This function serializes a CSR and writes it to a file.

    Parameters:
    csr : The CSR to be serialized.

    Returns:
    None: The function's main purpose is to write to a file and not to return any value.
    """
    csr_enc = csr.public_bytes(
        encoding=serialization.Encoding.PEM
    )

    with open(csrFileName, "wb") as f:
        f.write(csr_enc)
        f.close()

    return None


def sign(payload, hashAlg, privKey):
    """
    This function signs a message using a private key.

    Parameters:
    payload : The message to be signed.
    hashAlg : The hash algorithm used to hash the message. Valid values are SHA256, SHA384, SHA512.
    privKey : The private key to be used to sign the message.

    Returns:
    signature : The signature of the message. The signature is PEM encoded for results transmission. 
    """

    if isinstance(payload, str):
        print("payload is a string")
        payload = payload.encode()
    else: 
        print("payload is not a string")

    # Check the signature algorithm and set the appropriate algorithm
    if hashAlg.casefold() == HASH_SHA256.casefold():
        hashAlg = ec.ECDSA(hashes.SHA256())
    elif hashAlg.casefold() == HASH_SHA384.casefold():
        hashAlg = ec.ECDSA(hashes.SHA384())
    elif hashAlg.casefold() == HASH_SHA512.casefold():
        hashAlg = ec.ECDSA(hashes.SHA512())
    else:   
        print("Unsupported signature algorithm. Supported algorithms are SHA256, SHA384, SHA512.")
        return None
    
    signature = privKey.sign(
        payload,
        hashAlg
    )
    return signature

def verify(payload, signature, hashAlg, pubKey):
    """
    This function verifies a signature.

    Parameters:
    payload : The message to be verified.
    signature : The signature to be verified. It should be PEM encoded.
    hashAlg : he hash algorithm used to hash the message. Valid values are SHA256, SHA384, SHA512.
    pubKey : The public key used to verify the signature.

    Returns:
    boolean : True if the signature is valid, False otherwise.
    """

    if isinstance(payload, str):
        payload = payload.encode()

    # Check the signature algorithm and set the appropriate algorithm
    if hashAlg.casefold() == HASH_SHA256.casefold():
        hashAlg = ec.ECDSA(hashes.SHA256())
    elif hashAlg.casefold() == HASH_SHA384.casefold():
        hashAlg = ec.ECDSA(hashes.SHA384())
    elif hashAlg.casefold() == HASH_SHA512.casefold():
        hashAlg = ec.ECDSA(hashes.SHA512())
    else:   
        print("Unsupported signature algorithm. Supported algorithms are SHA256, SHA384, SHA512.")
        return None

    try:
        pubKey.verify(
            signature,
            payload,
            hashAlg
        )
    except InvalidSignatureError:
        return False
    except Exception as e: 
        return False

    return True
