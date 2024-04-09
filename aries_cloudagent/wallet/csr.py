from   cryptography import x509
from   cryptography.x509.oid import NameOID
from   cryptography.hazmat.primitives.asymmetric.ec import hashes
from   cryptography.hazmat.primitives.asymmetric import ec
from   cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Supported elliptic curves
CURVE_P256      = "P256"
CURVE_P384      = "P384"
CURVE_P521      = "P521"
CURVE_ED25519   = "Ed25519"

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


def generateKeyPair(curveName: str):
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
    keyPair = None

    if   curveName.casefold() == CURVE_P256.casefold():
         keyPair =   ec.generate_private_key(ec.SECP256R1())
    elif curveName.casefold() == CURVE_P384.casefold():
         keyPair =   ec.generate_private_key(ec.SECP384R1())
    elif curveName.casefold() == CURVE_P521.casefold():
         keyPair =   ec.generate_private_key(ec.SECP521R1())
    elif curveName.casefold() == CURVE_ED25519.casefold():
         keyPair =   Ed25519PrivateKey.generate()
    else:
        print("Unsupported curve name. Supported curve names are P256, P384, P521 and Ed25519.")
        return None

    return keyPair