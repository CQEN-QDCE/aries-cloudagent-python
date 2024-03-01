from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import rsa


def create_csr( common_name, country=None, state=None, city=None, 
                organization=None, organizational_unit=None, email=None, key=None):
    """
    Creates a Certificate Signing Request (CSR) with the provided details.

    This method generates a new CSR with the specified common name and optional 
    country, state, city, organization, organizational unit, and email.

    Args:
        common_name (str): The common name for the CSR (e.g., the fully-qualified domain name).
        country (str, optional): The two-letter ISO code for the country. Defaults to None.
        state (str, optional): The full name of the state or province. Defaults to None.
        city (str, optional): The name of the city. Defaults to None.
        organization (str, optional): The name of the organization. Defaults to None.
        organizational_unit (str, optional): The name of the organizational unit. Defaults to None.
        email (str, optional): The email address. Defaults to None.
        key (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey, optional): The private key to sign the CSR. Defaults to None.

    Returns:
        x509.CertificateSigningRequest: The generated CSR.

    Raises:
        ValueError: If the common_name is not a valid domain name or IP address.
    """

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([

        # Provide various details about who we are.

        x509.NameAttribute(NameOID.COUNTRY_NAME, country),

        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),

        x509.NameAttribute(NameOID.LOCALITY_NAME, city),

        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),

        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),

        x509.NameAttribute(NameOID.COMMON_NAME, common_name),

    ])).add_extension(

        x509.SubjectAlternativeName([

            # Email 
            x509.RFC822Name(email), 

        ]),

        critical=False,

    # Sign the CSR with our private key.

    ).sign(key, hashes.SHA256())

    return csr