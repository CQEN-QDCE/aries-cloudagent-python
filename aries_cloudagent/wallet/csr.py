from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization 
from cryptography.hazmat.primitives.asymmetric import rsa


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