"""Operations supporting Mdoc creation and verification."""

import json
import logging
from typing import Any, Mapping, Optional, Union

from marshmallow import fields
from pydid import DIDUrl, Resource, VerificationMethod

from ..core.profile import Profile
from ..messaging.jsonld.error import BadJWSHeaderError, InvalidVerificationMethod
from ..messaging.jsonld.routes import SUPPORTED_VERIFICATION_METHOD_TYPES
from ..messaging.models.base import BaseModel, BaseModelSchema
from ..resolver.did_resolver import DIDResolver
from .default_verification_key_strategy import BaseVerificationKeyStrategy
from .base import BaseWallet
from .key_type import ED25519
from .util import b64_to_bytes, bytes_to_b64

import cryptography
import random
import hashlib
import os
import datetime
import cbor2
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cwt import COSEKey
from pycose.headers import Algorithm, KID
from pycose.keys import CoseKey
from pycose.messages import Sign1Message
from binascii import hexlify, unhexlify

LOGGER = logging.getLogger(__name__)

DIGEST_SALT_LENGTH = 32
CBORTAGS_ATTR_MAP = {"birth_date": 1004, "expiry_date": 1004, "issue_date": 1004}
MDOC_TYPE = "org.iso.18013.5.1.mDL"


def shuffle_dict(d: dict):
    keys = list(d.keys())
    for i in range(random.randint(3, 27)):  # nosec: B311
        random.shuffle(keys)
    return dict([(key, d[key]) for key in keys])


def selfsigned_x509cert(private_key: CoseKey):
    ckey = COSEKey.from_bytes(private_key.encode())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local CA"),
        ]
    )
    utcnow = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ckey.key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow)
        .not_valid_after(utcnow + datetime.timedelta(days=10))
        .sign(ckey.key, None)
    )
    return cert.public_bytes(getattr(serialization.Encoding, "DER"))


class MsoIssuer:
    def __init__(
        self,
        data: dict,
        private_key: CoseKey,
        digest_alg: str = "sha256",
    ):
        self.data: dict = data
        self.hash_map: dict = {}
        self.disclosure_map: dict = {}
        self.digest_alg: str = digest_alg
        self.private_key: CoseKey = private_key

        hashfunc = getattr(hashlib, self.digest_alg)

        digest_cnt = 0
        for ns, values in data.items():
            if not isinstance(values, dict):
                continue
            self.disclosure_map[ns] = {}
            self.hash_map[ns] = {}

            for k, v in shuffle_dict(values).items():
                _rnd_salt = os.urandom(32)
                _value_cbortag = CBORTAGS_ATTR_MAP.get(k, None)

                if _value_cbortag:
                    v = cbor2.CBORTag(_value_cbortag, value=v)

                self.disclosure_map[ns][digest_cnt] = {
                    "digestID": digest_cnt,
                    "random": _rnd_salt,
                    "elementIdentifier": k,
                    "elementValue": v,
                }
                self.hash_map[ns][digest_cnt] = hashfunc(
                    cbor2.dumps(
                        cbor2.CBORTag(
                            24, value=cbor2.dumps(self.disclosure_map[ns][digest_cnt])
                        )
                    )
                ).digest()

                digest_cnt += 1

    def format_datetime_repr(self, dt: datetime.datetime) -> str:
        """Format a datetime object to a string representation"""
        return dt.isoformat().split(".")[0] + "Z"

    def sign(
        self,
        device_key: Union[dict, None] = None,
        valid_from: Union[None, datetime.datetime] = None,
        doctype: str = None,
    ) -> Sign1Message:
        """Sign a mso and returns it in Sign1Message type"""
        utcnow = datetime.datetime.utcnow()
        exp = utcnow + datetime.timedelta(hours=(24 * 365))

        payload = {
            "version": "1.0",
            "digestAlgorithm": self.digest_alg,
            "valueDigests": self.hash_map,
            "deviceKeyInfo": {"deviceKey": device_key},
            "docType": doctype or list(self.hash_map)[0],
            "validityInfo": {
                "signed": cbor2.dumps(
                    cbor2.CBORTag(0, self.format_datetime_repr(utcnow))
                ),
                "validFrom": cbor2.dumps(
                    cbor2.CBORTag(0, self.format_datetime_repr(valid_from or utcnow))
                ),
                "validUntil": cbor2.dumps(
                    cbor2.CBORTag(0, self.format_datetime_repr(exp))
                ),
            },
        }
        _cert = selfsigned_x509cert(self.private_key)
        mso = Sign1Message(
            phdr={
                Algorithm: self.private_key.alg,
                KID: self.private_key.kid,
                33: _cert,
            },
            # TODO: x509 (cbor2.CBORTag(33)) and federation trust_chain support (cbor2.CBORTag(27?)) here
            # 33 means x509chain standing to rfc9360
            # in both protected and unprotected for interop purpose .. for now.
            uhdr={33: _cert},
            payload=cbor2.dumps(payload),
        )
        mso.key = self.private_key
        return mso


def dict_to_b64(value: Mapping[str, Any]) -> str:
    """Encode a dictionary as a b64 string."""
    return bytes_to_b64(json.dumps(value).encode(), urlsafe=True, pad=False)


def b64_to_dict(value: str) -> Mapping[str, Any]:
    """Decode a dictionary from a b64 encoded value."""
    return json.loads(b64_to_bytes(value, urlsafe=True))


def nym_to_did(value: str) -> str:
    """Return a did from nym if passed value is nym, else return value."""
    return value if value.startswith("did:") else f"did:sov:{value}"


def did_lookup_name(value: str) -> str:
    """Return the value used to lookup a DID in the wallet.

    If value is did:sov, return the unqualified value. Else, return value.
    """
    return value.split(":", 3)[2] if value.startswith("did:sov:") else value


async def mdoc_sign(
    profile: Profile,
    headers: Mapping[str, Any],
    payload: Mapping[str, Any],
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
) -> str:
    """Create a signed Mdoc given headers, payload, and signing DID or DID URL."""
    if verification_method is None:
        if did is None:
            raise ValueError("did or verificationMethod required.")

        did = nym_to_did(did)

        verkey_strat = profile.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")
    else:
        # We look up keys by did for now
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        LOGGER.info(f"mdoc sign: {did}")
        did_info = await wallet.get_local_did(did_lookup_name(did))
        key_pair = await wallet._session.handle.fetch_key(did_info.verkey)
        jwk_bytes = key_pair.key.get_jwk_secret()
        jwk = json.loads(jwk_bytes)

        PKEY = {
            "KTY": "OKP",
            "CURVE": "Ed25519",
            "ALG": "EdDSA",
            "D": b64_to_bytes(jwk["d"], True),
            "X": b64_to_bytes(jwk["x"], True),
            "KID": os.urandom(32),
        }
        cose_key = CoseKey.from_dict(PKEY)
        if isinstance(payload, dict):
            data = [{"doctype": MDOC_TYPE, "data": payload}]
        documents = []
        for doc in data:
            msoi = MsoIssuer(data=doc["data"], private_key=cose_key)
            mso = msoi.sign()
            document = {
                "docType": MDOC_TYPE,
                "issuerSigned": {
                    "nameSpaces": {
                        ns: [cbor2.CBORTag(24, value={k: v}) for k, v in dgst.items()]
                        for ns, dgst in msoi.disclosure_map.items()
                    },
                    "issuerAuth": mso.encode(),
                },
                # this is required during the presentation.
                #  'deviceSigned': {
                #  # TODO
                #  }
            }
            documents.append(document)

        signed = {
            "version": "1.0",
            "documents": documents,
            "status": 0,
        }
        signed_hex = hexlify(cbor2.dumps(signed))

    return f"{signed_hex}"


class MdocVerifyResult(BaseModel):
    """Result from verify."""

    class Meta:
        """MdocVerifyResult metadata."""

        schema_class = "MdocVerifyResultSchema"

    def __init__(
        self,
        headers: Mapping[str, Any],
        payload: Mapping[str, Any],
        valid: bool,
        kid: str,
    ):
        """Initialize a MdocVerifyResult instance."""
        self.headers = headers
        self.payload = payload
        self.valid = valid
        self.kid = kid


class MdocVerifyResultSchema(BaseModelSchema):
    """MdocVerifyResult schema."""

    class Meta:
        """MdocVerifyResultSchema metadata."""

        model_class = MdocVerifyResult

    headers = fields.Dict(
        required=False, metadata={"description": "Headers from verified Mdoc."}
    )
    payload = fields.Dict(
        required=True, metadata={"description": "Payload from verified Mdoc"}
    )
    valid = fields.Bool(required=True)
    kid = fields.Str(required=False, metadata={"description": "kid of signer"})
    error = fields.Str(required=False, metadata={"description": "Error text"})


async def resolve_public_key_by_kid_for_verify(profile: Profile, kid: str) -> str:
    """Resolve public key material from a kid."""
    resolver = profile.inject(DIDResolver)
    vmethod: Resource = await resolver.dereference(
        profile,
        kid,
    )

    if not isinstance(vmethod, VerificationMethod):
        raise InvalidVerificationMethod(
            "Dereferenced resource is not a verificaiton method"
        )

    if not isinstance(vmethod, SUPPORTED_VERIFICATION_METHOD_TYPES):
        raise InvalidVerificationMethod(
            f"Dereferenced method {type(vmethod).__name__} is not supported"
        )

    return vmethod.material


class MsoVerifier:
    """MsoVerifier helper class to verify a mso"""

    def __init__(self, data: cbor2.CBORTag) -> None:
        """Create a new MsoParser instance"""
        self.object: Sign1Message = Sign1Message.decode(data)
        self.public_key: (
            cryptography.hazmat.backends.openssl.ec._EllipticCurvePublicKey
        ) = None
        self.x509_certificates: list = []

    @property
    def raw_public_keys(self) -> bytes:
        """Extract fpublic key rom x509 certificates"""
        _mixed_heads = self.object.phdr.items() | self.object.uhdr.items()
        for h, v in _mixed_heads:
            if h.identifier == 33:
                return list(self.object.uhdr.values())

    def attest_public_key(self) -> None:
        LOGGER.warning(
            "TODO: in next releases. "
            "The certificate is to be considered as untrusted, this release "
            "doesn't validate x.509 certificate chain. See next releases and "
            "python certvalidator or cryptography for that."
        )

    def load_public_key(self) -> None:
        """Load the public key from the x509 certificate"""
        self.attest_public_key()

        for i in self.raw_public_keys:
            self.x509_certificates.append(
                cryptography.x509.load_der_x509_certificate(i)
            )

        self.public_key = self.x509_certificates[0].public_key()
        pem_public = self.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()
        self.object.key = CoseKey.from_pem_public_key(pem_public)

    def verify_signature(self) -> bool:
        """Verify the signature"""
        self.load_public_key()

        return self.object.verify_signature()


async def mdoc_verify(profile: Profile, mdoc_str: str) -> MdocVerifyResult:
    """Verify a Mdoc CBOR string"""
    mdoc_bytes = unhexlify(mdoc_str)
    mdoc = cbor2.loads(mdoc_bytes)
    mso_verifier = MsoVerifier(mdoc["documents"][0]["issuerSigned"]["issuerAuth"])
    valid = mso_verifier.verify_signature()

    headers = {}
    payload = {}
    verification_method = ""

    return MdocVerifyResult(headers, payload, valid, verification_method)
