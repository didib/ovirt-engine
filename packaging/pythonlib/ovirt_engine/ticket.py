import base64
import datetime
import json

from M2Crypto import EVP
from M2Crypto import X509
from M2Crypto import Rand

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class TicketEncoder():

    @staticmethod
    def _formatDate(d):
        return d.strftime("%Y%m%d%H%M%S")

    def __init__(self, cert, key, lifetime=5):
        self._lifetime = lifetime
        with open(cert, 'rb') as cert_file:
            self._x509 = x509.load_pem_x509_certificate(
                data=cert_file.read(),
                backend=default_backend(),
            )
        with open(key, 'rb') as key_file:
            self._pkey = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend(),
            )

    def encode(self, data):
        d = {
            'salt': base64.b64encode(Rand.rand_bytes(8)).decode('ascii'),
            'digest': 'sha1',
            'validFrom': self._formatDate(datetime.datetime.utcnow()),
            'validTo': self._formatDate(
                datetime.datetime.utcnow() + datetime.timedelta(
                    seconds=self._lifetime
                )
            ),
            'data': data
        }

        fields = []
        data_to_sign = b''
        for k, v in d.items():
            fields.append(k)
            data_to_sign += v.encode('utf-8')
        d['signedFields'] = ','.join(fields)
        signature = self._pkey.sign(
            data_to_sign,
            # TODO replace PKCS1v15 with PSS if/when we know we do not
            # need m2crypto compatibility.
            padding.PKCS1v15(),
            # TODO Replace SHA1 with SHA256 if/when we know this is safe,
            # compatibility-wise (also above).
            hashes.SHA1()
        )
        d['signature'] = base64.b64encode(signature).decode('ascii')
        d['certificate'] = self._x509.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('ascii')
        return base64.b64encode(json.dumps(d).encode('utf-8'))


class TicketDecoder():

    _peer = None
    _ca = None

    @staticmethod
    def _parseDate(d):
        return datetime.datetime.strptime(d, '%Y%m%d%H%M%S')

    @staticmethod
    def _verifyCertificate(ca, x509cert):
        if x509cert.verify(ca.get_pubkey()) == 0:
            raise ValueError('Untrusted certificate')

        if not (
            x509cert.get_not_before().get_datetime().replace(tzinfo=None) <=
            datetime.datetime.utcnow() <=
            x509cert.get_not_after().get_datetime().replace(tzinfo=None)
        ):
            raise ValueError('Certificate expired')

    def __init__(self, ca, eku, peer=None):
        self._eku = eku
        if peer is not None:
            self._peer = X509.load_cert_string(peer)
        if ca is not None:
            self._ca = X509.load_cert(ca)

    def decode(self, ticket):
        decoded = json.loads(base64.b64decode(ticket))

        if self._peer is not None:
            x509cert = self._peer
        else:
            x509cert = X509.load_cert_string(
                decoded['certificate'].encode('utf8')
            )

        if self._ca is not None:
            self._verifyCertificate(self._ca, x509cert)

        if self._eku is not None:
            if self._eku not in x509cert.get_ext(
                'extendedKeyUsage'
            ).get_value().split(','):
                raise ValueError('Certificate is not authorized for action')

        signedFields = [s.strip() for s in decoded['signedFields'].split(',')]
        if len(
            set(['salt', 'data']) &
            set(signedFields)
        ) == 0:
            raise ValueError('Invalid ticket')

        pkey = x509cert.get_pubkey()
        pkey.reset_context(md=decoded['digest'])
        pkey.verify_init()
        for field in signedFields:
            pkey.verify_update(decoded[field].encode('utf8'))
        if pkey.verify_final(
            base64.b64decode(decoded['signature'])
        ) != 1:
            raise ValueError('Invalid ticket signature')

        if not (
            self._parseDate(decoded['validFrom']) <=
            datetime.datetime.utcnow() <=
            self._parseDate(decoded['validTo'])
        ):
            raise ValueError('Ticket life time expired')

        return decoded['data']


# vim: expandtab tabstop=4 shiftwidth=4
