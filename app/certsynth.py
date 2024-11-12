import binascii
import re
import struct

SYNTH_START = """
## Client Hello
default > (
content:"\\x80\\x80"; #Length
content:"\\x01"; # Handshake Message Type (Client Hello)
content:"\\x03\\x01"; # Version (TLS 1.0)
content:"\\x00\\x57"; # Cipher Spec length 
content:"\\x00\\x00"; # Session ID Length
content:"\\x00\\x20"; # Challenge Length (32)
content:"\\x00\\x009\\x00\\x008\\x00\\x005\\x00\\x00\\x16\\x00\\x00\\x13\\x00\\x00\\x0a\\x07\\x00\\xc0\\x00\\x003\\x00\\x002\\x00\\x00/\\x00\\x00\\x9a\\x00\\x00\\x99\\x00\\x00\\x96\\x03\\x00\\x80\\x00\\x00\\x05\\x00\\x00\\x04\\x01\\x00\\x80\\x00\\x00\\x15\\x00\\x00\\x12\\x00\\x00\\x09\\x06\\x00@\\x00\\x00\\x14\\x00\\x00\\x11\\x00\\x00\\x08\\x00\\x00\\x06\\x04\\x00\\x80\\x00\\x00\\x03\\x02\\x00\\x80\\x00\\x00\\xff"; # Cipher spec list
content:"\\xf2\\xb4X\\xf2.\\xbe\\x9d#d8hZ\\xe3J\\xdf\\xe4\\xce\\xc5\\x8f\\xab\\xa3\\xd0\\xc4\\xa1\\xb1\\xa1\\xc1\\x80G'K<"; ); # Challenge
## Server Hello and Certificate
default < (
### Server Hello
content:"\\x16\\x03\\x01\\x00Q\\x02\\x00\\x00M\\x03\\x01U\\xe8\\x83\\x0f\\xa1\\xe8\\xcd\\xc6^k\\xae`\\xf4\\xbe\\x0er\\xab~w,\\xce\\xf6L\\x89#\\xc9\\xbaU\\x8b\\xae\\x0ef\\x20\\xcf\\xb4\\xc1\\xb9\\xb0-\\x1e\\xe6Zl\\x0f\\xff\\xfd\\xe3)\\x97\\x89cy\\xa9\\xdbNV\\x83\\xa5\\x97:\\x12Td\\x09\\xac\\x009\\x00\\x00\\x05\\xff\\x01\\x00\\x01\\x00";"""

SYNTH_END = """
### Server Key Exchange
content:"\\x16\\x03\\x01\\x01\\x8d\\x0c\\x00\\x01\\x89\\x00\\x80\\xbb\\xbc-\\xca\\xd8Ft\\x90|C\\xfc\\xf5\\x80\\xe9\\xcf\\xdb\\xd9X\\xa3\\xf5h\\xb4-K\\x08\\xee\\xd4\\xeb\\x0f\\xb3PLl\\x03\\x02v\\xe7\\x10\\x80\\x0c\\\\xcb\\xba\\xa8\\x92&\\x14\\xc5\\xbe\\xec\\xa5e\\xa5\\xfd\\xf1\\xd2\\x87\\xa2\\xbc\\x04\\x9b\\xe6w\\x80`\\xe9\\x1a\\x92\\xa7W\\xe3\\x04\\x8fh\\xb0v\\xf7\\xd3l\\xc8\\xf2\\x9b\\xa5\\xdf\\x81\\xdc,\\xa7%\\xec\\xe6bp\\xcc\\x9aP5\\xd8\\xce\\xce\\xef\\x9e\\xa0'Jc\\xab\\x1eX\\xfa\\xfdI\\x88\\xd0\\xf6]\\x14gW\\xda\\x07\\x1d\\xf0E\\xcf\\xe1k\\x9b\\x00\\x01\\x02\\x00\\x80\\xa9\\xc5y)\\U\\x00\\x1f\\xa30\\x9b\\x8e\\xd6.\\xed\\x01\\xe9VY0\\x9e\\x03\\x95\\x1b\\x88[q\\xdd\\xfd\\x16\\x0e\\x1a\\xc3\\xbd\\xd3\\x1c\\xbc\\x92\\xa1o\\xed\\xa5T\\xea\\xaa\\xf7\\xdd\\xcd\\xd7\\xb8\\x20E\\x9b\\x1a\\xd4H}[\\xf46\\x98dL\\x0d\\xb6<A\\x98[\\x8c\\x95\\xc5\\\\x0a\\xef>\\xfc\\xb2\\x0d\\xf7\\x94\\xecv\\xd5\\x1f\\xf2\\x85;\\xa6\\xf6\\xf2U\\xcb\\x16\\xc4z\\xa1/\\xdeq\\xf3\\xb0\\x20\\x19\\xef\\xc8\\xc9\\xa5\\x15\\xae\\x9f\\xe9\\x07:\\x0d\\x10\\xbe\\xc8\\xb3\\x98Zh\\xe6k\\x7f5\\x1d\\x8f\\x00\\x80\\x19\\xbb\\x17\\xd6e\\x00\\xc8Y\\x95L\\xde\\xdb\\x9b\\xc7I\\x20F\\x96Po\\xf8\\xedV\\x92\\x85\\xe5V\\xf2zC\\x06\\xcb\\xcc\\xfe(\\x82\\x1c\\x11\\x9d\\xb8\\xd3wT\\x9c\\x08\\xe6\\x0aA\\x06\\xbax\\xb8\\x85\\x94p+\\x88/\\xb4\\x20%\\x1bhx\\xc462\\xa4;\\x9e\\xe7\\x98`\\x01]<q)!\\x9c\\xe7\\x8a6\\xd4\\xd9\\xb6\\x0f\\xbc*\\x0aV\\xf6\\x1cp\\xb7\\xf6[P\\x85\\xfc\\x9f.\\xc3\\x14k\\x0c\\x80\\xf7\\x20\\xf3\\xf4\\xac}\\x14\\xe66lz\\xf5\\xe9Yf\\x07\\x1a\\x00f\\x98\\x90";
### Server Hello Done
content:"\\x16\\x03\\x01\\x00\\x04\\x0e\\x00\\x00\\x00"; );"""

SYNTH_CERTIFICATES = """
### Certificates Handshake
content:"\\x16"; # Type Handshake
content:"\\x03\\x01"; # Version (TLS 1.0)
content:"{0}"; # Handshake length: Certificate length + 10 (2 bytes)
#### Handshake type Certificate
content:"\\x0b"; # Handshake type: Certificate
content:"{1}"; # Certificate Handshake length: Certificate length + 6 (3 bytes)
content:"{2}"; # Certificates length: Certificate length + 3 (3 bytes)
content:"{3}"; # Certificate Length (3 bytes)
content:"{4}"; # DER certificate bytes"""


def pem_cert_validate(pem_str):
    """Validate a Certificate PEM string
    Returns
    True if valid form False otherwise
    """
    lines = pem_str.splitlines()
    if lines[0] != "-----BEGIN CERTIFICATE-----":
        return False
    elif lines[-1] != "-----END CERTIFICATE-----":
        return False
    if not re.match(r"[a-zA-Z0-9+/]={0,2}", "".join(lines[1:-1])):
        return False
    else:
        return True


def pem_to_der(pem_str):
    """Convert a PEM string to DER format"""
    lines = pem_str.strip().splitlines()
    der = binascii.a2b_base64("".join(lines[1:-1]))
    return der


def to_synth_bytes(some_str):
    """Convert a string to flowsynth formatted hex"""
    str_hex = binascii.hexlify(some_str).decode("utf-8")
    out = "\\x" + "\\x".join([str_hex[i : i + 2] for i in range(0, len(str_hex), 2)])
    return out


def cert_to_synth(cert_str, format):
    """Generates flowsynth of a TLS handshake for the given certificate
    cert_str -- A string of a PEM or DER encoded certificate
    format -- "PEM or "DER"
    """

    cert_bytes = ""
    if format == "PEM":
        # validate?
        cert_bytes = pem_to_der(cert_str)
    elif format == "DER":
        cert_bytes = cert_str
    handshake_len_bytes = struct.pack(">H", len(cert_bytes) + 10)
    handshake_len_synth_bytes = to_synth_bytes(handshake_len_bytes)
    cert_handshake_len_bytes = struct.pack(">I", len(cert_bytes) + 6)[1:]
    cert_handshake_len_synth_bytes = to_synth_bytes(cert_handshake_len_bytes)
    certs_len_bytes = struct.pack(">I", len(cert_bytes) + 3)[1:]
    certs_len_synth_bytes = to_synth_bytes(certs_len_bytes)
    cert_len_bytes = struct.pack(">I", len(cert_bytes))[1:]
    cert_len_synth_bytes = to_synth_bytes(cert_len_bytes)
    return "".join(
        [
            SYNTH_START,
            SYNTH_CERTIFICATES.format(
                handshake_len_synth_bytes,
                cert_handshake_len_synth_bytes,
                certs_len_synth_bytes,
                cert_len_synth_bytes,
                to_synth_bytes(cert_bytes),
            ),
            SYNTH_END,
        ]
    )
