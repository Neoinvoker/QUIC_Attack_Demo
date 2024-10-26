import re
import os

# Templates for connection identifiers
STATIC_SCID_TEMPLATE = b'\x00\x00\x00\x00\x00\x01\t'
SCID_TEMPLATE = b'\x00\x00\x00\x00\x00\x01'

# Padding and constants
PAD = b'\x00\x00\x01\x00\x01'
VER_COUNT = 7

STATIC_DCID_TEMPLATE = (
    b'baidu\x02com\x00\x00\x01\x00\x01'
    b'\x03one\x03com\x00\x00\x01\x00\x01'
    b'\x03one\x03com\x00\x00\x01\x00\x01'
    b'\x03one\x03com\x00\x00\x01\x00\x01'
    b'\x03one\x03com\x00\x00\x01\x00\x01'
    b'\x06padded\x03com\x00\x00\x01\x00\x01'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x24\xfaV\xc51\x08q\x10\xf0'
)

def is_valid_hostname(hostname):
    """Check if the given hostname is valid."""
    if hostname.endswith("."):
        hostname = hostname[:-1]  # Strip exactly one dot from the right, if present
    if len(hostname) > 253:
        print("Length > 253")
        return False

    labels = hostname.split(".")

    # The TLD must not be all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed_pattern = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed_pattern.match(label) for label in labels)

def create_payload(host):
    """Create payload based on the given hostname."""
    if not is_valid_hostname(host):
        raise ValueError("Given payload is not a valid hostname")

    labels = host.split(".")
    scid = SCID_TEMPLATE + bytes([len(labels[0])])

    # Constructing the DCID
    dcid_len = len(labels[0]) + 1  # First label length + null byte
    dcid = labels[0][1:].encode('utf-8')  # Skip the first character for length encoding
    for label in labels[1:]:
        dcid += bytes([len(label)]) + label.encode('utf-8')
    
    # Append standard records
    dcid += b'\x00\x00\x01\x00\x01' + PAD * 6
    dcid += b'\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00'

    remain_len = (dcid_len - len(dcid) - 1) + (VER_COUNT * 4)
    dcid += bytes([remain_len])
    dcid += os.urandom(dcid_len - len(dcid))

    return dcid, scid