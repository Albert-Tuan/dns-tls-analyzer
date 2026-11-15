"""TV1 domain normalization on top of the shared TV2 helper (one PSL policy, offline).

Analysis unit: the single label in front of the public suffix of the registered domain,
e.g. ``a1b2.example.co.uk`` -> registered ``example.co.uk`` -> DGA label ``example``.
Subdomains are TV2's concern (tunneling) and are never scored as the DGA label.
"""
import ipaddress

from app.dns.normalization import normalize_qname

# Reason codes for records that cannot be scored; never turned into a DGA verdict.
EMPTY = 'empty_domain'
NOT_A_STRING = 'not_a_string'
IP_ADDRESS = 'ip_address'
INVALID = 'invalid_or_unsupported_domain'
REVERSE = 'reverse_dns_name'
SINGLE_LABEL = 'single_label_hostname'
UNKNOWN_SUFFIX = 'unknown_suffix_or_internal_name'


def _unknown(raw, reason, qname=None):
    return {'input': raw, 'qname': qname, 'registered_domain': None, 'subdomain': None,
            'public_suffix': None, 'dga_label': None, 'dga_label_unicode': None,
            'is_idn': False, 'status': 'unknown', 'reason': reason}


def normalize_domain(qname: str) -> dict:
    """Trim, lower-case, drop one trailing dot, IDNA-encode and split with the bundled PSL.

    Returns ``status='ok'`` with ``dga_label`` (ASCII/Punycode form) or ``status='unknown'``
    with a ``reason`` code. Never raises for odd input.
    """
    if isinstance(qname, bytes):
        try:
            qname = qname.decode('ascii')
        except UnicodeDecodeError:
            return _unknown(None, INVALID)
    if not isinstance(qname, str):
        return _unknown(None, NOT_A_STRING)
    raw = qname
    name = qname.strip()
    if name.endswith('.'):
        name = name[:-1]
    if not name:
        return _unknown(raw, EMPTY)
    try:
        ipaddress.ip_address(name.strip('[]'))
        return _unknown(raw, IP_ADDRESS)
    except ValueError:
        pass
    pieces = normalize_qname(name)
    if pieces is None:
        return _unknown(raw, INVALID)
    ascii_name = pieces['qname']
    registered = pieces['registered_domain']
    if registered is None:
        if ascii_name.endswith(('.in-addr.arpa', '.ip6.arpa')):
            reason = REVERSE
        elif '.' not in ascii_name:
            reason = SINGLE_LABEL
        else:
            reason = UNKNOWN_SUFFIX
        return _unknown(raw, reason, ascii_name)
    label, suffix = registered.split('.', 1)
    is_idn = label.startswith('xn--')
    try:
        unicode_label = label.encode('ascii').decode('idna') if is_idn else label
    except UnicodeError:
        return _unknown(raw, INVALID, ascii_name)
    return {'input': raw, 'qname': ascii_name, 'registered_domain': registered,
            'subdomain': pieces['subdomain'], 'public_suffix': suffix, 'dga_label': label,
            'dga_label_unicode': unicode_label, 'is_idn': is_idn, 'status': 'ok', 'reason': None}
