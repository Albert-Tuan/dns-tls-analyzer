"""Shared, offline PSL normalization. No DNS requests or PSL downloads."""
from functools import lru_cache
import ipaddress
import re

@lru_cache(maxsize=1)
def _extractor():
    import tldextract
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                include_psl_private_domains=False)

def normalize_qname(qname: str | bytes) -> dict | None:
    """None = invalid/unsupported hostname; unknown suffix is retained with null domain.

    DNS service underscores are accepted; arbitrary binary DNS labels are not.
    Reserved .test is explicitly supported for offline lab fixtures only.
    Private PSL entries excluded, so TV1/TV2 share the same registered-domain policy.
    """
    try:
        raw = qname.decode('ascii') if isinstance(qname, bytes) else qname
        if not isinstance(raw, str) or raw != raw.strip():
            return None
        name = raw[:-1] if raw.endswith('.') else raw
        labels = [s.encode('idna').decode('ascii').lower() for s in name.split('.')]
        if any(not s or len(s)>63 or not re.fullmatch(r'[a-z0-9_-]+',s) for s in labels):
            return None
        name = '.'.join(labels)
        if len(name)>253:
            return None
        try:
            ipaddress.ip_address(name)
            return None
        except ValueError:
            pass
        if len(labels)>=2 and labels[-1]=='test':
            registered, sub = '.'.join(labels[-2:]), '.'.join(labels[:-2])
        elif name.endswith(('.in-addr.arpa','.ip6.arpa')):
            registered, sub = None, None
        else:
            result = _extractor()(name)
            registered = result.top_domain_under_public_suffix or None
            sub = result.subdomain if registered else None
        return {'qname':name,'registered_domain':registered,'subdomain':sub}
    except (ValueError,TypeError,UnicodeError):
        return None
