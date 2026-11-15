import socket

import pytest

from app.dga.features import extract_dga_features, label_features, ngram_rarity, ngrams, shannon_entropy
from app.dga.normalizer import normalize_domain
from app.dga import ngram_reference


@pytest.mark.parametrize('name,registered,label,sub', [
    ('WWW.Example.COM.', 'example.com', 'example', 'www'),
    ('  www.example.com  ', 'example.com', 'example', 'www'),
    ('ab12.example.test', 'example.test', 'example', 'ab12'),
    ('Foo.Example.CO.UK.', 'example.co.uk', 'example', 'foo'),
    ('a.b.example.com.vn', 'example.com.vn', 'example', 'a.b')])
def test_normalize_registered_label(name, registered, label, sub):
    n = normalize_domain(name)
    assert (n['status'], n['registered_domain'], n['dga_label'], n['subdomain']) == ('ok', registered, label, sub)


@pytest.mark.parametrize('name,reason', [
    ('', 'empty_domain'), ('   ', 'empty_domain'), ('.', 'empty_domain'), (None, 'not_a_string'),
    (123, 'not_a_string'), ('bad..example.com', 'invalid_or_unsupported_domain'),
    ('a/b.example.com', 'invalid_or_unsupported_domain'), (b'\xff.com', 'invalid_or_unsupported_domain'),
    ('192.0.2.1', 'ip_address'), ('2001:db8::1', 'ip_address'), ('localhost', 'single_label_hostname'),
    ('printer.local', 'unknown_suffix_or_internal_name'), ('1.2.0.192.in-addr.arpa', 'reverse_dns_name')])
def test_unscorable_names_are_unknown_with_reason(name, reason):
    n = normalize_domain(name)
    assert n['status'] == 'unknown' and n['reason'] == reason and n['dga_label'] is None
    assert extract_dga_features(name)['features'] is None


def test_unicode_and_punycode_are_the_same_ascii_label():
    uni, puny = normalize_domain('www.Bücher.de'), normalize_domain('xn--bcher-kva.de')
    assert uni['dga_label'] == puny['dga_label'] == 'xn--bcher-kva'
    assert uni['is_idn'] and uni['dga_label_unicode'] == 'bücher'


def test_entropy_edge_cases_and_known_values():
    assert shannon_entropy('') == 0.0
    assert shannon_entropy('a') == 0.0
    assert shannon_entropy('aaaa') == 0.0
    assert shannon_entropy('ab') == 1.0
    assert shannon_entropy('abcd') == 2.0


def test_ratios():
    f = label_features('a1b2')
    assert f['length'] == 4 and f['digit_ratio'] == 0.5
    assert f['vowel_ratio'] == 0.5  # vowels over letters only (a, b)
    assert f['unique_character_ratio'] == 1.0
    digits = label_features('163')
    assert digits['digit_ratio'] == 1.0 and digits['vowel_ratio'] is None


def test_ngrams_stay_inside_hyphen_segments():
    assert ngrams('mail', 2) == ['ma', 'ai', 'il']
    assert ngrams('mail', 3) == ['mai', 'ail']
    assert ngrams('ab-cd', 2) == ['ab', 'cd'] and ngrams('ab-cd', 3) == []
    assert label_features('ab-cd')['ngram_score'] == label_features('ab-cd')['bigram_rarity']


def test_ngram_rarity_smoothing_and_order():
    assert ngram_rarity('qzx') == 1.0  # count 0 -> smoothed to maximum rarity, no log(0)
    top = max(ngram_reference.TRIGRAM_COUNTS, key=ngram_reference.TRIGRAM_COUNTS.get)
    assert ngram_rarity(top) == 0.0
    assert label_features('information')['ngram_score'] < label_features('xjkqzvbnmplw')['ngram_score']
    assert label_features('x')['ngram_score'] is None


def test_reference_table_is_fixed_and_documented():
    from scripts.dga_build_ngram_reference import SOURCES
    assert ngram_reference.SOURCE['bigram_sha256'] == SOURCES[2][1]
    assert ngram_reference.SOURCE['trigram_sha256'] == SOURCES[3][1]
    for n, table in ((2, ngram_reference.BIGRAM_COUNTS), (3, ngram_reference.TRIGRAM_COUNTS)):
        assert table and all(len(k) == n and set(k) <= set(ngram_reference.ALPHABET) and v > 0
                             for k, v in table.items())


def test_subdomain_is_not_the_dga_label():
    f = extract_dga_features('ld5si1xla3gn5nxkutkx1zn0fmlqk3ituw4l3i.example.com')
    assert f['dga_label'] == 'example' and f['features']['length'] == 7


def test_features_deterministic_and_offline(monkeypatch):
    first = extract_dga_features('p8e14fc63b0cb6dd1bb2dd4b9e86969393.so')

    def forbidden(*args, **kwargs):
        raise AssertionError('network access is forbidden')
    monkeypatch.setattr(socket, 'socket', forbidden)
    assert extract_dga_features('p8e14fc63b0cb6dd1bb2dd4b9e86969393.so') == first
