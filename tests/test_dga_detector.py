import json
from dataclasses import replace
from pathlib import Path

import pytest

from app.dga.detector import (BENIGN, SUSPICIOUS, UNKNOWN, DgaConfig, analyze_dns_domains,
                              evaluate_rules, score_domain)
from app.dga.evaluation import load_dataset
from app.dns.parser import parse_dns_pcap

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_KEYS = {'detector', 'classification', 'target', 'score', 'features', 'reasons'}


def query(qname, i=0, ip='192.0.2.10', is_query=True):
    from app.dns.normalization import normalize_qname
    return {'timestamp': 1794000000.0 + i, 'src_ip': ip, 'dst_ip': '192.0.2.53', 'dns_id': i,
            'is_query': is_query, **normalize_qname(qname), 'qtype': 'A',
            'rcode': None if is_query else 'NOERROR', 'packet_length': 80, 'frame_number': i + 1}


def test_example_com_is_scored_without_error():
    r = score_domain('example.com')
    assert CONTRACT_KEYS <= r.keys() and r['detector'] == 'dga'
    assert r['classification'] == BENIGN and isinstance(r['score'], int) and 0 <= r['score'] <= 100
    assert r['features']['length'] == 7 and r['target'] == 'example.com'


def test_labelled_dga_domain_has_score_and_explained_reasons():
    row = next(r for r in load_dataset(ROOT / 'samples/dga/dga_dataset.csv', 'test')
               if r['domain'] == 'p8e14fc63b0cb6dd1bb2dd4b9e86969393.so')
    assert row['label'] == 'dga' and row['family'] == 'dyre'
    r = score_domain(row['domain'])
    assert r['classification'] == SUSPICIOUS and r['score'] >= DgaConfig().alert_score
    assert {'unusual_ngrams', 'high_entropy', 'high_digit_ratio'} <= set(r['reasons'])
    assert len(r['signal_groups']) >= 2


def test_query_response_pair_gives_one_domain():
    events = json.loads((ROOT / 'handoff/evidence/query_response_events.json').read_text())
    results = analyze_dns_domains(events)
    assert len(events) == 2 and len(results) == 1
    assert results[0]['target'] == 'example.com' and results[0]['observations']['query_count'] == 1


def test_responses_alone_produce_nothing():
    assert analyze_dns_domains([query('www.example.com', is_query=False)]) == []


def test_repeated_queries_give_one_result():
    results = analyze_dns_domains([query('foo.example.com', i) for i in range(100)])
    assert len(results) == 1 and results[0]['observations']['query_count'] == 100
    assert results[0]['observations']['unique_qnames'] == 1


def test_long_random_subdomains_scored_on_registered_label():
    events = json.loads((ROOT / 'handoff/evidence/synthetic_tunnel_like_dns_events.json').read_text())
    results = analyze_dns_domains(events)
    assert len(results) == 1 and results[0]['dga_label'] == 'example'
    assert results[0]['classification'] == BENIGN
    assert results[0]['observations']['unique_qnames'] == 40


def test_empty_input_and_bad_input_type():
    assert analyze_dns_domains([]) == []
    with pytest.raises(TypeError):
        analyze_dns_domains('www.example.com')
    with pytest.raises(TypeError):
        analyze_dns_domains(['www.example.com'])


@pytest.mark.parametrize('name,reason', [('192.0.2.1', 'ip_address'), ('', 'empty_domain'),
                                         ('localhost', 'single_label_hostname')])
def test_ip_or_empty_is_unknown_with_reason(name, reason):
    r = score_domain(name)
    assert r['classification'] == UNKNOWN and r['score'] is None and r['reasons'] == [reason]


def test_events_without_registered_domain_are_unknown():
    results = analyze_dns_domains([query('host.unknownsuffixzz'), query('1.2.0.192.in-addr.arpa', 1)])
    assert [r['classification'] for r in results] == [UNKNOWN, UNKNOWN]
    assert all(r['reasons'] and r['score'] is None for r in results)


def test_one_signal_group_never_flags():
    # Only the composition rules can fire; score 40 >= alert 20, but one group is not enough.
    cfg = replace(DgaConfig(), alert_score=20, ngram_score_threshold=1.0, entropy_threshold=10.0,
                  length_threshold=100.0)
    r = score_domain('b1c2d3f4g5.com', cfg)
    assert r['reasons'] == ['high_digit_ratio', 'low_vowel_ratio'] and r['score'] == 40
    assert r['signal_groups'] == ['composition'] and r['classification'] == BENIGN
    assert score_domain('b1c2d3f4g5.com')['classification'] == SUSPICIOUS


def test_every_alert_on_dev_has_two_groups():
    for row in load_dataset(ROOT / 'samples/dga/dga_dataset.csv', 'dev'):
        r = score_domain(row['domain'])
        if r['classification'] == SUSPICIOUS:
            assert len(r['signal_groups']) >= 2 and len(r['reasons']) >= 2


@pytest.mark.parametrize('name', ['example.com', 'information.com', 'bücher.de', 'mail.google.com',
                                  'bestbuy.com', 'xn--bcher-kva.de'])
def test_natural_and_idn_names_are_not_flagged(name):
    assert score_domain(name)['classification'] != SUSPICIOUS


@pytest.mark.parametrize('name', ['web2023shop.com', 'news4you2day.com', 'minecraftforge.net'])
def test_long_or_digit_words_never_flagged_by_a_single_rule(name):
    # Known false-positive class (see docs/TV1_DGA_REPORT.md): allowed only with >= 2 groups.
    r = score_domain(name)
    fired, groups, _ = evaluate_rules(r['features'], DgaConfig())
    assert r['classification'] != SUSPICIOUS or (len(fired) >= 2 and len(groups) >= 2)


def test_idn_is_unknown_not_dga():
    r = score_domain('bücher.de')
    assert r['classification'] == UNKNOWN and 'idn_label_outside_reference_corpus' in r['reasons']


@pytest.mark.parametrize('name,length', [('a' * 63 + '.com', 63), ('1234567890.com', 10), ('163.com', 3)])
def test_very_long_and_all_digit_labels(name, length):
    r = score_domain(name)
    assert r['features']['length'] == length and r['classification'] in (BENIGN, SUSPICIOUS)
    json.dumps(r, allow_nan=False)
    assert r['score'] == 0 or r['reasons']


def test_short_label_not_flagged():
    r = score_domain('qx7.com')
    assert r['classification'] == BENIGN and 'label_too_short_for_scoring' in r['reasons']


def test_default_config_is_the_frozen_dev_selection():
    assert DgaConfig() == DgaConfig.from_file(ROOT / 'configs/dga_frozen.json')
    selection = json.loads((ROOT / 'configs/dga_frozen.selection.json').read_text())
    assert selection['split'] == 'dev' and selection['selected']['config'] == DgaConfig().to_dict()


@pytest.mark.parametrize('change', [{'alert_score': 0}, {'alert_score': 101}, {'weight_set': 'other'},
                                    {'entropy_threshold': float('nan')}, {'min_signal_groups': 5},
                                    {'min_label_length': True}])
def test_invalid_config(change):
    with pytest.raises(ValueError):
        replace(DgaConfig(), **change)


def test_dataset_splits_are_disjoint():
    dev = load_dataset(ROOT / 'samples/dga/dga_dataset.csv', 'dev')
    test = load_dataset(ROOT / 'samples/dga/dga_dataset.csv', 'test')
    assert {r['split'] for r in dev} == {'dev'} and {r['split'] for r in test} == {'test'}
    assert not {r['domain'] for r in dev} & {r['domain'] for r in test}
    assert not {r['dga_label'] for r in dev} & {r['dga_label'] for r in test}


def test_json_output_is_strict_and_ordered():
    events = [query('www.example.com'), query('p8e14fc63b0cb6dd1bb2dd4b9e86969393.so', 1),
              query('192.0.2.1.example.com', 2)]
    results = analyze_dns_domains(events)
    json.dumps(results, allow_nan=False)
    assert results[0]['classification'] == SUSPICIOUS
    assert sum(r['classification'] == SUSPICIOUS for r in results) == 1


@pytest.mark.parametrize('pcap,domains', [('benign_dns.pcap', {'example.com', 'example.org'}),
                                          ('query_response.pcap', {'example.com'}),
                                          ('synthetic_tunnel_like_dns.pcap', {'example.com'}),
                                          ('tls_clienthello_only.pcap', set()), ('empty.pcap', set())])
def test_pipeline_from_tv2_parser(pcap, domains):
    results = analyze_dns_domains(parse_dns_pcap(str(ROOT / 'samples' / pcap)))
    assert {r['target'] for r in results} == domains
    assert all(r['classification'] != SUSPICIOUS for r in results)


def test_labelled_fixture_pcap():
    manifest = json.loads((ROOT / 'samples/dga/fixture_manifest.json').read_text())
    events = parse_dns_pcap(str(ROOT / 'samples' / manifest['pcap']))
    assert sum(e['is_query'] for e in events) == manifest['expected_dns_queries']
    results = analyze_dns_domains(events)
    assert {r['target'] for r in results} == {l['registered_domain'] for l in manifest['labels']}
    assert len(results) == manifest['expected_domains']
