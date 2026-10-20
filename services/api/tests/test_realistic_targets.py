"""Parser realism complements the lightweight correlation-only vulnapp fixtures."""
import pickle

import pytest
from fastapi.testclient import TestClient

from app.engine.checks.deserialization import DeserializationCheck
from app.engine.checks.xxe_confirmation import XxeConfirmationCheck
from tests.factories import operation, scan_context
from tests.fakes import CollectorOob
from tests.realistic_targets import parser_target


@pytest.mark.parametrize('secure', [False, True])
@pytest.mark.parametrize(('path', 'check', 'families'), [
    ('/xml', XxeConfirmationCheck, {'external_entity', 'parameter_entity', 'blind_exfil'}),
    ('/deserialize', DeserializationCheck, {'python_pickle'}),
])
def test_real_parser_confirms_only_supported_payloads(path, check, families, secure):
    app, outbound = parser_target(secure=secure)
    op = operation('POST', path, params=[{'name': 'data', 'in': 'body'}])
    with TestClient(app) as client:
        ctx = scan_context([op], client=client, allow_mutation=True,
                           premium=True, oob=CollectorOob(outbound))
        findings = check().run(ctx)
    assert {f.evidence['family'] for f in findings} == (set() if secure else families)
    assert all(f.confidence.value == 'verified' for f in findings)


@pytest.mark.parametrize('secure', [False, True])
def test_benign_urls_do_not_trigger_parser_callbacks(secure):
    app, outbound = parser_target(secure=secure)
    with TestClient(app) as client:
        xml = '<x>http://benign.test/token</x>'
        assert client.post('/xml', json={'data': xml}).status_code == 200
        literal = pickle.dumps('http://benign.test/token', protocol=0).decode()
        assert client.post('/deserialize', json={'data': literal}).status_code == 200
        assert client.post('/xml', json={'data': '<broken'}).status_code == 400
    assert outbound == []


@pytest.mark.parametrize('family', ['external_entity', 'parameter_entity', 'blind_exfil'])
def test_xml_payloads_are_well_formed_and_only_resolve_http_entities(family):
    from app.engine.checks.xxe_confirmation import _payload_for

    app, outbound = parser_target(secure=False)
    url = 'http://oast.test/payload-token'
    with TestClient(app) as client:
        response = client.post('/xml', json={'data': _payload_for(family, url)})
    assert response.status_code == 200
    assert outbound == [url]  # no file access or exfiltration is demonstrated
