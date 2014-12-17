
from parser import sip

sip_test_1 = """REGISTER sips:ss2.biloxi.example.com SIP/2.0\r\nVia: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7\r\nMax-Forwards: 70\r\nFrom: Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl\r\nTo: Bob <sips:bob@biloxi.example.com>\r\nCall-ID: 1j9FpLxk3uxtm8tn@biloxi.example.com\r\nCSeq: 1 REGISTER\r\nContact: <sips:bob@client.biloxi.example.com>\r\nContent-Length: 0"""


def test_sip_parse():
    assert len(sip_test_1)
    sip_message = sip.parse_sip(sip_test_1)
    assert sip_message != None
