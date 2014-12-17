
from pyparsing import *


reserved = ";/?:@&=+$,"
user_unreserved = "&=+$,;?/"
unreserved = alphanums+"-_.!~*'()"
escaped = Combine("%" + Word(hexnums, min=2, max=2))


print(escaped.parseString("%AA"))
print(escaped.parseString("%01"))
print(escaped.parseString("%A1"))
print(escaped.parseString("%F1"))

token = Word(alphanums + "-.!%*_+`'~", min=1)

print(token.parseString("testing"))
print(token.parseString("testing!"))
print(token.parseString("!~.testing"))
print(token.parseString("!~.t1234sting"))
print(token.parseString("!~.testing&```"))


word = Word(alphanums + "-.!%*_+`'~()<>:\/\"[]?{}", excludeChars=" \t")
word.setDefaultWhitespaceChars("")
print(word.parseString("Thew ordof"))
print(word.parseString("Thew_orderof:something"))

user = Word(unreserved+user_unreserved) | Combine(OneOrMore(escaped))
user.setResultsName("user")

print(user.parseString("username"))
print(user.parseString("user_name"))
print(user.parseString("username1234"))
print(user.parseString("user=name"))
print(user.parseString("%AA%BB%EE"))


password = (ZeroOrMore(Word(unreserved + "&=+$,")) ^ Combine(ZeroOrMore(escaped)))
password.setResultsName("password")

print(password.parseString("password"))
print(password.parseString("123459086398bjbvjshygofclbjsc"))
print(password.parseString("&=,somename"))
print(password.parseString("%aE%ef%12"))

port = Word(nums, min=1, max=5)
port.setResultsName("port")

print(port.parseString("5560"))
print(port.parseString("5"))
print(port.parseString("65536"))

domain_label = Word(alphanums, alphanums+"-")

print(domain_label.parseString("domain-label"))
print(domain_label.parseString("123domain-label-"))
print(domain_label.parseString("domain-label-a"))


hostname = Combine(OneOrMore(domain_label + Optional(".")))

print(hostname.parseString("wwwin.cisco.com"))
print(hostname.parseString("wwwin.cisco.com."))
print(hostname.parseString("wwwin.cisco."))

ipv4address = Combine(Word(nums, min=1, max=3) + ("." + Word(nums))*3)

print(ipv4address.parseString("127.0.0.1"))
print(ipv4address.parseString("1.0.0.1"))
print(ipv4address.parseString("0.0.0.0"))
print(ipv4address.parseString("192.168.0.0"))

hex4 = Word(hexnums, min=1, max=4)
hex_seq = hex4 + ZeroOrMore(":" + hex4)
hex_part = hex_seq ^ hex_seq + "::" + Optional(hex_seq) ^ "::" + hex_seq

ipv6address = Combine(hex_part + Optional(":" + ipv4address))

print(ipv6address.parseString("::1"))
print(ipv6address.parseString("FE80:0000:0000:0000:0202:B3FF:FE1E:8329"))
print(ipv6address.parseString("FE80::0202:B3FF:FE1E:8329"))
print(ipv6address.parseString("2001:db8::1"))

ipv6reference = Combine("[" + ipv6address + "]")

print(ipv6reference.parseString("[::1]"))
print(ipv6reference.parseString("[2001::1]"))
print(ipv6reference.parseString("[1234:1234::1]"))

host = hostname ^ ipv4address ^ ipv6reference

print(host.parseString("cisco.com"))
print(host.parseString("192.168.0.0"))
print(host.parseString("[::1]"))
print(host.parseString("[2001::1]"))

host_port = Combine(host + Optional(":" + port))

print(host_port.parseString("cisco.com:8080"))
print(host_port.parseString("192.168.1.1:8080"))
print(host_port.parseString("[::1]:22"))

####################### Telephone Subscriber Grammar RFC3966 ###########################

phone_digit = nums + "-.()"
global_number_digits = Combine("+" + Word(phone_digit))

print(global_number_digits.parseString("+1-201-555-0123"))


parameter = ";" + Word(alphanums + "-", min=1) + Optional("=" + Word("[]/:&+$" + alphanums + "-_.!~*'()", min=1))
extension = ";ext=" + Word(phone_digit, min=1)
isdn_subaddress = ";isub=" + (Word(";/?:@&=+$" + alphanums + "-_.!~*'()", min=1) ^ escaped)
par = parameter ^ extension ^ isdn_subaddress

print(par.parseString(";something"))
print(par.parseString(";something=somethinelse"))
print(par.parseString(";isub=;?:_-some"))
print(par.parseString(";ext=00987768"))

global_number = global_number_digits + ZeroOrMore(par)

print(global_number.parseString("+1-201-555-0123;ext=2"))
print(global_number.parseString("+1-201-555-0123;isub=2"))
print(global_number.parseString("+1-201-555-0123;ext=2"))

phone_digit_hex = hexnums + "*#" + "-.()"
context = ";phone-context=" + (hostname ^ global_number_digits)
local_number = Word(phone_digit_hex, min=1) + context + ZeroOrMore(par)

print(local_number.parseString("7042;phone-context=example.com"))
print(local_number.parseString("863-1234;phone-context=+1-914-555"))

telephone_subscriber = global_number | local_number

##################### End of telephone subscriber grammar #############################

user_info = (user | telephone_subscriber) + Optional(":" + password) + "@"

print(user_info.parseString("1234@"))
print(user_info.parseString("shane@"))
print(user_info.parseString("alice@"))
print(user_info.parseString("bob:pass@"))


sip_uri = oneOf("sip: sips:") + Optional(user_info) + host_port

print(sip_uri.parseString("sip:shane@cisco.com"))
print(sip_uri.parseString("sip:shane@cisco.com:80"))
print(sip_uri.parseString("sips:shane@cisco.com:80"))
print(sip_uri.parseString("sips:12345678@cisco.com:80"))

transport_param = "transport=" + oneOf("udp tcp sctp tls")
user_param = "user=" + oneOf("phone ip")

method = oneOf("INVITE ACK BYE CANCEL REGISTER OPTIONS")
method_param = "method=" + method
ttl_param = "ttl=" + Word(nums, min=1, max=3).setParseAction(lambda x: int(x[0]) if 0 <= int(x[0]) <= 255 else "")
maddr_param = "maddr=" + host
lr_param = "lr"
other_param = Word(alphanums + unreserved+"[]/:&+$", min=1) + "=" + Word(alphanums+unreserved+"[]/:&+$")

uri_parameter = transport_param ^ user_param ^ method_param ^ ttl_param ^ maddr_param ^ lr_param ^ other_param
uri_parameters = ZeroOrMore(";" + uri_parameter)

print(uri_parameter.parseString("transport=udp"))
print(uri_parameter.parseString("transport=tcp"))
print(uri_parameter.parseString("user=phone"))
print(uri_parameter.parseString("user=ip"))
print(uri_parameter.parseString("method=INVITE"))
print(uri_parameter.parseString("method=CANCEL"))
print(uri_parameter.parseString("ttl=1"))
print(uri_parameter.parseString("ttl=0"))
print(uri_parameter.parseString("ttl=255"))
print(uri_parameter.parseString("ttl=256"))
print(uri_parameter.parseString("maddr=cisco.com"))
print(uri_parameter.parseString("lr"))
print(uri_parameter.parseString("stuff=stuff"))

hnv_unreserved = "[]/?:+$"
hname = Word(hnv_unreserved + unreserved, min=1) ^ escaped
hvalue = Optional(Word(hnv_unreserved + unreserved)) ^ ZeroOrMore(escaped)

header = Combine(hname + "=" + hvalue)
headers = "?" + header + ZeroOrMore("&" + header)

print(header.parseString("name=value"))
print(header.parseString("[name]=[value]"))
print(headers.parseString("?name=value&something=somethingelse"))


scheme = Word(alphas, alphanums+"+-.", min=1)
srvr = Optional(user_info + "@") + host_port
reg_name = Word(unreserved+";?:@&=+$", min=1) ^ OneOrMore(escaped)
authority = srvr ^ reg_name

pchar = Optional(Word(unreserved+";?:@&=+$,")) ^ ZeroOrMore(escaped)
segment = pchar + ZeroOrMore(";" + pchar)
abs_path = "/" + segment + ZeroOrMore("/" + segment)
net_path = "//" + authority + Optional(abs_path)
query = Optional(Word(reserved + unreserved)) ^ ZeroOrMore(escaped)
hier_part = (net_path ^ abs_path) + Optional("?" + query)
opaque_part = (Word(unreserved + ";?:@&=+$,") ^ OneOrMore(escaped)) + \
              Optional(Word(reserved + unreserved) ^ ZeroOrMore(escaped))
absolute_uri = scheme + ":" + (hier_part ^ opaque_part)
request_uri = sip_uri ^ absolute_uri

sip_version = "SIP/" + Word(nums, min=1) + "." + Word(nums, min=1)
request_line = method + request_uri + sip_version + LineEnd()


################################################ Message Headers #######################################################

# Accept Header
discrete_type = oneOf("text image audio video application")
composite_type = oneOf("message multipart")
m_type = (discrete_type ^ composite_type)
m_subtype = (token ^ ("x-" + token))
m_parameter = token + "=" + (("\"" + token + "\"") | token)

qvalue = ("0" + Optional("." + Optional(Word(nums, max=3)))) ^ ("1" + Optional("." + Literal("0")*(0, 3)))

quoted_string = "\"" + token + "\""
# ("q" EQUAL qvalue) / generic-param
accept_param = ("q=" + qvalue) ^ (token + Optional("=" + (host ^ quoted_string ^ token)))

media_range = (Literal("*/*") ^ (m_type + "/*") ^ (m_type + "/" + m_subtype)) + ZeroOrMore(m_parameter)
accept_range = media_range + ZeroOrMore(";" + accept_param)
accept = Literal("Accept: ") + Optional(accept_range) + ZeroOrMore(Literal(", ") + accept_range) + LineEnd()
accept.setResultsName("accept")
accept.setName("accept")

print(accept.parseString("Accept: application/sdp;level=1, application/x-private, text/html\r\n"))
print(accept.parseString("Accept: */*\r\n"))


#Accept Encoding Header
codings = "*" ^ token
encoding = codings + ZeroOrMore(";" + accept_param)
accept_encoding = "Accept-Encoding: " + Optional(encoding) + ZeroOrMore(Literal(", ") + encoding)

print(accept_encoding.parseString("Accept-Encoding: gzip"))
"""

accept_language
alert_info
allow
authentication_info
authorization
call_id
call_info
contact
content_disposition
content_encoding
content_language
content_length
content_type
cseq
date
error_info
expires
from
in_reply_to
max_forwards
mime_version
min_expires
organization
priority
proxy_authenticate
proxy_authorization
proxy_require
record_route
reply_to
require
retry_after
route
server
subject
supported
timestamp
to
unsupported
user_agent
via
warning
www_authenticate
extension_header


message_header = (accept ^ accept_encoding ^ accept_language ^ alert_info ^ allow ^ authentication_info ^ authorization ^ call_id ^ call_info ^ contact ^ content_disposition ^ content_encoding ^ content_language ^ content_length ^ content_type ^ cseq ^ date ^ error_info ^ expires ^ from ^ in_reply_to ^ max_forwards ^ mime_version ^ min_expires ^ organization ^ priority ^ proxy_authenticate ^ proxy_authorization ^ proxy_require ^ record_route ^ reply_to ^ require ^ retry_after ^ route ^ server ^ subject ^ supported ^ timestamp ^ to ^ unsupported ^ user_agent ^ via ^ warning ^ www_authenticate ^ extension_header)

request = request_line + ZeroOrMore(message_header) + LineEnd() + Optional(message_body)


sip_message = request ^ response
"""


