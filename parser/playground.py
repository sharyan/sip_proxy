from pyparsing import *

reserved = ";/?:@&=+$,"
user_unreserved = "&=+$,;?/"
unreserved = alphanums + "-_.!~*'()"
escaped = Combine("%" + Word(hexnums, min=2, max=2))
LHEX = hexnums.lower()

# LWS = [*WSP CRLF] 1*WSP
SP = Literal(" ").suppress()
HTAB = White("\t").parseWithTabs().suppress()

LWS = Optional(ZeroOrMore(" ") + LineEnd()) + OneOrMore(" ")
SWS = (Optional(LWS)).suppress()
LAQUOT = (Optional(Literal(" ").parseWithTabs()) + Literal("<")).suppress()
RAQUOT = (Literal(">") + Optional(Literal(" ").parseWithTabs())).suppress()
HCOLON = (Optional(Literal(" ").parseWithTabs()) + Literal(":") + Optional(Literal(" "))).suppress()
SLASH = (SWS + Literal("/") + SWS).suppress()
SEMI = (SWS + Literal(";") + SWS).suppress()
EQUAL = (Optional(" ") + Literal("=") + Optional(" ")).suppress()
# COMMA   =  [*WSP CRLF] 1*WSP "," [*WSP CRLF] 1*WSP ; comma
COMMA = (SWS + Literal(",") + SWS).suppress()
LPAREN = (SWS + "(" + SWS).suppress()
RPAREN = (SWS + ")" + SWS).suppress()
LDQUOT = (SWS + "\"").suppress()
RDQUOT = ("\"" + SWS).suppress()
DCOLON = Literal("::").suppress()

ctext = Word(printables + alphas8bit)
quoted_pair = Literal("\\") + Word(printables)
comment = LPAREN + ZeroOrMore(ctext ^ quoted_pair) + RPAREN

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
sentence = Combine(ZeroOrMore(" " ^ word))
print(word.parseString("Thew ordof"))
print(word.parseString("Thew_orderof:something"))

user = Word(unreserved + user_unreserved) | Combine(OneOrMore(escaped))
user.setResultsName("user")

print(user.parseString("username"))
print(user.parseString("user_name"))
print(user.parseString("username1234"))
print(user.parseString("user=name"))
print(user.parseString("%AA%BB%EE"))

password = (ZeroOrMore(Word(unreserved + "&=+$,"))
            ^ Combine(ZeroOrMore(escaped)))
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

domain_label = Word(alphanums, alphanums + "-")

print(domain_label.parseString("domain-label"))
print(domain_label.parseString("123domain-label-"))
print(domain_label.parseString("domain-label-a"))

hostname = Combine(OneOrMore(domain_label + Optional(".")))

print(hostname.parseString("wwwin.cisco.com"))
print(hostname.parseString("wwwin.cisco.com."))
print(hostname.parseString("wwwin.cisco."))

ipv4address = Combine(Word(nums, min=1, max=3) + ("." + Word(nums)) * 3)

print(ipv4address.parseString("127.0.0.1"))
print(ipv4address.parseString("1.0.0.1"))
print(ipv4address.parseString("0.0.0.0"))
print(ipv4address.parseString("192.168.0.0"))

hex4 = Word(hexnums, min=1, max=4)
hex_seq = hex4 + ZeroOrMore(HCOLON + hex4)
hex_part = hex_seq ^ hex_seq + DCOLON + Optional(hex_seq) ^ DCOLON + hex_seq

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

# ###################### Telephone Subscriber Grammar RFC3966 #############

phone_digit = nums + "-.()"
global_number_digits = Combine("+" + Word(phone_digit))

print(global_number_digits.parseString("+1-201-555-0123"))

parameter = ";" + Word(alphanums + "-", min=1) + \
            Optional("=" + Word("[]/:&+$" + alphanums + "-_.!~*'()", min=1))
extension = ";ext=" + Word(phone_digit, min=1)
isdn_subaddress = ";isub=" + \
                  (Word(";/?:@&=+$" + alphanums + "-_.!~*'()", min=1) ^ escaped)
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

# #################### End of telephone subscriber grammar ################

user_info = (user | telephone_subscriber) + \
            Optional(Literal(":").suppress() + password) + "@"

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
ttl_param = "ttl=" + \
            Word(nums, min=1, max=3).setParseAction(
                lambda x: int(x[0]) if 0 <= int(x[0]) <= 255 else "")
maddr_param = "maddr=" + host
lr_param = "lr"
other_param = Word(alphanums + unreserved + "[]/:&+$", min=1) + \
              "=" + Word(alphanums + unreserved + "[]/:&+$")

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

scheme = Word(alphas, alphanums + "+-.", min=1)
srvr = Optional(user_info + "@") + host_port
reg_name = Word(unreserved + ";?:@&=+$", min=1) ^ OneOrMore(escaped)
authority = srvr ^ reg_name

pchar = Optional(Word(unreserved + ";?:@&=+$,")) ^ ZeroOrMore(escaped)
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


################################################ Message Headers #########

# Accept Header
discrete_type = oneOf("text image audio video application")
composite_type = oneOf("message multipart")
m_type = (discrete_type ^ composite_type)
m_subtype = (token ^ ("x-" + token))
m_parameter = token + "=" + (("\"" + token + "\"") | token)

qvalue = ("0" + Optional("." + Optional(Word(nums, max=3)))
         ) ^ ("1" + Optional("." + Literal("0") * (0, 3)))

quoted_string = "\"" + token + "\""
# ("q" EQUAL qvalue) / generic-param
accept_param = (
                   "q=" + qvalue) ^ (token + Optional("=" + (host ^ quoted_string ^ token)))

media_range = (Literal("*/*") ^ (m_type + "/*") ^
               (m_type + "/" + m_subtype)) + ZeroOrMore(m_parameter)
accept_range = media_range + ZeroOrMore(";" + accept_param)
accept = Literal("Accept: ") + Optional(accept_range) + \
         ZeroOrMore(Literal(", ") + accept_range) + LineEnd()
accept.setResultsName("accept")
accept.setName("accept")

print(accept.parseString(
    "Accept: application/sdp;level=1, application/x-private, text/html\r\n"))
print(accept.parseString("Accept: */*\r\n"))


# Accept Encoding Header
codings = "*" ^ token
encoding = codings + ZeroOrMore(";" + accept_param)
accept_encoding = "Accept-Encoding: " + \
                  Optional(encoding) + ZeroOrMore(Literal(", ") + encoding)

print(accept_encoding.parseString("Accept-Encoding: gzip"))
print(accept_encoding.parseString("Accept-Encoding: zip"))
print(accept_encoding.parseString(
    "Accept-Encoding: sdp, sip, html, googlieyes"))

# "Accept-Language" HCOLON [ language *(COMMA language) ]
language_range = (
                     Word(alphas, min=1, max=8) + ZeroOrMore("-" + Word(alphas, min=1, max=2))) ^ "*"
language = language_range + ZeroOrMore(";" + accept_param)
accept_language = "Accept-Language: " + language + ZeroOrMore(", " + language)

print(accept_language.parseString("Accept-Language: sd, zu, ln;q=0.123"))

# ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)

### Generic Param ###
gen_value = token ^ host ^ quoted_string
generic_param = token + Literal("=") + gen_value
#####################


######################## Via Header ####################################
protocol_name = Literal("SIP") ^ token
protocol_version = token
transport = oneOf("UDP TCP TLS SCTP")
sent_by = host + Optional(":" + port)
sent_protocol = protocol_name + "/" + protocol_version + "/" + transport

ttl = Word(nums, min=1, max=3).setParseAction(
    lambda ttl: int(ttl) if 0 <= ttl <= 255 else None)
via_ttl = Literal("ttl=") + ttl
via_maddr = Literal("maddr=") + host
via_recieved = "recieved=" + (ipv4address ^ ipv6address)
via_branch = "branch=" + token
via_extension = generic_param

via_params = via_ttl ^ via_maddr ^ via_recieved ^ via_branch ^ via_extension

via_param = sent_protocol + \
            Literal(" ").suppress() + sent_by + ZeroOrMore(";" + via_params)
via = (Literal("Via: ") ^ Literal("v: ")) + \
      via_param + ZeroOrMore(", " + via_param)
print(via.parseString("Via: SIP/2.0/UDP 172.18.193.120:5060"))
print(via.parseString(
    "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877;received=192.0.2.4"))
#########################################################################

### Alert Info ###

alert_param = Literal("<").suppress() + absolute_uri + \
              Literal(">").suppress() + \
              ZeroOrMore(Literal(";").suppress() + generic_param)
alert_info = Literal("Alert-Info:") + alert_param + \
             ZeroOrMore(", " + alert_param)

print(alert_info.parseString(
    "Alert-Info:<http://www.notused.com>;info=alert-external\;x-line-id=0"))


################# Allow

# Allow  =  "Allow" HCOLON [Method *(COMMA Method)]
allow = Literal("Allow: ") + Optional(method + ZeroOrMore(", " + method))

#################


### Authentication-Info ###

nonce_value = quoted_string
next_nonce = Literal("nextnonce=") + nonce_value

qop_value = oneOf("auth-int auth") ^ token
message_qop = Literal("qop=") + qop_value

response_digest = Literal("<") + Optional(LHEX) + Literal(">")
response_auth = Literal("rspauth=") + response_digest

cnonce = Literal("cnonce=") + nonce_value

nc_value = Word(LHEX, exact=8)
nonce_count = Literal("nc=") + nc_value

ainfo = next_nonce ^ message_qop ^ response_auth ^ cnonce ^ nonce_count

# "Authentication-Info" HCOLON ainfo *(COMMA ainfo)
authentication_info = Literal(
    "Authentication-Info: ") + ainfo + ZeroOrMore(", " + ainfo)

########################### Authorization

username = Literal("username") + EQUAL + quoted_string
realm = Literal("realm") + EQUAL + quoted_string
nonce = Literal("nonce") + EQUAL + quoted_string
opaque = Literal("opaque") + EQUAL + quoted_string

digest_uri_value = request_uri
digest_uri = Literal("uri") + EQUAL + LDQUOT + digest_uri_value + RDQUOT

cnonce = Literal("cnonce") + EQUAL + nonce_value

request_digest = LDQUOT + Word(hexnums, exact=32) + RDQUOT
dresponse = Literal("response") + EQUAL + request_digest

algorithm = Literal("algorithm") + EQUAL + (oneOf("MD5 MD5-sess") ^ token)

auth_param = token + EQUAL + (token ^ quoted_string)

dig_resp = username ^ realm ^ nonce ^ digest_uri ^ dresponse ^ algorithm ^ cnonce ^ opaque ^ message_qop ^ nonce_count ^ auth_param
digest_response = dig_resp + ZeroOrMore(COMMA + dig_resp)
credentials = (Literal("Digest") + SWS + digest_response)
authorization = Literal("Authorization") + HCOLON.suppress() + credentials

print(authorization.parseString(
    "Authorization: Digest username=\"Alice\", realm=\"atlanta.com\", nonce=\"84a4cc6f3082121f32b42a2187831a9e\", response=\"7587245234b3434cc3412213e5f113a5432\""))

############################

# ( "Call-ID" / "i" ) HCOLON callid
call_id = oneOf("Call-ID i") + HCOLON.suppress() + \
          Combine(word + Optional(Literal("@") + word))

print(call_id.parseString("Call-ID: a84b4c76e66710"))
print(call_id.parseString("Call-ID: a84b4c76e66710@cisco.com"))
print(call_id.parseString("i: a84b4c76e66710"))
print(call_id.parseString("i: a84b4c76e66710@cisco.com"))

############################ Call-Info

info_param = Literal("purpose") + EQUAL + ((oneOf("icon info card") ^ token) ^ generic_param)
info = LAQUOT + absolute_uri + RAQUOT + ZeroOrMore(SEMI + info_param)
# "Call-Info" HCOLON info *(COMMA info)
call_info = Literal("Call-Info") + HCOLON + info + ZeroOrMore(COMMA + info)

print(call_info.parseString(
    "Call-Info: <http://wwww.example.com/alice/photo.jpg> ;purpose=icon, <http://www.example.com/alice/> ;purpose=info"))

############################

# ("Contact" / "m" ) HCOLON ( STAR / (contact-param *(COMMA contact-param)))
display_name = ZeroOrMore(token + Literal(" ").suppress()) ^ quoted_string

addr_spec = sip_uri ^ absolute_uri

name_addr = Optional(display_name) + LAQUOT.suppress() + \
            addr_spec + RAQUOT.suppress()

cpq = "q=" + qvalue
delta_seconds = Word(nums, min=1)
cp_expires = "expires=" + delta_seconds

contact_params = cpq ^ cp_expires ^ generic_param
contact_param = (name_addr ^ addr_spec) + ZeroOrMore(";" + contact_params)
contact = oneOf("Contact m") + HCOLON + (Literal("*") ^
                                         (contact_param + ZeroOrMore(", " + contact_param)))

print(contact.parseString("Contact: <mailto:carol@chicago.com>"))
print(contact.parseString("Contact: <sip:carol@chicago.com>"))

###################### Content-Disposition
disp_type = oneOf("render session icon alter") ^ token
handling_param = Literal("handling") + EQUAL + (oneOf("optional required") ^ token)
disp_param = handling_param ^ generic_param

# "Content-Disposition" HCOLON disp-type *( SEMI disp-param )
content_disposition = Literal("Content-Disposition") + HCOLON + disp_type + ZeroOrMore(SEMI + disp_param)

print(content_disposition.parseString("Content-Disposition: session"))

####################### Content-Encoding

# content_coding = token
# ( "Content-Encoding" / "e" ) HCOLON content-coding *(COMMA content-coding)
content_encoding = oneOf("Content-Encoding e") + HCOLON + token + ZeroOrMore(COMMA + token)
print(content_encoding.parseString("Content-Encoding: gzip"))

###################### Content-Language

primary_tag = Word(alphas, min=1, max=8)
language_tag = primary_tag + ZeroOrMore(Literal("-") + primary_tag)
# "Content-Language" HCOLON language-tag *(COMMA language-tag)
content_language = Literal("Content-Language") + HCOLON + Combine(language_tag + ZeroOrMore(COMMA + language_tag))

print(content_language.parseString("Content-Language: fr"))
print(content_language.parseString("Content-Language: de-fr-en-us"))

#####################

# ( "Content-Length" / "l" ) HCOLON 1*DIGIT
content_length = oneOf(
    "Content-Length l") + HCOLON.suppress() + Word(nums, min=1)

print(content_length.parseString("l: 12846"))
print(content_length.parseString("Content-Length: 12846"))

#######################

# media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
# Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
media_type = m_type + \
             SLASH.suppress() + m_subtype + ZeroOrMore(SEMI + m_parameter)
content_type = oneOf("Content-Type c") + HCOLON.suppress() + media_type

print(content_type.parseString("Content-Type: application/sdp"))
print(content_type.parseString("Content-Type: application/json"))

########################

# "CSeq" HCOLON 1*DIGIT LWS Method
c_seq = Literal("CSeq") + HCOLON.suppress() + \
        Word(nums, min=1) + Optional(" ").suppress() + method

print(c_seq.parseString("CSeq: 63104 OPTIONS"))

######################### Date

weekday = oneOf("Mon Tue Wed Thu Fri Sat Sun")
month = oneOf("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec")
time = Word(nums, exact=2) + HCOLON + Word(nums, exact=2) + HCOLON + Word(nums, exact=2)
sip_date = weekday + COMMA + Word(nums, exact=2) + month + SP + Word(nums, exact=4) + SP + time + SP + Literal("GMT")
# "Date" HCOLON SIP-date
date_header = Literal("Date") + HCOLON + sip_date

######################## Error-Info
# TODO error_info
# TODO expires

#########################

# ( "From" / "f" ) HCOLON from-spec
tag_param = Literal("tag") + EQUAL.suppress() + token
from_param = tag_param ^ generic_param
from_spec = (name_addr ^ addr_spec) + ZeroOrMore(SEMI.suppress() + from_param)
From = oneOf("From f") + HCOLON.suppress() + from_spec

print(From.parseString("From: Alice <sip:alice@atlanta.com>;tag=1928301774"))

########################

# TODO in_reply_to
# TODO max_forwards
# TODO mime_version
# TODO min_expires
# TODO organisation

#########################

# "Priority" HCOLON priority-value
priority_value = oneOf("emergency urgent normal non-urgent") ^ token
priority = Literal("Priority") + HCOLON + priority_value

##########################

# TODO proxy_authenicate
# TODO proxy_authorization
# TODO proxy_require
# TODO record_route

# Reply-To

# ( name-addr / addr-spec ) *( SEMI rplyto-param )
reply_to_spec = (name_addr ^ addr_spec) + \
                ZeroOrMore(SEMI.suppress() + generic_param)

# "Reply-To" HCOLON rplyto-spec
reply_to = Literal("Reply-To") + HCOLON.suppress() + reply_to_spec

print(reply_to.parseString("Reply-To: Bob <sip:bob@biloxi.com>"))

# Require

# "Require" HCOLON option-tag *(COMMA option-tag)
require = Literal("Require") + HCOLON.suppress() + token + \
          ZeroOrMore(COMMA.suppress() + token)

print(require.parseString("Require: 100rel"))
print(require.parseString("Require: 100rel, 200unrel"))

#############################

# TODO route_after

# Route

# name-addr *( SEMI rr-param )
route_param = name_addr + ZeroOrMore(SEMI.suppress() + generic_param)

# "Route" HCOLON route-param *(COMMA route-param)
route = Literal("Route") + HCOLON.suppress() + route_param + \
        ZeroOrMore(COMMA.suppress() + route_param)

print(route.parseString(
    "Route: <sip:bigbox3.site3.atlanta.com;lr>, <sip:server10.biloxi.com;lr>"))

# Server

product_version = token
product = token + Optional(Optional(SLASH.suppress()) + product_version)
server_val = product ^ comment
# "Server" HCOLON server-val *(LWS server-val)
server = Literal("Server") + HCOLON.suppress() + \
         server_val + ZeroOrMore(LWS.suppress() + server_val)

print(server.parseString("Server: HomeServer v2"))

# Subject

# ( "Subject" / "s" ) HCOLON [TEXT-UTF8-TRIM]
# TODO add support for utf8 in parser
subject = oneOf("Subject s") + HCOLON.suppress() + Optional(sentence)

print(subject.parseString("Subject: Need more boxes"))
print(subject.parseString("s: Tech Support"))

#############################

# TODO supported
# TODO timestamp

# To

to_param = tag_param ^ generic_param
# ( "To" / "t" ) HCOLON ( name-addr/ addr-spec ) *( SEMI to-param )
to = oneOf("To t") + HCOLON.suppress() + (name_addr ^ addr_spec) + \
     ZeroOrMore(SEMI.suppress() + to_param)

print(
    to.parseString("To: The Operator <sip:operator@cs.columbia.edu>;tag=287447"))
print(to.parseString("t: sip:+12125551212@server.phone2net.com"))


#############################

# TODO unsupported

# User-Agent

# "User-Agent" HCOLON server-val *(LWS server-val)
user_agent = Literal("User-Agent") + HCOLON.suppress() + \
             server_val + ZeroOrMore(LWS.suppress() + server_val)

print(user_agent.parseString("User-Agent: Softphone Beta1.5"))

#############################

# TODO warning
# TODO www_authenticate
# TODO extension_header

#############################

informational = oneOf("100 180 181 182 183")
success = Literal("200")
redirection = oneOf("300 301 302 305 380")
client_error = oneOf("400 401 402 403 404 405 406 407 408 410 413 415 "
                     "416 420 421 423 480 481 482 483 485 486 487 488 491 493")
server_error = oneOf("500 501 502 5023 504 505 513")
global_failure = oneOf("600 603 604 606")
extension_code = Word(nums, exact=3)

status_code = informational ^ redirection ^ success ^ client_error ^ server_error ^ global_failure ^ extension_code

print(status_code.parseString("100"))
print(status_code.parseString("200"))
print(status_code.parseString("300"))
print(status_code.parseString("400"))
print(status_code.parseString("500"))
print(status_code.parseString("600"))
print(status_code.parseString("900"))

reason_phrase = ZeroOrMore(Word(reserved + unreserved + " \t") ^ escaped)

print(reason_phrase.parseString("OK"))
print(reason_phrase.parseString("Failed: No server present to handle request"))
print(reason_phrase.parseString("Bad implementation"))
print(reason_phrase.parseString("Just fuck off"))

status_line = sip_version + SP + status_code + SP + reason_phrase + LineEnd()
"""
message_header = (
    accept ^ accept_encoding ^ accept_language ^ alert_info ^ allow ^ authentication_info ^ authorization ^ call_id ^ call_info ^ contact ^ content_disposition ^ content_encoding ^ content_language ^ content_length ^ content_type ^ cseq ^ date ^ error_info ^ expires ^
from ^ in_reply_to ^ max_forwards ^ mime_version ^ min_expires ^ organization ^ priority ^ proxy_authenticate ^ proxy_authorization ^ proxy_require ^ record_route ^ reply_to ^ require ^ retry_after ^ route ^ server ^ subject ^ supported ^ timestamp ^ to ^ unsupported ^ user_agent ^ via ^ warning ^ www_authenticate ^ extension_header)

request = request_line + \
          ZeroOrMore(message_header) + LineEnd() + Optional(message_body)
response = status_line + \
           ZeroOrMore(message_header) + LineEnd() + Optional(message_body)
sip_message = request ^ response
"""