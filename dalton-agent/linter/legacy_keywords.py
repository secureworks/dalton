"""Suricata rule keywords renamed to dotted sticky buffers, mostly in the
5.0 keyword overhaul. `suricata --list-keywords` only lists the current
name, but current engines still accept these old spellings, and they are
all over rulesets and blog posts people are working from today.

This is not about supporting old engines - it's about reading old *rules*.
Each entry maps the legacy spelling to the current keyword it aliases; the
`/keywords` endpoint fills in the description and documentation link from
the live engine's own current-keyword data, so this table never goes stale
against the description/doc-link text itself.

Every entry below was verified against a running Suricata 8.0.6 engine:
the legacy spelling parses successfully in a real rule, and the modern
spelling it maps to is both listed by `--list-keywords` and also parses.
A number of plausible-looking candidates (tls_version, tls_subject,
tls_issuerdn, tls_fingerprint, ssh_protoversion, ssh_softwareversion,
file_name, dns_query_name) were tried and rejected by the engine as
'unknown rule keyword' - they are not included here.
"""

LEGACY_KEYWORD_ALIASES = {
    "file_data": "file.data",
    "dns_query": "dns.query",
    "tls_sni": "tls.sni",
    "tls_cert_issuer": "tls.cert_issuer",
    "tls_cert_subject": "tls.cert_subject",
    "tls_cert_serial": "tls.cert_serial",
    "tls_cert_fingerprint": "tls.cert_fingerprint",
    "http_protocol": "http.protocol",
    "http_request_line": "http.request_line",
    "http_response_line": "http.response_line",
    "http_start": "http.start",
    "http_accept": "http.accept",
    "http_accept_lang": "http.accept_lang",
    "http_accept_enc": "http.accept_enc",
    "http_referer": "http.referer",
    "http_content_type": "http.content_type",
    "http_content_len": "http.content_len",
    "http_connection": "http.connection",
    "http_header_names": "http.header_names",
    "dce_iface": "dcerpc.iface",
    "dce_opnum": "dcerpc.opnum",
    "dce_stub_data": "dcerpc.stub_data",
    "ssh_proto": "ssh.proto",
    "ssh_software": "ssh.software",
    "ack": "tcp.ack",
    "seq": "tcp.seq",
    "window": "tcp.window",
    "smb_named_pipe": "smb.named_pipe",
}
