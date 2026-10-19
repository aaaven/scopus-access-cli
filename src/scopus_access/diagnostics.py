"""Fixed-shape diagnostics: never copy raw header values or remote messages."""
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

HEADER_REASONS = frozenset({
    'RATE_LIMIT_HEADERS_VALID', 'RATE_LIMIT_FIRST_SUCCESSFUL_DIAGNOSTIC',
    'RATE_LIMIT_HEADERS_MISSING', 'RATE_LIMIT_HEADERS_INVALID', 'RATE_LIMIT_HEADERS_CONTRADICTORY',
    'RATE_LIMIT_RESET_STALE', 'RATE_LIMIT_RESET_REGRESSED', 'RATE_LIMIT_LIMIT_CHANGED_IN_WINDOW',
    'RATE_LIMIT_REMAINING_INCREASED', 'RATE_LIMIT_WINDOW_CHANGED_EARLY',
    'RATE_LIMIT_REMAINING_EXCEEDS_LOCAL_ACCOUNTING',
    'RATE_LIMIT_BALANCE_MIN_APPLIED', 'RATE_LIMIT_LOCAL_ACCOUNTING_UNAVAILABLE',
    'RECONCILIATION_UNAVAILABLE',
})
HEADER_STATES = frozenset({'missing', 'valid', 'invalid', 'stale', 'inconsistent'})
SERVICE_CODES = {
    'AUTHENTICATION_ERROR': 'authentication_error', 'AUTHORIZATION_ERROR': 'authorization_error',
    'INVALID_INPUT': 'invalid_input', 'INVALID_QUERY': 'invalid_query',
    'INVALID_REQUEST': 'invalid_request', 'INVALID_COUNT': 'invalid_count',
    'QUERY_ERROR': 'query_error', 'QUERY_PARSE_ERROR': 'query_parse_error',
    'INVALID_PARAMETER': 'invalid_parameter', 'BAD_REQUEST': 'bad_request',
    'RESOURCE_NOT_FOUND': 'resource_not_found', 'RATE_LIMIT_EXCEEDED': 'rate_limit_exceeded',
}


def quota_diagnostic(headers, epoch):
    values = {str(k).lower(): v for k, v in headers.items()}
    parsed, fields = {}, {}
    for name in ('limit', 'remaining', 'reset'):
        raw = values.get('x-ratelimit-' + name)
        state = 'missing' if raw is None else 'invalid'
        if isinstance(raw, str) and re.fullmatch(r'\s*[0-9]{1,18}\s*', raw):
            number = int(raw)
            if name != 'limit' or number > 0:
                parsed[name] = number
                state = 'valid'
        fields[name + '_status'] = state
    reason = 'RATE_LIMIT_HEADERS_VALID'
    if 'missing' in fields.values(): reason = 'RATE_LIMIT_HEADERS_MISSING'
    elif 'invalid' in fields.values(): reason = 'RATE_LIMIT_HEADERS_INVALID'
    elif parsed['remaining'] > parsed['limit']:
        fields['remaining_status'] = 'inconsistent'
        reason = 'RATE_LIMIT_HEADERS_CONTRADICTORY'
    else:
        try: datetime.fromtimestamp(parsed['reset'], tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            fields['reset_status'] = 'invalid'; reason = 'RATE_LIMIT_HEADERS_INVALID'
        if reason == 'RATE_LIMIT_HEADERS_VALID' and parsed['reset'] <= int(epoch):
            fields['reset_status'] = 'stale'; reason = 'RATE_LIMIT_RESET_STALE'
    for name, target in [('limit','quota_limit'),('remaining','quota_remaining'),('reset','quota_reset_epoch')]:
        if name in parsed and fields[name+'_status'] != 'invalid': fields[target]=parsed[name]
    fields.update(telemetry_reason=reason, observed_epoch=max(0, int(epoch)))
    return fields, tuple(parsed[n] for n in ('limit','remaining','reset')) if reason == 'RATE_LIMIT_HEADERS_VALID' else None


def service_diagnostic(body):
    result = {'remote_error_code': 'unclassified', 'error_category': 'unclassified',
              'error_parameter': 'unclassified', 'error_response_sha256': hashlib.sha256(body).hexdigest()}
    if len(body) > 65536: return result
    try: payload = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        if b'<!DOCTYPE' in body.upper() or b'<!ENTITY' in body.upper(): return result
        try:
            root=ET.fromstring(body)
            # Only the two documented error envelopes and fixed leaf fields.
            root_name=root.tag.rsplit('}',1)[-1]
            if root_name not in {'service-error','error-response'}: return result
            leaves={node.tag.rsplit('}',1)[-1]:node.text for node in root.iter()}
            payload=({'service-error':{'status':{'statusCode':leaves.get('statusCode'),'statusText':leaves.get('statusText')}}}
                     if root_name=='service-error' else {'error-response':{'error-code':leaves.get('error-code'),'error-message':leaves.get('error-message')}})
        except (ET.ParseError,ValueError,RecursionError): return result
    pairs = []
    for root, code, message in [('service-error','statusCode','statusText'), ('error-response','error-code','error-message')]:
        value = payload.get(root) if isinstance(payload, dict) else None
        if root == 'service-error' and isinstance(value, dict): value = value.get('status')
        if isinstance(value, dict): pairs.append((value.get(code), value.get(message)))
    known = [(SERVICE_CODES[c], m) for c,m in pairs if isinstance(c,str) and c in SERVICE_CODES]
    if len(set(c for c,m in known)) != 1: return result
    code, message = known[0]; result['remote_error_code'] = code
    if code in {'invalid_query','query_error','query_parse_error'}:
        result.update(error_category='query_syntax', error_parameter='query')
    elif code in {'invalid_input','invalid_request','invalid_parameter','invalid_count','bad_request'}:
        result['error_category'] = 'invalid_parameter'
    elif code in {'authentication_error','authorization_error'}: result['error_category'] = 'access'
    if code == 'invalid_count': result['error_parameter'] = 'count'
    # Recognize only complete, numeric templates. No arbitrary message fragment,
    # echoed query, URL, token, or key can be copied into a control record.
    if isinstance(message,str) and len(message) <= 160:
        match = re.fullmatch(r'Requested count ([0-9]{1,6}) exceeds (?:the )?maximum(?: of)? ([0-9]{1,6})\.?', message, re.I)
        if match and result['error_category'] == 'invalid_parameter':
            maximum = int(match.group(2))
            if 0 < maximum <= 100000:
                result.update(error_parameter='count', service_max_count=maximum)
    return result
