#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only SNMPv1 broadcast discovery, compatible with PySNMP 7.

Use a bounded UDP socket rather than the removed asyncore dispatcher.
Only BER/protocol handling depends on PySNMP. State is fresh per discovery.
"""
import socket
import time
from helper import output, conv

try:
    from pysnmp.proto import api
    from pyasn1.codec.ber import encoder, decoder
    pmod = api.PROTOCOL_MODULES[api.SNMP_VERSION_1]
    snmp_modules_found = True
    snmp_import_error = None
except ImportError as exc:
    snmp_modules_found = False
    snmp_import_error = str(exc)

timeout = 0.5
maxhost = 999


def build_request():
    pdu = pmod.GetRequestPDU()
    pmod.apiPDU.set_defaults(pdu)
    pmod.apiPDU.set_varbinds(pdu, (
        ('1.3.6.1.2.1.25.3.2.1.2.1', None),
        ('1.3.6.1.2.1.25.3.2.1.3.1', None),
        ('1.3.6.1.2.1.25.3.2.1.5.1', None),
        ('1.3.6.1.2.1.43.16.5.1.2.1.1', None),
        ('1.3.6.1.2.1.1.3.0', None),
    ))
    message = pmod.Message()
    pmod.apiMessage.set_defaults(message)
    pmod.apiMessage.set_community(message, 'public')
    pmod.apiMessage.set_pdu(message, pdu)
    return encoder.encode(message), int(pmod.apiPDU.get_request_id(pdu))


def parse_response(data, request_id):
    message, remainder = decoder.decode(data, asn1Spec=pmod.Message())
    if remainder or int(pmod.apiMessage.get_version(message)) != api.SNMP_VERSION_1:
        return None
    if pmod.apiMessage.get_community(message).asOctets() != b'public':
        return None
    pdu = pmod.apiMessage.get_pdu(message)
    if not pdu.isSameTypeWith(pmod.GetResponsePDU()):
        return None
    if int(pmod.apiPDU.get_request_id(pdu)) != request_id:
        return None
    if int(pmod.apiPDU.get_error_status(pdu)):
        return None
    values = {oid.prettyPrint(): value for oid, value in pmod.apiPDU.get_varbinds(pdu)}
    kind = values.get('1.3.6.1.2.1.25.3.2.1.2.1')
    # Require positive printer identification rather than treating every agent as a printer.
    if kind is None or kind.prettyPrint() != '1.3.6.1.2.1.25.3.1.5':
        return None
    def text(oid, default='?'):
        value = values.get(oid)
        return value.prettyPrint() if value is not None else default
    ticks = values.get('1.3.6.1.2.1.1.3.0')
    uptime = conv().elapsed(str(int(ticks)), 100, True) if ticks is not None else '?'
    return [text('1.3.6.1.2.1.25.3.2.1.3.1'), uptime,
            text('1.3.6.1.2.1.43.16.5.1.2.1.1'),
            text('1.3.6.1.2.1.25.3.2.1.5.1', '0')[:1]]


class discovery:
    def __init__(self, usage=False):
        if not snmp_modules_found:
            output().warning('SNMP support unavailable: ' + snmp_import_error)
            if usage:
                print('')
            return
        if usage:
            print('No target given, discovering local printers')
        results = {}
        try:
            packet, request_id = build_request()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(packet, ('255.255.255.255', 161))
                deadline = time.monotonic() + timeout
                while len(results) < maxhost:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        data, address = sock.recvfrom(65535)
                    except socket.timeout:
                        break
                    if address[1] != 161:
                        continue
                    try:
                        record = parse_response(data, request_id)
                    except Exception:
                        # Ignore malformed replies without aborting discovery.
                        continue
                    if record is not None:
                        results[address[0]] = record
            if results:
                print('')
                output().discover(('address', ('device', 'uptime', 'status', None)))
                output().hline(79)
                for printer in sorted(results.items(), key=lambda item: socket.inet_aton(item[0])):
                    output().discover(printer)
            else:
                output().info('No printers found via SNMP broadcast')
            if usage or results:
                print('')
        except Exception as exc:
            output().errmsg('SNMP Error', exc)
            if usage:
                print('')
