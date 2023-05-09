#!/usr/bin/python

import struct
import logging

from tls.alert import *
from tls.handshake import *


class TLSRecord(object):

    # Content types
    ChangeCipherSpec = 0x14
    Alert = 0x15
    Handshake = 0x16
    Application = 0x17
    Heartbeat = 0x18

    content_types = {
        0x14: "ChangeCipherSpec",
        0x15: "Alert",
        0x16: "Handshake",
        0x17: "Application",
        0x18: "Heartbeat",
    }

    # TLS versions
    SSL3 = 0x0300
    TLS1_0 = 0x0301
    TLS1_1 = 0x0302
    TLS1_2 = 0x0303
    TLS1_3 = 0x0304

    tls_versions = {
        0x0300: "SSL3",
        0x0301: "TLS1_0",
        0x0302: "TLS1_1",
        0x0303: "TLS1_2",
        0x0304: "TLS1_3",
    }

    def __init__(self):
        self.bytes = ""

    @classmethod
    def create(cls, content_type, version, message, length=-1):
        self = cls()

        # TODO: support mac=None, padding=None

        if length < 0:
            length = len(message)

        fmt = "!BHH%ds" % (length)
        if isinstance(message, str):
            message = message.encode("utf-8")

        self.bytes = struct.pack(fmt, content_type, version, length, message)

        return self

    @classmethod
    def from_bytes(cls, provided_bytes):
        self = cls()
        self.bytes = provided_bytes
        return self

    def content_type(self):
        val = self.bytes[0]
        if isinstance(val, bytes):
            val = ord(val)
        return val

    def version(self):
        (version,) = struct.unpack("!H", self.bytes[1:3])
        return version

    def message_length(self):
        (length,) = struct.unpack("!H", self.bytes[3:5])
        return length

    def message(self):
        return self.bytes[5 : self.message_length() + 5]

    def messages(self):
        """
        Convenience method that returns the messages wrapped in the right type. To
        keep things consistent it always returns a list even though only handshake
        records can contain multiple messages.
        """

        if self.content_type() == self.Handshake:
            return self.handshake_messages()
        elif self.content_type() == self.ChangeCipherSpec:
            return [ChangeCipherSpecMessage.from_bytes(self.message())]
        elif self.content_type() == self.Alert:
            return [AlertMessage.from_bytes(self.message())]
        elif self.content_type() == self.Application:
            return [ApplicationMessage.from_bytes(self.message())]
        elif self.content_type() == self.Heartbeat:
            return [HeartbeatMessage.from_bytes(self.message())]
        else:
            return [UnknownMessage.from_bytes(self.message())]

    def handshake_messages(self):
        if self.content_type() != self.Handshake:
            raise Exception("Not a Handshake record")

        messages = []

        # A single handshake record can contain multiple handshake messages
        processed_bytes = 0
        while processed_bytes < self.message_length():
            message = HandshakeMessage.from_bytes(self.message()[processed_bytes:])
            processed_bytes += message.message_length() + 4
            messages += [message]

        return messages

    def __len__(self):
        return len(self.bytes)


#
# Utilities for processing responses
#


def read_tls_record(f):
    logger = logging.getLogger("pytls")

    hdr = f.read(5)
    if hdr == "":
        raise IOError(
            "Unexpected EOF receiving record header - server closed connection"
        )

    if len(hdr) < 5:
        raise IOError(
            f"Unexpected EOF receiving record header ({len(hdr)=} - server closed connection"
        )

    typ, ver, ln = struct.unpack(">BHH", hdr)
    logger.debug("%d\t0x%x\t%d", typ, ver, ln)

    pay = f.read(ln)
    if pay == "":
        raise IOError(
            "Unexpected EOF receiving record payload - server closed connection"
        )

    logger.debug(
        " ... received message: type = %d (%s), ver = %04x, length = %d",
        typ,
        TLSRecord.content_types.get(typ, "UNKNOWN!"),
        ver,
        len(pay),
    )

    if typ == TLSRecord.Handshake:
        message_type = pay[0]
        if isinstance(message_type, bytes):
            message_type = ord(message_type)

        logger.debug(
            ">>> Handshake message: %s",
            HandshakeMessage.message_types.get(message_type, "UNKNOWN!"),
        )
    elif typ == TLSRecord.Alert:
        message_type = pay[1]
        if isinstance(message_type, bytes):
            message_type = ord(message_type)

        logger.debug(
            ">>> Alert message: %s",
            AlertMessage.alert_types.get(message_type, "UNKNOWN!"),
        )

    return TLSRecord.from_bytes(hdr + pay)
