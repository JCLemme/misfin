import os
import sys
import datetime

from transponder.identity import Identity, LocalIdentity
from transponder.misfin import Request

# transponder - development misfin client/server
# misfin letter format ("gemmail")
# lem (2023)

# this is software in flux - don't rely on it


class Letter:
    """ A Misfin letter, with the ability to parse gemmail lines. """
    """ This class is !nasty! and needs rework. """

    def __init__(self, sender: LocalIdentity, recipients: list[Identity], message: str, received_at=datetime.datetime.now()):
        self.sender = sender
        self.recipients = recipients
        self.message = message
        self.received_at = received_at

    def _extract_recipients(message):
        found = []
        lines = message.splitlines()
        for i, line in enumerate(lines):
            if len(line) > 0 and line[0] == ":":
                line = line.removeprefix(":").strip()
                del lines[i]
                addrs = line.split(" ")
                for a in addrs:
                    try: found.append(Identity(a))
                    except: pass

        return found, "\n".join(lines)

    def _extract_sender(message):
        sender = None       
        lines = message.splitlines()
        for i, line in enumerate(lines):
            if len(line) > 0 and line[0] == "<":
                line = line.removeprefix("<").strip()
                del lines[i]
                addy = line.split(" ", 1)
                address = addy[0]
                blurb = ""
                if len(addy) > 1: blurb = addy[1]
                try: sender = Identity(address, blurb=blurb)
                except: pass
                break

        return sender, "\n".join(lines)

    def _extract_timestamp(message):
        timest = None
        lines = message.splitlines()
        for i, line in enumerate(lines):
            if len(line) > 0 and line[0] == "@":
                line = line.removeprefix("@").strip()
                del lines[i]
                marked, *_ = line.split(" ", 1)
                try: timest = datetime.fromisoformat(marked)
                except: pass
                break

        return timest, "\n".join(lines)

    @classmethod
    def incoming(cls, sender: Identity, req: Request):
        """ Reassembles a Letter from an incoming request. """
        found_recipients, message = cls._extract_recipients(req.payload)
        return cls(sender, [req.recipient] + found_recipients, message)

    @classmethod
    def load(cls, raw):
        """ Reassembles a Letter from a text file. """
        recipients, raw = cls._extract_recipients(raw)
        sender, raw = cls._extract_sender(raw)
        received_at, raw = cls._extract_timestamp(raw)
        return cls(sender, recipients, raw, received_at)

    def build(self, include_timestamp=True, force_recipients=False):
        message = "< {} {}\n".format(self.sender.address(), self.sender.blurb)

        if force_recipients or len(self.recipients) > 1:
            message += ": " 
            for a in self.recipients: message += "{} ".format(a.address())
            message += "\n"

        if include_timestamp and isinstance(self.received_at, datetime.datetime):
            message += "@ {}\n".format(self.received_at.isoformat())

        message += self.message
        return message
