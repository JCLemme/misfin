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
    """ This class is still being worked on, but is a lot less nasty than it was """

    def __init__(self, sender: LocalIdentity, recipients: list[Identity], message: str, received_at=datetime.datetime.now()):
        self.sender = sender
        self.recipients = recipients
        self.message = message
        self.received_at = received_at

    def _seek_and_destroy(message, linetype):
        """ Extracts out the first line of a given type from the message. """
        found = None
        message_lines = message.splitlines()
        for idx, line in enumerate(message_lines):
            if len(line) > 0 and line[0] == linetype:
                found = line.removeprefix(linetype).strip()
                del message_lines[i]
                break

        return found, "\n".join(message_lines)

    def _extract_sender(message):
        found, message = super()._seek_and_destroy(message, "<")
        if found is None: return None, message

        sender = None
        contents = found.split(" ", 1)
        address = contents[0]

        if len(contents) > 1: blurb = contents[1]
        else: blurb = ""

        try: sender = Identity(address, blurb)
        except: pass

        return sender, message

    def _extract_recipients(message):
        found, message = super()._seek_and_destroy(message, ":")
        if found is None: return None, message

        recipients = []
        for address in found:
            try: recipients.append(Identity(address))
            except: pass

        return recipients, message

    def _extract_timestamp(message):
        found, message = super()._seek_and_destroy(message, "@")
        if found is None: return None, message

        try: timestamp = datetime.fromisoformat(found)
        except: timestamp = None

        return timestamp, message

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
