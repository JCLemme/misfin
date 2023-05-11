import os
import sys
import datetime

from transponder.identity import Identity, LocalIdentity
from transponder.letter import Letter
from transponder.misfin import Request, Response
import transponder.misfin as tmm

# transponder - development misfin client/server
# debugging interface
# lem (2023)

# this is software in flux - don't rely on it


def _allow_anything(server, peer, request):
    """ Callback that accepts any message to the server's mailbox. """
    """ SCARY! Only use for testing. """
    print("Incoming to {} from {}".format(request.recipient.mailbox, peer.longform()))
    print("Fingerprint is {}".format(peer.fingerprint))
    print("Message:")
    print("{}".format(request.payload))

    if request.recipient.mailbox == server.mailbox or request.recipient.mailbox in []:
        return Response.delivered(server.fingerprint)
    else:
        print("...but we aren't {}, we're {}".format(request.recipient.mailbox, server.mailbox))
        return Response.of(51)



if __name__ == "__main__":

    # I wasn't kidding.
    def print_usage():
        print("usage: python -m transponder.debug...")
        print("usage:           [make-cert mailbox blurb hostname output.who]")
        print("usage:           [cert-from parent.who mailbox blurb output.who]")
        print("usage:           [send-as identity.who destination 'message']")
        print("usage:           [receive-as identity.who]")
        sys.exit(-1)

    try:
        command = sys.argv[1]

        if command == "make-cert":
            mailbox, blurb, hostname, output = sys.argv[2:]

            ident = LocalIdentity.new(mailbox, blurb, hostname, is_ca=True)
            with open(output, "wb") as dest: dest.write(ident.as_pem())

            print("Generated cert for {} - saved to {}".format(ident.longform(), output))

        elif command == "cert-from":
            parent, mailbox, blurb, output = sys.argv[2:]

            loaded_pem = open(parent, "rb").read()
            parent_ident = LocalIdentity(loaded_pem, loaded_pem)
            ident = LocalIdentity.child_of(parent_ident, mailbox, blurb)
            with open(output, "wb") as dest: dest.write(ident.as_pem())

            print("Generated cert for {}, child of {} - saved to {}".format(ident.longform(), parent_ident.longform(), output))

        elif command == "send-as":
            sender, destination, message = sys.argv[2:]

            loaded_pem = open(sender, "rb").read()
            ident = LocalIdentity(loaded_pem, loaded_pem)

            msg = Request(Identity(destination), message)

            print(tmm.send_as(ident, msg))

        elif command == "receive-as":
            loaded_pem = open(sys.argv[2], "rb").read()
            ident = LocalIdentity(loaded_pem, loaded_pem)

            print("Receiving for {}".format(ident.longform()))
            tmm.receive_forever(ident, _allow_anything)

    except Exception as err:
        # Hehe
        #raise err
        print(type(err).__name__, err)
        print_usage()
