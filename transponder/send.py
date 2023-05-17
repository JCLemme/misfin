import os
import sys
import argparse

import transponder.identity
import transponder.misfin

# transponder - development misfin client/server
# interactive message sender
# lem (2023)

# this is software in flux - don't rely on it


if __name__ == "__main__":

    parser = argparse.ArgumentParser(prog="transponder.send", description="Sends a Misfin message, either from arguments or interactively")

    parser.add_argument("-a", "--from", dest="sender", help="Address or identity to send as")
    parser.add_argument("-t", "--to", dest="recipient", help="Recipient's address")
    parser.add_argument("-m", "--message", help="Message to send, or - to read from stdin")

    parser.add_argument("-c", "--confirm", action="store_true", help="Ask user before sending message")

    args = parser.parse_args()

    # ---

    if args.sender is None:
        args.sender = input("From (filename or address): ")

    if any(ext in args.sender for ext in [".who", ".cert", ".pem"]):
        try:
            raw_ident = open(args.sender, "rb").read()
            ident = transponder.identity.LocalIdentity(raw_ident, raw_ident)
        except Exception as err:
            print(err)
            print("Couldn't load that identity.")
            sys.exit(1)
    else:
        print("Stub: no maildir to load identity from yet.")
        sys.exit(1)


    if args.recipient is None:
        args.recipient = input("To: ")

    try:
        recipient = transponder.identity.Identity(args.recipient)
    except Exception as err:
        print(err)
        print("Can't send there - malformed address?")
        sys.exit(1)


    if args.message is None or args.message == "-":
        # Ugly way to hide prompt for users that plan on piping
        if args.message is None: print("Enter your message - hit Ctrl+D on a blank line to finish")
        args.message = sys.stdin.read()
        args.message = args.message.rstrip()
   
    try:
        req = transponder.misfin.Request(recipient, args.message)
    except Exception as err:
        print(err)
        print("Can't send that message.")
        sys.exit(1)


    if args.confirm:
        print("")
        print(f"Sending this message from {ident.longform()} to {recipient.address()}:")
        print(f"{req.payload}")

        if ["y", "yes"] not in input("Go ahead? [y/n]").lower():
            print("Not sending.")
            sys.exit(1)

    
    resp = transponder.misfin.send_as(ident, req)

    if resp.was_successful():
        print(f"Message delivered. Recipient fingerprint is {resp.meta}")
        sys.exit()
    elif resp.was_redirect():
        print(f"Message bounced - try sending to {resp.meta}")
        sys.exit(1)
    else:
        print(f"Couldn't deliver message. Response was ({resp}).")
        sys.exit(1)
