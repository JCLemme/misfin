misfin (is) mail (for the) small web
====================================

💬 📯 📬

    misfin://hello@misfin.org What's up?\r\n
    ↓↓↓↓
    20 1e:9f:11:e4:8f:aa:12:b3:cb...

what is this?
-------------
Misfin is to email what Gemini is to the Web. Set up a Misfin server alongside your Gemini capsule, and start networking with other capsuleers - no signup required. For the full details, see gemini://misfin.org/ .

details?
--------
A Misfin message is a single string of UTF-8 gemtext, no more than 2,048 characters long. Want to write more? Send two messages. What about attachments? Host it on a Gemini server and add a link line - you get the fingerprint of your recipient back, so you can even gate access if it's eyes only.
Keeping Misfin mail simple makes it a better fit for the small web - it's easier to implement, easier to secure, and easier to keep running. 

i don't like it?
----------------
Good, because we're still trying to nail down the details. This version is Misfin(B), but there's another, more SMTP-like version - Misfin(A) - that is also implemented here. Eventually we're settling on one or the other, but feel free to experiment.
For the moment though? Download the reference implementation, make a certificate, and send your comments to misfin://rfc@misfin.org. (Or make a ticket on [sourcehut](https://todo.sr.ht/~lem/misfin-rfc), or on [Github](https://github.com/JCLemme/misfin), or post about it on station, or w/e).

run your own
------------
There isn't a production mailserver written yet, but you can run the testing suite and send/receive mail. Run `python -m misfin` to see how. (You'll need to install `pyopenssl` first).

    python -m misfin make-cert queen "Queen bee" hive.com queen_hive.pem
    python -m misfin receive-as queen_hive.pem

    ...

    python -m misfin make-cert bee "Worker bee" hive.com bee_hive.pem
    python -m misfin send-as bee_hive.pem queen@hive.com "Where's the flowers at"
