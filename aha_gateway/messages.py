"""Every text the gateway itself sends to a person. Nothing here contains user data."""

NOT_CONNECTED = (
    "No aha computer is connected for this number right now. If you've paired it, the computer may be off "
    "or offline: messages aren't kept, so please send it again when it's on. To link this number, run "
    "`aha pair` on your computer and send the code here, like: PAIR 7K3-QF9"
)
PAIR_UNKNOWN = "That pairing code isn't valid or has expired. Run `aha pair` on your computer for a new one."
PAIR_OFFLINE = "The computer that made that code isn't connected any more. Run `aha pair` again."
PAIRED = "Paired with {name}. Say hi!"
NOT_SUBSCRIBED = "This aha computer's subscription isn't active, so messages can't be delivered. {link}"
SLOW_DOWN = "You're sending messages faster than aha can take them. Please wait a moment."
