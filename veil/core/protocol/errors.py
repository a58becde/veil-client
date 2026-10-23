"""Коды ошибок протокола (spec/09-errors.md). Тот же список у сервера — сверяется общим вектором error_codes."""

E_VERSION = "E_VERSION"
E_MALFORMED = "E_MALFORMED"
E_NOT_ENVELOPE = "E_NOT_ENVELOPE"
E_DECRYPT = "E_DECRYPT"
E_SIG = "E_SIG"
E_CLOCK = "E_CLOCK"
E_REPLAY = "E_REPLAY"
E_TOKEN_MISSING = "E_TOKEN_MISSING"
E_TOKEN_INVALID = "E_TOKEN_INVALID"
E_TOKEN_SPENT = "E_TOKEN_SPENT"
E_TOKEN_DAY = "E_TOKEN_DAY"
E_RATE = "E_RATE"
E_BOT_NOT_BOUND = "E_BOT_NOT_BOUND"
E_DEVICE = "E_DEVICE"
E_STALE = "E_STALE"
E_CONTENT_MISMATCH = "E_CONTENT_MISMATCH"
E_UNSUPPORTED = "E_UNSUPPORTED"
E_TOO_LONG = "E_TOO_LONG"
E_NOT_FOUND = "E_NOT_FOUND"
E_NOT_OWNER = "E_NOT_OWNER"
E_EDIT_WINDOW = "E_EDIT_WINDOW"
E_EDIT_LIMIT = "E_EDIT_LIMIT"
E_NICK_INVALID = "E_NICK_INVALID"
E_NICK_COOLDOWN = "E_NICK_COOLDOWN"
E_NICK_TAKEN = "E_NICK_TAKEN"
E_TELEGRAM = "E_TELEGRAM"
E_UNCONFIRMED = "E_UNCONFIRMED"  # публикация ушла в Telegram без подтверждения: пост мог выйти (spec/09)
E_INTERNAL = "E_INTERNAL"
E_PENDING = "E_PENDING"  # действие принято (токен потрачен) и ждёт очереди: повторить тот же конверт

CODES = (E_VERSION, E_MALFORMED, E_NOT_ENVELOPE, E_DECRYPT, E_SIG, E_CLOCK, E_REPLAY, E_TOKEN_MISSING, E_TOKEN_INVALID,
         E_TOKEN_SPENT, E_TOKEN_DAY, E_RATE, E_BOT_NOT_BOUND, E_DEVICE, E_STALE, E_CONTENT_MISMATCH, E_UNSUPPORTED,
         E_TOO_LONG, E_NOT_FOUND, E_NOT_OWNER, E_EDIT_WINDOW, E_EDIT_LIMIT, E_NICK_INVALID, E_NICK_COOLDOWN,
         E_NICK_TAKEN, E_TELEGRAM, E_UNCONFIRMED, E_INTERNAL, E_PENDING)


class ProtocolError(Exception):
    def __init__(self, code: str, message: str = "", **extra):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.extra = extra
