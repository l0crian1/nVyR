"""Errors and nonfatal warnings safe to disclose over the local RPC boundary."""

from contextlib import contextmanager
from dataclasses import dataclass


@dataclass(frozen=True)
class Warning:
    """Nonfatal feedback passed to context.report; never raised as an exception."""

    message: str

    def __str__(self):
        return f'Warning: {self.message}'


class RouterError(Exception):
    code = "configuration"

    def __init__(self, message, *, token=None, start=None, details=None):
        super().__init__(message)
        self.token, self.start, self.details = token, start, details or {}

    def as_dict(self):
        return {"code": self.code, "message": str(self), "token": self.token,
                "start": self.start, "details": self.details}


class ParseError(RouterError):
    code = "parse"


class ValidationError(RouterError):
    code = "validation"


class ConfirmationRequired(RouterError):
    code = "confirmation_required"


class LockError(RouterError):
    code = "lock"


class BusyError(RouterError):
    code = "busy"


class SessionExpiredError(RouterError):
    code = "session_expired"


class PersistenceError(RouterError):
    code = "persistence"


class RecoveryError(RouterError):
    """Live compensation failed: retain the transaction and block further commits."""

    code = "recovery"


@contextmanager
def recovery_required(message):
    """Classify expected failures after a live change that cannot be compensated here."""
    try:
        yield
    except RecoveryError:
        raise
    except (OSError, RouterError) as error:
        raise RecoveryError(f'{message}: {error}') from error


class OperationalError(RouterError):
    code = "operational"
