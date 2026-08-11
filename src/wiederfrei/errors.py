"""Exception types shared across the package."""


class WiederfreiError(Exception):
    """Base class for errors this tool raises deliberately."""


class ConfigError(WiederfreiError):
    """The rules file or environment configuration is invalid."""


class NotifyError(WiederfreiError):
    """An alert could not be delivered."""
