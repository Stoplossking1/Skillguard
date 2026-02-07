"""SGScanner exception hierarchy."""


class ScanError(Exception):
    """Base exception for all SGScanner errors."""
    pass


class IngestionError(ScanError):
    """Raised when a skill directory cannot be loaded or parsed."""
    pass


class EngineError(ScanError):
    """Raised when a scan engine encounters an unrecoverable error."""
    pass


class ValidationError(ScanError):
    """Raised when skill content fails validation checks."""
    pass
