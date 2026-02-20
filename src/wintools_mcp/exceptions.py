"""Exception hierarchy for wintools-mcp."""


class WintoolsError(Exception):
    pass


class ToolNotFoundError(WintoolsError):
    pass


class ToolNotInCatalogError(WintoolsError):
    pass


class ExecutionError(WintoolsError):
    pass


class TimeoutError(WintoolsError):
    pass


class DenylistError(WintoolsError):
    pass
