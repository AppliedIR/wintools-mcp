"""Exception hierarchy for wintools-mcp."""


class WintoolsError(Exception):
    pass


class ToolNotInCatalogError(WintoolsError):
    pass


class ExecutionError(WintoolsError):
    pass


class ExecutionTimeoutError(WintoolsError):
    pass


class DenylistError(WintoolsError):
    pass
