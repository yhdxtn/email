class AgentError(Exception):
    """Public errors carry only stable, non-sensitive codes."""
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status
