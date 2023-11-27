from unittest.mock import MagicMock

class MockActionEvent:
    def __init__(self, params={}):
        self.params = params
        self.fail = MagicMock()
        self.set_results = MagicMock()
