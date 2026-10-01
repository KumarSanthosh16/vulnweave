"""Deliberately unsafe web settings for validating a local Semgrep pack.

Never copy these patterns into application code.
"""

import ssl


class DemoApp:
    def run(self, **_options: object) -> None:
        pass


app = DemoApp()
app.run(debug=True)
ssl._create_unverified_context()
