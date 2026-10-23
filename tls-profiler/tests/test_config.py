from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from src.decider_agent.config import load_project_environment


class ProjectEnvironmentTests(unittest.TestCase):
    def test_loads_project_dotenv_without_overriding_process_environment(self) -> None:
        variable = "TLS_PROFILER_DOTENV_TEST"
        original_value = os.environ.pop(variable, None)
        try:
            with tempfile.TemporaryDirectory() as directory:
                project_root = Path(directory)
                (project_root / ".env").write_text(
                    f"{variable}=from-file\n",
                    encoding="utf-8",
                )
                load_project_environment(project_root)
                self.assertEqual(os.environ[variable], "from-file")

                os.environ[variable] = "from-process"
                load_project_environment(project_root)
                self.assertEqual(os.environ[variable], "from-process")
        finally:
            os.environ.pop(variable, None)
            if original_value is not None:
                os.environ[variable] = original_value


if __name__ == "__main__":
    unittest.main()
