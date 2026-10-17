"""Exercise optional archive export without opening the collector's UDP socket."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest
from unittest import mock


COLLECTOR = Path(__file__).resolve().parents[1] / "mac" / "collect-windows.py"


def load_archive_export():
    tree = ast.parse(COLLECTOR.read_text(encoding="utf-8"))
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "collect_archives")
    namespace = dict(Path=Path, os=os, shutil=shutil, signal=signal,
                     subprocess=subprocess, json=json, __file__=str(COLLECTOR))
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(COLLECTOR), "exec"), namespace)
    return namespace["collect_archives"]


class CollectWindowsArchiveTests(unittest.TestCase):
    def test_relative_output_remains_under_callers_directory(self):
        collect = load_archive_export()
        with tempfile.TemporaryDirectory() as temporary:
            caller = Path(temporary).resolve()
            output = caller / "requested-evidence"
            output.mkdir()
            primary = output / "windows-diagnostics.json"
            primary.write_text('{"existing":"evidence"}', encoding="utf-8")
            process = mock.Mock(returncode=0)
            process.communicate.return_value = ("Archive collection: complete\n", None)
            previous = Path.cwd()
            try:
                os.chdir(caller)
                with mock.patch.object(subprocess, "Popen", return_value=process) as launch:
                    with contextlib.redirect_stdout(io.StringIO()):
                        collect(Path("requested-evidence"))
            finally:
                os.chdir(previous)
            command = launch.call_args.args[0]
            self.assertEqual(command[-1], str(output / "connection-archives"))
            self.assertEqual(launch.call_args.kwargs["cwd"], COLLECTOR.parents[1])
            self.assertEqual(json.loads((output / "archive-collection.json").read_text())["status"], "complete")
            self.assertEqual(primary.read_text(), '{"existing":"evidence"}')


if __name__ == "__main__":
    unittest.main()
