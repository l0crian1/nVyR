"""Generate runtime schemas for wheels, editable installs, and source archives."""

from pathlib import Path
import sys

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.editable_wheel import editable_wheel
from setuptools.command.sdist import sdist

# PEP 517 executes setup.py without adding the source root to sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_tools.schema_builder import build_schemas


class BuildPy(build_py):
    def run(self):
        super().run()
        build_schemas(output=Path(self.build_lib) / 'nvyr/schemas')


class EditableWheel(editable_wheel):
    def run(self):
        build_schemas()
        super().run()


class Sdist(sdist):
    def run(self):
        build_schemas()

        # Source archives include the GPL FRR patch; runtime wheels do not.
        metadata = self.distribution.metadata
        original_license = metadata.license_expression
        metadata.license_expression = 'MIT AND GPL-2.0-or-later'
        try:
            super().run()
        finally:
            metadata.license_expression = original_license


setup(
    license_expression='MIT',
    cmdclass={'build_py': BuildPy, 'editable_wheel': EditableWheel, 'sdist': Sdist},
)
