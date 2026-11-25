"""Ghidra adapter for VxAtlas. Import Ghidra classes only after ``pyghidra.start()``."""

from .languages import language_for

__all__ = ["language_for"]
__version__ = "0.1.0.dev0"
