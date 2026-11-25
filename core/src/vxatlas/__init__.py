"""VxAtlas core: identify VxWorks images, recover load address and symbols."""

from .analyze import analyze, analyze_file
from .model import Analysis, Confidence, Evidence, Symbol, SymbolTable

__all__ = [
    "analyze",
    "analyze_file",
    "Analysis",
    "Confidence",
    "Evidence",
    "Symbol",
    "SymbolTable",
]
__version__ = "0.1.0"
