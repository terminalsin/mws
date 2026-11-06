"""Hand-written call sequences, one module per service (or service family).

Importing this package registers every scenario in `parity.dsl.REGISTRY`.
"""

import importlib
import pkgutil

for _m in pkgutil.iter_modules(__path__):
    importlib.import_module(f"{__name__}.{_m.name}")
