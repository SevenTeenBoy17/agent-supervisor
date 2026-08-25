"""The v8 files below are executable legacy harnesses, not pytest modules.

They remain on disk for forensic replay but are deliberately unreferenced by v3.  Importing
them executes process-level tests and ``sys.exit`` during collection.
"""

collect_ignore = [
    "test_dispatch_ledger.py",
    "test_precision.py",
    "test_retrieval.py",
    "test_verifier.py",
]
