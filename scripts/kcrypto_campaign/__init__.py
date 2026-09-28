# SPDX-License-Identifier: GPL-3.0-or-later
"""P8/T13 common campaign harness (audited, self-contained).

Package layout per the remaining-tests plan: strict versioned
input manifests (``inputs``), owned-guest custody (``owned_guest``),
atomic terminal receipts (``receipt``), offline reconciliation
(``reconcile``), pre/post-GO identity validation (``identity``) and
the R-cell oracle predicates (``oracles``).

``owned_guest``/``receipt`` are promoted from the reviewed P2 seed
(``tests/kcrypto_campaign/``); ``owned_guest`` carries the P8
extensions (owned command identity, spawn/stop receipts, the
``run_cell`` wrapper) while ``receipt`` stays byte-identical to
the seed. Import only as a package (``from kcrypto_campaign
import inputs``) so these modules never collide with the P2 seed
on ``sys.path``.
"""

__all__ = ["identity", "inputs", "oracles", "owned_guest", "receipt", "reconcile"]
