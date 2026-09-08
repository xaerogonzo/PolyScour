r"""Storage analysis. Reads, measures, describes — and changes nothing.

This package deliberately has no planner and no executor, and imports neither.
That absence is the design: `cleaning/` is DISCOVER -> ANALYZE -> PLAN ->
EXECUTE, and this stops after ANALYZE. Filing a read-only walker next to the
only module that removes things is how the two eventually get confused.

It also calls no guard, which `docs/adr/0007` explains at length because a
reviewer should expect one. The short version: the guard constrains what may be
*changed*, there is nothing here to authorise, and calling it would refuse
every byte this package exists to describe.
"""
