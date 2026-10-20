"""The CLI heavy lane's bounded whitebox agent.

Phase 3 of the two-lane split: a bounded agent that drives the existing engine
plus sandboxed tools and reads project source for whitebox analysis, with hard
caps and the same safety posture as the rest of the runner. Every module here
is DB-free (the runner has no database) and treats source and tool output as
evidence, never instructions.
"""
