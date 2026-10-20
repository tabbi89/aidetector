"""Domain vocabulary shared by the engine, the models and the report layer.

Nothing in this package may import SQLAlchemy, FastAPI or anything from
``app.engine`` / ``app.models`` — these are the facts every layer agrees on,
so the dependency arrow points *into* here and never back out.
"""
