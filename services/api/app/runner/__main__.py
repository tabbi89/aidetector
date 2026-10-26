import sys

if "--auth-check" in sys.argv[1:]:
    # Credential check only: a few GETs per identity, a report on stdout.
    from app.runner.auth_check import main as auth_check_main

    raise SystemExit(auth_check_main())

from app.runner.main import main

raise SystemExit(main())
