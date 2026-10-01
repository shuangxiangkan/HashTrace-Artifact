"""Allow ``python -m hashtrace`` to run the command-line interface."""

from .cli import main


raise SystemExit(main())

