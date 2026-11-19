"""Enable ``python -m nginx_h2_probe ...`` as an alias for the CLI."""

import sys

from nginx_h2_probe.cli import main

if __name__ == "__main__":
    sys.exit(main())
