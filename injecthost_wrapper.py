#!/usr/bin/env python3
"""
Wrapper script for InjectHost CLI.
Sets up the Python path to include the application modules.
"""

import sys
import os
from pathlib import Path

# Get the directory where the modules are installed
module_dir = Path("/usr/local/lib/injecthost")

# Add the module directory to Python path so modules can be found
if str(module_dir) not in sys.path:
    sys.path.insert(0, str(module_dir))

# Now import and run the main application
if __name__ == "__main__":
    from injecthost import main
    main() 