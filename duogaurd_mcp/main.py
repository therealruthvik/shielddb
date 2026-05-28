import sys
import os
import uvicorn
import logging

# Ensure parent directory is in path so absolute imports work when run as script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure logging to stderr so it doesn't pollute stdout for MCP stdio JSON-RPC
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("ShieldDBCLI")

def print_help():
    help_text = """
ShieldDB: The Guarded Autonomous Database Administrator CLI

Usage:
  python -m duogaurd_mcp.main <command> [options]

Commands:
  run          Starts the FastMCP Model Context Protocol (MCP) server over standard I/O (stdio).
               Use this to connect ShieldDB to Claude Desktop, Cursor, or your AI agents.
  dashboard    Starts the FastAPI REST server and Security Dashboard backend API on port 8000.
               Use this to host the interactive safety playground and stats console.
  download     Pre-downloads and caches the 'DuoGuard-0.5B' and tokenizer models locally.
               Use this to verify model integrity and speed up initial server booting.
  populate     Explicitly initializes the database connection and seeds mock customer tables.
  help         Prints this help card.
"""
    print(help_text, file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)
        
    cmd = sys.argv[1].lower().strip()
    
    if cmd == "run":
        from duogaurd_mcp.server import run as run_server
        run_server()
        
    elif cmd == "dashboard":
        logger.info("Initializing ShieldDB REST Gateway API on port 8000...")
        # Import api here so singletons are initialized inside the command thread
        from duogaurd_mcp.api import app
        
        # Load dotenv if exists
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
            
        logger.info("Starting Uvicorn REST API server on http://localhost:8000...")
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
        
    elif cmd == "download":
        logger.info("Running manual pre-download check for DuoGuard models...")
        from duogaurd_mcp.moderator import DuoGuardModerator
        # Initialize and force load synchronously
        mod = DuoGuardModerator(auto_load=False)
        mod.load_model()
        if mod.is_ready:
            logger.info("Pre-download completed successfully. All weights and tokens cached locally!")
            sys.exit(0)
        else:
            logger.error("Pre-download failed. Check internet connectivity or Hugging Face rate limits.")
            sys.exit(1)
            
    elif cmd == "populate":
        logger.info("Initializing database connection for mass mock data seeding...")
        from duogaurd_mcp.seed_large_data import seed_large_data
        try:
            seed_large_data()
            logger.info("Database populating completed successfully!")
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error populating database: {e}")
            sys.exit(1)
        
    elif cmd in ["help", "--help", "-h"]:
        print_help()
        sys.exit(0)
        
    else:
        logger.error(f"Unknown command: '{cmd}'")
        print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
