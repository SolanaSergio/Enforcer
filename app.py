import os
import sys
import logging
from dotenv import load_dotenv
from Enforcer import Enforcer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load environment variables
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')

if not TOKEN:
    logging.error("No Discord token found in environment variables!")
    sys.exit(1)

try:
    # Initialize the bot with optimized settings
    bot = Enforcer(
        chunk_guilds_at_startup=False,  # Don't load all members at start
        heartbeat_timeout=150.0  # Increase heartbeat timeout
    )
    
    # Run the bot with error handling
    bot.run(TOKEN, log_handler=None)  # Disable default discord.py logging
except Exception as e:
    logging.error(f"Failed to start bot: {str(e)}")
    sys.exit(1) 