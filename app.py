import os
import discord
from discord.ext import commands
from dotenv import load_dotenv
from Enforcer import Enforcer

# Load environment variables
load_dotenv()

# Initialize bot
bot = Enforcer()

# Run the bot
bot.run(os.getenv('DISCORD_TOKEN')) 