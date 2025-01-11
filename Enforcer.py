import discord
from discord.ext import commands
import asyncio
import json
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Set, Optional, Union
from collections import defaultdict
import aiohttp
import hashlib
from dataclasses import dataclass, asdict
import nltk
from nltk.tokenize import word_tokenize
from nltk.util import ngrams
import difflib
import base64
import time
import random
import string

# Download required NLTK data
try:
    nltk.download('punkt', quiet=True)
except:
    pass

@dataclass
class UserActivity:
    message_times: List[datetime]
    dm_attempts: int
    invite_uses: int
    mentions: int
    links_sent: int
    similar_messages: int
    last_checked: datetime

@dataclass
class ScamReport:
    user_id: int
    reporter_id: int
    timestamp: datetime
    reason: str
    evidence: str
    message_content: Optional[str]
    channel_id: Optional[int]

class MessageStore:
    def __init__(self, max_size: int = 1000):
        self.messages: List[str] = []
        self.max_size = max_size
        self.fingerprints: Set[str] = set()

    def add_message(self, content: str) -> bool:
        """Add message and return True if it's similar to existing messages"""
        fingerprint = self._generate_fingerprint(content)
        is_similar = fingerprint in self.fingerprints
        self.fingerprints.add(fingerprint)
        self.messages.append(content)
        
        if len(self.messages) > self.max_size:
            self.messages.pop(0)
            old_fingerprint = self._generate_fingerprint(self.messages[0])
            self.fingerprints.remove(old_fingerprint)
        
        return is_similar

    def _generate_fingerprint(self, content: str) -> str:
        """Generate a fingerprint for fuzzy matching"""
        tokens = word_tokenize(content.lower())
        three_grams = [''.join(g) for g in ngrams(tokens, 3)]
        fingerprint = hashlib.md5(''.join(sorted(three_grams)).encode()).hexdigest()
        return fingerprint

class EnforcerDatabase:
    def __init__(self, filename: str = 'enforcer_data.json'):
        self.filename = filename
        self.data = self.load_data()
        self.message_store = MessageStore()
        self.user_activities: Dict[int, UserActivity] = {}
        self.known_scam_domains: Set[str] = set()
        self.phishing_patterns: Set[str] = set()
        self.suspicious_links: Dict[str, int] = defaultdict(int)
        self.cached_user_risks: Dict[int, tuple] = {}
        self.last_scan_time = datetime.now()

    def load_data(self) -> dict:
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._create_default_data()

    def _create_default_data(self) -> dict:
        return {
            'guild_settings': {},
            'reported_users': {},
            'verified_users': set(),
            'trusted_users': set(),
            'banned_patterns': set(),
            'known_scammers': set(),
            'warning_history': {},
            'protection_settings': {},
            'custom_rules': {},
            'machine_learning_data': [],
            'automated_actions': {},
            'verification_requirements': {},
            'risk_thresholds': {
                'message_similarity': 0.85,
                'rapid_dm_threshold': 5,
                'mention_spam_threshold': 10,
                'link_spam_threshold': 3,
                'invite_spam_threshold': 3,
                'message_spam_threshold': 5
            }
        }

    def save_data(self):
        """Save data with error handling"""
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.data, f)
        except Exception as e:
            logging.error(f"Error saving safety data: {e}")

class ModeratorVerification:
    def __init__(self):
        self.verified_roles = {}  # {guild_id: role_id}
        self.verified_interactions = {}  # {user_id: [{"mod_id": int, "timestamp": datetime}]}

    def set_mod_role(self, guild_id: int, role_id: int):
        """Set the official moderator role for a guild"""
        self.verified_roles[guild_id] = role_id

    def is_verified_mod(self, member: discord.Member) -> bool:
        """Check if a member is a verified moderator based on their role"""
        guild_id = member.guild.id
        if guild_id not in self.verified_roles:
            return member.guild_permissions.administrator or member.guild_permissions.manage_messages
            
        mod_role = member.guild.get_role(self.verified_roles[guild_id])
        return mod_role in member.roles or member.guild_permissions.administrator

    def record_interaction(self, mod_id: int, user_id: int):
        """Record a legitimate moderator interaction"""
        if user_id not in self.verified_interactions:
            self.verified_interactions[user_id] = []
        
        self.verified_interactions[user_id].append({
            "mod_id": mod_id,
            "timestamp": datetime.now(timezone.utc)
        })

    def get_recent_interactions(self, user_id: int) -> List[dict]:
        """Get recent moderator interactions for a user"""
        if user_id not in self.verified_interactions:
            return []
            
        recent = [
            interaction for interaction in self.verified_interactions[user_id]
            if datetime.now(timezone.utc) - interaction["timestamp"] < timedelta(days=7)
        ]
        return recent

class ReportButton(discord.ui.View):
    def __init__(self, bot: 'Enforcer', suspicious_user: discord.User, message_content: str):
        super().__init__(timeout=None)  # Buttons don't timeout
        self.bot = bot
        self.suspicious_user = suspicious_user
        self.message_content = message_content

    @discord.ui.button(label="🚨 Report Scam", style=discord.ButtonStyle.red)
    async def report_scam(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Create report
        report = ScamReport(
            user_id=self.suspicious_user.id,
            reporter_id=interaction.user.id,
            timestamp=datetime.now(timezone.utc),
            reason="Suspicious DM - One-Click Report",
            evidence=self.message_content,
            message_content=self.message_content,
            channel_id=None
        )
        
        # Process the report
        for guild in interaction.user.mutual_guilds:
            await self.bot.process_detailed_report(guild, report)
        
        await interaction.response.send_message("✅ Thank you for reporting! Our moderators have been notified.", ephemeral=True)
        self.disable_all_items()
        await interaction.message.edit(view=self)

    @discord.ui.button(label="❌ Block User", style=discord.ButtonStyle.grey)
    async def block_user(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.user.block(self.suspicious_user)
            await interaction.response.send_message(f"✅ Blocked {self.suspicious_user.mention}", ephemeral=True)
        except:
            await interaction.response.send_message("❌ Unable to block user", ephemeral=True)
        
        self.disable_all_items()
        await interaction.message.edit(view=self)

class TrustRating:
    def __init__(self):
        self.trust_scores = {}
        self.score_factors = {
            'account_age': 0.3,
            'mutual_servers': 0.1,
            'verification_status': 0.2,
            'previous_reports': -0.4,
            'message_history': 0.2,
            'dm_behavior': -0.2
        }

    async def calculate_trust_score(self, user: discord.User, mutual_guilds: List[discord.Guild]) -> dict:
        """Calculate a trust score for a user"""
        score = 0.0
        reasons = []
        
        # Account age factor (0-1 score)
        account_age_days = (datetime.now(timezone.utc) - user.created_at).days
        age_score = min(account_age_days / 365, 1.0)  # Cap at 1 year
        score += age_score * self.score_factors['account_age']
        
        if account_age_days < 30:
            reasons.append("⚠️ Account less than 30 days old")

        # Mutual servers factor
        mutual_score = min(len(mutual_guilds) / 3, 1.0)  # Cap at 3 servers
        score += mutual_score * self.score_factors['mutual_servers']
        
        if len(mutual_guilds) < 2:
            reasons.append("⚠️ Few mutual servers")

        # Previous reports (stored in trust_scores)
        if user.id in self.trust_scores and 'reports' in self.trust_scores[user.id]:
            report_count = self.trust_scores[user.id]['reports']
            if report_count > 0:
                score += self.score_factors['previous_reports']
                reasons.append(f"🚨 Previously reported {report_count} times")

        # DM behavior
        if user.id in self.trust_scores and 'dm_violations' in self.trust_scores[user.id]:
            dm_violations = self.trust_scores[user.id]['dm_violations']
            if dm_violations > 0:
                score += self.score_factors['dm_behavior']
                reasons.append(f"⚠️ Previous suspicious DM activity")

        # Normalize score between 0 and 1
        final_score = max(min(score + 0.5, 1.0), 0.0)
        
        return {
            'score': final_score,
            'rating': self._get_rating(final_score),
            'reasons': reasons,
            'details': {
                'account_age_days': account_age_days,
                'mutual_servers': len(mutual_guilds),
                'raw_score': score
            }
        }

    def _get_rating(self, score: float) -> str:
        """Convert score to human-readable rating"""
        if score >= 0.8:
            return "Very Trustworthy"
        elif score >= 0.6:
            return "Trustworthy"
        elif score >= 0.4:
            return "Neutral"
        elif score >= 0.2:
            return "Suspicious"
        else:
            return "High Risk"

    def record_violation(self, user_id: int, violation_type: str):
        """Record a trust violation for a user"""
        if user_id not in self.trust_scores:
            self.trust_scores[user_id] = {'reports': 0, 'dm_violations': 0}
        
        if violation_type == 'report':
            self.trust_scores[user_id]['reports'] = self.trust_scores[user_id].get('reports', 0) + 1
        elif violation_type == 'dm':
            self.trust_scores[user_id]['dm_violations'] = self.trust_scores[user_id].get('dm_violations', 0) + 1

class ProfileAnalyzer:
    def __init__(self):
        self.suspicious_patterns = {
            'username': [
                r'mod[_-]?\d+',
                r'admin[_-]?\d+',
                r'staff[_-]?\d+',
                r'discord[_-]?(mod|admin|staff)',
                r'nitro[_-]?free',
                r'steam[_-]?gift'
            ],
            'avatar': [
                'default',
                'mod',
                'admin',
                'staff',
                'discord'
            ]
        }

    async def analyze_profile(self, user: discord.User) -> dict:
        """Analyze a user's profile for suspicious patterns"""
        results = {
            'suspicious_elements': [],
            'risk_level': 'LOW',
            'recommendations': []
        }

        # Check username patterns
        username = user.name.lower()
        for pattern in self.suspicious_patterns['username']:
            if re.search(pattern, username):
                results['suspicious_elements'].append(f"Suspicious username pattern: {pattern}")
                results['risk_level'] = 'HIGH'
                results['recommendations'].append("Username appears to impersonate staff")

        # Check if using default avatar
        if user.avatar is None:
            results['suspicious_elements'].append("Using default Discord avatar")
            results['recommendations'].append("No custom avatar set - common in throwaway accounts")
            results['risk_level'] = max(results['risk_level'], 'MEDIUM')

        # Check account age
        account_age = (datetime.now(timezone.utc) - user.created_at).days
        if account_age < 7:
            results['suspicious_elements'].append("Account less than 7 days old")
            results['risk_level'] = 'HIGH'
            results['recommendations'].append("Very new account - exercise caution")
        elif account_age < 30:
            results['suspicious_elements'].append("Account less than 30 days old")
            results['risk_level'] = max(results['risk_level'], 'MEDIUM')
            results['recommendations'].append("Relatively new account - be cautious")

        return results

class ScamDetector:
    def __init__(self):
        self.scam_patterns = {
            'phishing': [
                r'discord\s*nitro\s*free',
                r'steam\s*gift\s*free',
                r'free\s*nitro\s*generator',
                r'claim\s*your\s*nitro',
                r'nitro\s*giveaway',
                r'@everyone\s*free',
                r'discord\s*staff\s*here',
            ],
            'impersonation': [
                r'discord\s*mod(?:erator)?',
                r'discord\s*admin(?:istrator)?',
                r'official\s*staff',
                r'server\s*staff',
            ],
            'malicious_links': [
                r'dlscord\.(?:gift|com)',
                r'steamcommunnity\.com',
                r'dlscordnitro\.gift',
                r'discordgift\.site',
            ]
        }
        self.known_scam_domains = set()
        self.phishing_patterns = set()
        self.recent_scams = defaultdict(list)  # guild_id -> List[recent scam messages]
        self.shared_scam_alerts = defaultdict(list)  # For cross-server alerts

    async def add_scam_domain(self, domain: str):
        """Add a domain to the known scam domains list"""
        self.known_scam_domains.add(domain.lower())

    async def remove_scam_domain(self, domain: str):
        """Remove a domain from the known scam domains list"""
        self.known_scam_domains.discard(domain.lower())

    async def share_scam_alert(self, guild_id: int, alert: dict):
        """Share a scam alert with other servers"""
        self.shared_scam_alerts[guild_id].append({
            **alert,
            'timestamp': datetime.now(timezone.utc)
        })
        # Keep only last 50 alerts
        self.shared_scam_alerts[guild_id] = self.shared_scam_alerts[guild_id][-50:]

    async def analyze_message(self, message: discord.Message) -> tuple[bool, str, list]:
        """Enhanced analysis of a message for scam patterns"""
        detected_categories = []
        content = message.content.lower()
        
        # Check each category of scam patterns
        for category, patterns in self.scam_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    detected_categories.append(category)
                    break

        # Check for known scam domains
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', content)
        for url in urls:
            domain = url.split('/')[2]
            if domain in self.known_scam_domains:
                detected_categories.append("malicious_domain")
            elif any(scam_domain in domain for scam_domain in self.scam_patterns['malicious_links']):
                detected_categories.append("suspicious_domain")

        # Check message characteristics
        if message.mention_everyone or len(message.mentions) > 5:
            detected_categories.append("mass_mentions")

        if len(urls) > 2:
            detected_categories.append("multiple_links")

        # Generate detailed reason if scam detected
        is_scam = len(detected_categories) > 0
        reason = self._generate_reason(detected_categories) if is_scam else ""

        # Record scam if detected
        if is_scam and hasattr(message, 'guild') and message.guild:
            self.recent_scams[message.guild.id].append({
                'content': content,
                'categories': detected_categories,
                'timestamp': datetime.now(timezone.utc)
            })

        return is_scam, reason, detected_categories

    def _generate_reason(self, categories: List[str]) -> str:
        """Generate a detailed reason based on detected categories"""
        category_descriptions = {
            'phishing': "Attempted phishing or free nitro scam",
            'impersonation': "Staff impersonation attempt",
            'malicious_domain': "Known malicious domain detected",
            'suspicious_domain': "Suspicious domain detected",
            'mass_mentions': "Mass mention spam",
            'multiple_links': "Multiple suspicious links",
            'trading_scam': "Potential trading scam"
        }
        
        reasons = [category_descriptions.get(cat, cat) for cat in categories]
        return "Detected: " + ", ".join(reasons)

class MessageAnalyzer:
    def __init__(self):
        self.spam_threshold = 5
        self.similarity_threshold = 0.85
        self.message_history = defaultdict(list)

    async def analyze_user_messages(self, user_id: int, message: discord.Message) -> dict:
        """Analyze messages for spam and suspicious patterns"""
        results = {
            "is_spam": False,
            "is_suspicious": False,
            "similarity_score": 0.0,
            "reasons": []
        }

        # Add message to history
        self.message_history[user_id].append({
            "content": message.content,
            "timestamp": datetime.now(timezone.utc)
        })

        # Check message frequency
        recent_messages = [
            msg for msg in self.message_history[user_id]
            if (datetime.now(timezone.utc) - msg["timestamp"]) < timedelta(minutes=5)
        ]

        if len(recent_messages) > self.spam_threshold:
            results["is_spam"] = True
            results["reasons"].append("message_frequency")

        return results

class RaidProtector:
    def __init__(self):
        self.join_history = defaultdict(list)
        self.raid_threshold = 10
        self.time_window = 60  # seconds

    async def check_raid(self, guild: discord.Guild, member: discord.Member) -> bool:
        """Check if current join activity indicates a raid"""
        current_time = time.time()
        
        # Add new join
        self.join_history[guild.id].append(current_time)
        
        # Clean old entries
        self.join_history[guild.id] = [
            t for t in self.join_history[guild.id]
            if current_time - t <= self.time_window
        ]
        
        # Check if join rate exceeds threshold
        return len(self.join_history[guild.id]) >= self.raid_threshold

    async def get_raid_status(self, guild: discord.Guild) -> dict:
        """Get current raid status for a guild"""
        return {
            "is_raid": len(self.join_history[guild.id]) >= self.raid_threshold,
            "recent_joins": len(self.join_history[guild.id]),
            "threshold": self.raid_threshold
        }

class VerificationSystem:
    def __init__(self):
        self.verification_requirements = {}
        self.verified_users = set()
        self.pending_verifications = {}

    async def set_requirements(self, guild_id: int, requirements: dict):
        """Set verification requirements for a guild"""
        self.verification_requirements[guild_id] = requirements

    async def verify_user(self, member: discord.Member) -> bool:
        """Verify a user based on guild requirements"""
        guild_id = member.guild.id
        if guild_id not in self.verification_requirements:
            return True

        requirements = self.verification_requirements[guild_id]
        
        # Basic age check
        if "account_age" in requirements:
            age_days = (datetime.now(timezone.utc) - member.created_at).days
            if age_days < requirements["account_age"]:
                return False

        self.verified_users.add(member.id)
        return True

    def is_verified(self, user_id: int) -> bool:
        """Check if a user is verified"""
        return user_id in self.verified_users

class Enforcer(commands.Bot):
    def __init__(self, **options):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        intents.presences = True
        intents.guilds = True
        intents.messages = True
        
        super().__init__(
            command_prefix='!',
            intents=intents,
            description='Security and moderation bot for Discord',
            **options
        )
        
        # Initialize components
        self.db = EnforcerDatabase()
        self.moderator_verification = ModeratorVerification()
        self.trust_rating = TrustRating()
        self.profile_analyzer = ProfileAnalyzer()
        self._scam_detector = None
        self._message_analyzer = None
        self._raid_protector = None
        self._verification_system = None
        
        # Initialize settings
        self.shared_scam_alerts = {}
        self._last_cleanup = 0
        self._cleanup_interval = 3600  # Cleanup every hour
        
        # DM Protection settings
        self.dm_protection = defaultdict(lambda: {
            'enabled': False,
            'warn_users': True,
            'block_new_accounts': False,
            'minimum_age_days': 7
        })

        # Server lockdown settings
        self.lockdown_settings = defaultdict(lambda: {
            'active': False,
            'start_time': None,
            'restrictions': {
                'block_dms': True,
                'block_invites': True,
                'block_links': True,
                'minimum_age': 30  # days
            }
        })

    async def setup_hook(self):
        """Initialize async components"""
        await super().setup_hook()
        self.loop.create_task(self.cleanup_old_data())
        
        # Add commands
        @self.command(name='checkuser', help='Check a user\'s trust rating and profile')
        async def check_user(ctx, user: discord.User):
            trust_info = await self.trust_rating.calculate_trust_score(user, user.mutual_guilds)
            profile_analysis = await self.profile_analyzer.analyze_profile(user)
            
            embed = discord.Embed(
                title=f"User Analysis - {user.name}",
                color=discord.Color.blue(),
                timestamp=datetime.now(timezone.utc)
            )
            
            embed.add_field(
                name="Trust Rating",
                value=f"**{trust_info['rating']}** ({trust_info['score']:.2%})",
                inline=False
            )
            
            if trust_info['reasons']:
                embed.add_field(
                    name="Trust Factors",
                    value="\n".join(trust_info['reasons']),
                    inline=False
                )
            
            await ctx.send(embed=embed)

        @self.command(name='setmodrole', help='Set the official moderator role for the server')
        @commands.has_permissions(administrator=True)
        async def set_moderator_role(ctx, role: discord.Role):
            self.moderator_verification.set_mod_role(ctx.guild.id, role.id)
            await ctx.send(f"✅ {role.mention} has been set as the moderator role.")

        @self.command(name='reportdm', help='Report a suspicious DM from a user')
        async def report_dm(ctx, user: discord.User, *, reason: str = "Suspicious DM"):
            report = ScamReport(
                user_id=user.id,
                reporter_id=ctx.author.id,
                timestamp=datetime.now(timezone.utc),
                reason=reason,
                evidence="Manual report via command",
                message_content=None,
                channel_id=None
            )
            await self.process_detailed_report(ctx.guild, report)
            await ctx.send(f"✅ Report submitted for {user.mention}")

        @self.command(name='dmprotection', help='Configure DM protection settings')
        @commands.has_permissions(administrator=True)
        async def dm_protection(ctx, setting: str = None, value: str = None):
            if setting is None:
                settings = self.dm_protection[ctx.guild.id]
                await ctx.send(f"DM Protection: {'Enabled' if settings['enabled'] else 'Disabled'}")
                return

            if setting == 'enable':
                self.dm_protection[ctx.guild.id]['enabled'] = True
                await ctx.send("✅ DM protection enabled")
            elif setting == 'disable':
                self.dm_protection[ctx.guild.id]['enabled'] = False
                await ctx.send("✅ DM protection disabled")

        print(f"Logged in as {self.user}")
        print("------")
        print("Available commands:")
        for command in self.commands:
            print(f"!{command.name} - {command.help}")
        print("------")

    async def process_detailed_report(self, guild: discord.Guild, report: ScamReport):
        """Process a detailed scam report"""
        # Add to database
        if str(report.user_id) not in self.db.data['reported_users']:
            self.db.data['reported_users'][str(report.user_id)] = []
        
        self.db.data['reported_users'][str(report.user_id)].append(asdict(report))
        self.db.save_data()

        # Find logging channel
        log_channel = None
        for channel in guild.channels:
            if channel.name in ['mod-logs', 'security-logs', 'incident-logs']:
                log_channel = channel
                break

        if log_channel and isinstance(log_channel, discord.TextChannel):
            embed = discord.Embed(
                title="🚨 Scam Report",
                description=f"User reported for suspicious activity",
                color=discord.Color.red(),
                timestamp=report.timestamp
            )
            
            embed.add_field(name="Reported User", value=f"<@{report.user_id}>", inline=True)
            embed.add_field(name="Reporter", value=f"<@{report.reporter_id}>", inline=True)
            embed.add_field(name="Reason", value=report.reason, inline=False)
            
            if report.message_content:
                embed.add_field(
                    name="Message Content",
                    value=f"```{report.message_content[:1000]}```",
                    inline=False
                )

            await log_channel.send(embed=embed)

    async def log_security_incident(self, guild: discord.Guild, message: str, level: str = "INFO"):
        """Log a security incident to the appropriate channel"""
        # Find logging channel
        log_channel = None
        for channel in guild.channels:
            if channel.name in ['mod-logs', 'security-logs', 'incident-logs']:
                log_channel = channel
                break

        if log_channel and isinstance(log_channel, discord.TextChannel):
            colors = {
                "INFO": discord.Color.blue(),
                "WARNING": discord.Color.yellow(),
                "HIGH": discord.Color.red(),
                "CRITICAL": discord.Color.dark_red()
            }

            embed = discord.Embed(
                title=f"Security Alert - {level}",
                description=message,
                color=colors.get(level, discord.Color.default()),
                timestamp=datetime.now(timezone.utc)
            )
            
            await log_channel.send(embed=embed)

    async def check_staff_impersonation(self, message: discord.Message, mutual_guilds: List[discord.Guild]) -> bool:
        """Check if a message appears to be impersonating staff"""
        content = message.content.lower()
        author = message.author
        
        # Common staff-related terms
        staff_terms = [
            'mod', 'admin', 'staff', 'official', 'discord staff',
            'moderator', 'administrator', 'support', 'helper'
        ]
        
        # Check if message contains staff terms
        if any(term in content for term in staff_terms):
            # Check if user is actually staff in any mutual guild
            is_real_staff = any(
                self.moderator_verification.is_verified_mod(guild.get_member(author.id))
                for guild in mutual_guilds
                if guild.get_member(author.id)
            )
            
            return not is_real_staff

        return False

    async def handle_staff_impersonation(self, message: discord.Message):
        """Handle a detected staff impersonation attempt"""
        # Log the incident
        for guild in message.author.mutual_guilds:
            await self.log_security_incident(
                guild,
                f"🚫 Staff Impersonation Attempt Detected\n"
                f"User: {message.author.mention}\n"
                f"Content: ```{message.content}```",
                level="HIGH"
            )

        # Notify mutual guild moderators
        for guild in message.author.mutual_guilds:
            # Find mod channel
            mod_channel = None
            for channel in guild.channels:
                if channel.name in ['mod-chat', 'moderator-only', 'staff-chat']:
                    mod_channel = channel
                    break

            if mod_channel and isinstance(mod_channel, discord.TextChannel):
                embed = discord.Embed(
                    title="🚫 Staff Impersonation Alert",
                    description="A user has been detected attempting to impersonate staff",
                    color=discord.Color.red(),
                    timestamp=datetime.now(timezone.utc)
                )
                
                embed.add_field(name="User", value=f"{message.author.mention} ({message.author.id})")
                embed.add_field(name="Message", value=f"```{message.content}```")
                
                await mod_channel.send(embed=embed)

    async def on_message(self, message: discord.Message):
        """Handle message events"""
        # Ignore bot messages
        if message.author.bot:
            return

        # Process commands first
        await self.process_commands(message)

        # Handle DMs
        if isinstance(message.channel, discord.DMChannel):
            await self.handle_dm_message(message)
            return

        # Only process guild messages beyond this point
        if not isinstance(message.guild, discord.Guild):
            return

        # Check lockdown restrictions
        if await self.check_lockdown_restrictions(message):
            try:
                await message.delete()
                await message.channel.send(
                    f"{message.author.mention} Your message was removed due to server lockdown restrictions.",
                    delete_after=10
                )
            except discord.Forbidden:
                pass
            return

        # Analyze message for spam/scams
        is_scam, reason, categories = await self.scam_detector.analyze_message(message)
        analysis = await self.message_analyzer.analyze_user_messages(message.author.id, message)

        if is_scam or analysis["is_spam"]:
            await self.log_security_incident(
                message.guild,
                f"🚨 Suspicious Message Detected\n"
                f"User: {message.author.mention}\n"
                f"Categories: {', '.join(categories)}\n"
                f"Spam: {analysis['is_spam']}\n"
                f"Content: ```{message.content}```",
                level="HIGH"
            )

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        """Handle member join events"""
        # Check for raid
        is_raid = await self.raid_protector.check_raid(member.guild, member)
        if is_raid:
            await self.log_security_incident(
                member.guild,
                f"⚠️ Potential Raid Detected\n"
                f"Recent Joins: {len(self.raid_protector.join_history[member.guild.id])}",
                level="CRITICAL"
            )

        # Verify user
        if not await self.verification_system.verify_user(member):
            await self.log_security_incident(
                member.guild,
                f"❌ User failed verification requirements\n"
                f"User: {member.mention}",
                level="WARNING"
            )

    async def handle_dm_message(self, message: discord.Message):
        """Enhanced DM message handling"""
        # Get mutual guilds with the sender
        mutual_guilds = message.author.mutual_guilds
        recipient = message.channel.recipient

        # Check DM protection settings in mutual guilds
        protected_guilds = [
            guild for guild in mutual_guilds
            if self.dm_protection[guild.id]['enabled']
        ]

        if protected_guilds:
            # Check account age if any guild has new account blocking
            account_age = (datetime.now(timezone.utc) - message.author.created_at).days
            blocking_guilds = [
                guild for guild in protected_guilds
                if self.dm_protection[guild.id]['block_new_accounts'] and
                account_age < self.dm_protection[guild.id]['minimum_age_days']
            ]

            if blocking_guilds:
                # Block message and notify
                await message.channel.send(
                    "⚠️ This message was blocked due to server DM protection settings. "
                    "The user's account is too new to send DMs."
                )
                return

            # Get trust rating
            trust_info = await self.trust_rating.calculate_trust_score(message.author, mutual_guilds)
            
            # Warn recipient if enabled and trust score is low
            if trust_info['score'] < 0.4:
                warning_embed = discord.Embed(
                    title="⚠️ Caution: Low Trust User",
                    description="You're receiving a DM from a user with a low trust rating:",
                    color=discord.Color.yellow()
                )
                warning_embed.add_field(
                    name="Trust Score",
                    value=f"**{trust_info['rating']}** ({trust_info['score']:.2%})",
                    inline=False
                )
                if trust_info['reasons']:
                    warning_embed.add_field(
                        name="Reasons",
                        value="\n".join(trust_info['reasons']),
                        inline=False
                    )
                warning_embed.add_field(
                    name="Recommendation",
                    value="Be cautious with this interaction. You can use `!reportdm` to report suspicious behavior.",
                    inline=False
                )
                
                try:
                    await recipient.send(embed=warning_embed)
                except discord.Forbidden:
                    pass

        # Continue with existing DM handling
        await super().handle_dm_message(message)

    @commands.command(name='recentscams')
    @commands.has_permissions(manage_messages=True)
    async def recent_scams(self, ctx, limit: int = 5):
        """View recent scam attempts in the server"""
        recent = self.scam_detector.recent_scams[ctx.guild.id][-limit:]
        
        if not recent:
            await ctx.send("No recent scam attempts recorded!")
            return

        embed = discord.Embed(
            title="Recent Scam Attempts",
            description=f"Last {len(recent)} detected scam attempts",
            color=discord.Color.red()
        )

        for i, scam in enumerate(recent, 1):
            embed.add_field(
                name=f"Attempt #{i}",
                value=f"**Categories:** {', '.join(scam['categories'])}\n"
                      f"**Content:** ```{scam['content'][:200]}```\n"
                      f"**Time:** {scam['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}",
                inline=False
            )

        await ctx.send(embed=embed)

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member):
        """Enhanced member join handling"""
        await super().on_member_join(member)

        # Additional check for new accounts
        account_age = (datetime.now(timezone.utc) - member.created_at).days
        if account_age < 7:  # New account threshold
            # Notify moderators
            embed = discord.Embed(
                title="👤 New Account Joined",
                description=f"User: {member.mention}\nAccount Age: {account_age} days",
                color=discord.Color.yellow(),
                timestamp=datetime.now(timezone.utc)
            )
            
            # Get trust score
            trust_info = await self.trust_rating.calculate_trust_score(member, [member.guild])
            embed.add_field(
                name="Trust Rating",
                value=f"**{trust_info['rating']}** ({trust_info['score']:.2%})",
                inline=False
            )
            
            # Find mod channel
            for channel in member.guild.channels:
                if channel.name in ['mod-chat', 'moderator-only', 'staff-chat']:
                    if isinstance(channel, discord.TextChannel):
                        await channel.send(embed=embed)
                        break

    @commands.command(name='scamdomains')
    @commands.has_permissions(manage_messages=True)
    async def manage_scam_domains(self, ctx, action: str, domain: str = None):
        """Manage the scam domain blacklist"""
        if action.lower() == 'list':
            domains = list(self.scam_detector.known_scam_domains)
            if not domains:
                await ctx.send("No domains in the blacklist.")
                return

            embed = discord.Embed(
                title="Blacklisted Domains",
                description="Currently known scam domains:",
                color=discord.Color.red()
            )
            
            # Split into chunks of 15 domains
            for i in range(0, len(domains), 15):
                chunk = domains[i:i+15]
                embed.add_field(
                    name=f"Domains {i+1}-{i+len(chunk)}",
                    value="\n".join(f"• `{domain}`" for domain in chunk),
                    inline=False
                )
            
            await ctx.send(embed=embed)
            
        elif action.lower() == 'add' and domain:
            await self.scam_detector.add_scam_domain(domain)
            await ctx.send(f"✅ Added `{domain}` to scam domain blacklist")
            
        elif action.lower() == 'remove' and domain:
            await self.scam_detector.remove_scam_domain(domain)
            await ctx.send(f"✅ Removed `{domain}` from scam domain blacklist")

    @commands.command(name='scaminfo')
    async def scam_information(self, ctx):
        """Show information about common scams and safety tips"""
        embed = discord.Embed(
            title="🛡️ Scam Awareness Guide",
            description="Learn about common Discord scams and how to stay safe",
            color=discord.Color.blue()
        )

        embed.add_field(
            name="Common Scam Types",
            value="• Free Nitro Scams\n"
                  "• Steam Gift Scams\n"
                  "• Staff Impersonation\n"
                  "• Fake Giveaways\n"
                  "• Trading Scams",
            inline=False
        )

        embed.add_field(
            name="🚩 Red Flags",
            value="• Offers that seem too good to be true\n"
                  "• Pressure to act quickly\n"
                  "• Requests for personal information\n"
                  "• Links to suspicious websites\n"
                  "• Claims of being Discord staff",
            inline=False
        )

        embed.add_field(
            name="🛡️ Stay Safe",
            value="• Never click suspicious links\n"
                  "• Don't download unknown files\n"
                  "• Keep your token private\n"
                  "• Enable 2FA\n"
                  "• Report suspicious activity",
            inline=False
        )

        embed.add_field(
            name="📱 Useful Commands",
            value=f"`{ctx.prefix}checkuser` - Check user trust rating\n"
                  f"`{ctx.prefix}reportdm` - Report suspicious DMs\n"
                  f"`{ctx.prefix}recentscams` - View recent scam attempts",
            inline=False
        )

        await ctx.send(embed=embed)

    @commands.command(name='lockdown')
    @commands.has_permissions(administrator=True)
    async def server_lockdown(self, ctx, action: str = None, duration: int = 60):
        """Enable or disable server lockdown mode"""
        if action is None:
            # Show current status
            settings = self.lockdown_settings[ctx.guild.id]
            if settings['active']:
                time_remaining = (settings['start_time'] + timedelta(minutes=duration) - datetime.now(timezone.utc)).total_seconds() / 60
                await ctx.send(f"🔒 Server is in lockdown mode. {time_remaining:.1f} minutes remaining.")
            else:
                await ctx.send("🔓 Server is not in lockdown mode.")
            return

        if action.lower() == 'enable':
            self.lockdown_settings[ctx.guild.id]['active'] = True
            self.lockdown_settings[ctx.guild.id]['start_time'] = datetime.now(timezone.utc)
            
            embed = discord.Embed(
                title="🔒 Server Lockdown Enabled",
                description="Emergency protection measures are now active:",
                color=discord.Color.red()
            )
            embed.add_field(
                name="Restrictions",
                value="• DMs between members blocked\n"
                      "• Server invites blocked\n"
                      "• Links blocked\n"
                      f"• Minimum account age: {self.lockdown_settings[ctx.guild.id]['restrictions']['minimum_age']} days",
                inline=False
            )
            embed.add_field(
                name="Duration",
                value=f"Lockdown will last for {duration} minutes",
                inline=False
            )
            
            await ctx.send(embed=embed)
            
            # Schedule lockdown end
            await asyncio.sleep(duration * 60)
            if self.lockdown_settings[ctx.guild.id]['active']:
                self.lockdown_settings[ctx.guild.id]['active'] = False
                await ctx.send("🔓 Lockdown period has ended. Server restrictions lifted.")
                
        elif action.lower() == 'disable':
            self.lockdown_settings[ctx.guild.id]['active'] = False
            await ctx.send("🔓 Lockdown mode disabled. Server restrictions lifted.")

    @commands.command(name='sharescam')
    @commands.has_permissions(manage_messages=True)
    async def share_scam_alert(self, ctx, *, details: str):
        """Share a scam alert with other servers"""
        alert = {
            'source_guild': ctx.guild.id,
            'details': details,
            'reporter': ctx.author.id
        }
        
        await self.scam_detector.share_scam_alert(ctx.guild.id, alert)
        
        # Share with mutual guilds
        shared_count = 0
        for guild in self.guilds:
            if guild.id != ctx.guild.id and ctx.author in guild.members:
                # Find appropriate channel
                for channel in guild.channels:
                    if channel.name in ['mod-logs', 'security-logs', 'scam-alerts']:
                        if isinstance(channel, discord.TextChannel):
                            embed = discord.Embed(
                                title="⚠️ Cross-Server Scam Alert",
                                description=details,
                                color=discord.Color.orange(),
                                timestamp=datetime.now(timezone.utc)
                            )
                            embed.set_footer(text=f"Shared from {ctx.guild.name}")
                            await channel.send(embed=embed)
                            shared_count += 1
                            break

        await ctx.send(f"✅ Scam alert shared with {shared_count} servers.")

    async def check_lockdown_restrictions(self, message: discord.Message) -> bool:
        """Check if a message violates lockdown restrictions"""
        if not isinstance(message.guild, discord.Guild):
            return False
            
        settings = self.lockdown_settings[message.guild.id]
        if not settings['active']:
            return False

        # Check restrictions
        if settings['restrictions']['block_links'] and re.search(r'https?://', message.content):
            return True
            
        if settings['restrictions']['block_invites'] and re.search(r'discord\.gg|discordapp\.com/invite', message.content):
            return True

        return False

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message):
        """Enhanced message handling with lockdown checks"""
        if message.author.bot:
            return

        # Check lockdown restrictions
        if isinstance(message.guild, discord.Guild) and await self.check_lockdown_restrictions(message):
            try:
                await message.delete()
                await message.channel.send(
                    f"{message.author.mention} Your message was removed due to server lockdown restrictions.",
                    delete_after=10
                )
            except discord.Forbidden:
                pass
            return

        # Continue with normal message processing
        await super().on_message(message)

    @property
    def scam_detector(self):
        if self._scam_detector is None:
            self._scam_detector = ScamDetector()
        return self._scam_detector
    
    @property
    def message_analyzer(self):
        if self._message_analyzer is None:
            self._message_analyzer = MessageAnalyzer()
        return self._message_analyzer
    
    @property
    def raid_protector(self):
        if self._raid_protector is None:
            self._raid_protector = RaidProtector()
        return self._raid_protector
    
    @property
    def verification_system(self):
        if self._verification_system is None:
            self._verification_system = VerificationSystem()
        return self._verification_system
    
    async def cleanup_old_data(self):
        """Cleanup old data to free memory"""
        current_time = time.time()
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
            
        self._last_cleanup = current_time
        
        # Clear old scam alerts
        old_alerts = []
        for alert_id, data in self.shared_scam_alerts.items():
            if current_time - data['timestamp'] > 86400:  # Older than 24 hours
                old_alerts.append(alert_id)
        
        for alert_id in old_alerts:
            del self.shared_scam_alerts[alert_id]
 