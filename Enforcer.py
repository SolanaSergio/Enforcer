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
import os
from urllib.parse import urlparse

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
        self.data = self._create_default_data()  # Always start with default data
        self.message_store = MessageStore()
        self.user_activities = {}
        self.known_scam_domains = set()
        self.phishing_patterns = set()
        self.suspicious_links = defaultdict(int)
        self.cached_user_risks = {}
        self.last_scan_time = datetime.now()
        self.save_data()  # Save the default data immediately

    def _create_default_data(self) -> dict:
        return {
            'guild_settings': {},
            'reported_users': {},
            'verified_users': [],  # Changed from set() to list for JSON serialization
            'trusted_users': [],   # Changed from set() to list for JSON serialization
            'banned_patterns': [],  # Changed from set() to list for JSON serialization
            'known_scammers': [],  # Changed from set() to list for JSON serialization
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

    def _datetime_handler(self, obj):
        """Handle datetime objects for JSON serialization"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, set):
            return list(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def _process_data_for_save(self, data):
        """Recursively process data to make it JSON serializable"""
        if isinstance(data, dict):
            return {k: self._process_data_for_save(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._process_data_for_save(item) for item in data]
        elif isinstance(data, (set, tuple)):
            return [self._process_data_for_save(item) for item in data]
        elif isinstance(data, datetime):
            return data.isoformat()
        elif hasattr(data, '__dict__'):
            return self._process_data_for_save(data.__dict__)
        return data

    def save_data(self):
        """Save data with error handling and datetime serialization"""
        try:
            # Process the data to make it JSON serializable
            processed_data = self._process_data_for_save(self.data)
            
            with open(self.filename, 'w') as f:
                json.dump(processed_data, f, indent=4, default=self._datetime_handler)
        except Exception as e:
            logging.error(f"Error saving safety data: {e}")

    def load_data(self):
        """Load data with datetime parsing"""
        try:
            if os.path.exists(self.filename):
                with open(self.filename, 'r') as f:
                    loaded_data = json.load(f)
                    
                    # Convert ISO format strings back to datetime where needed
                    for user_id, reports in loaded_data.get('reported_users', {}).items():
                        for report in reports:
                            if 'timestamp' in report:
                                try:
                                    report['timestamp'] = datetime.fromisoformat(report['timestamp'])
                                except (ValueError, TypeError):
                                    report['timestamp'] = datetime.now()
                    
                    self.data = loaded_data
            else:
                self.data = self._create_default_data()
        except Exception as e:
            logging.error(f"Error loading safety data: {e}")
            self.data = self._create_default_data()

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

    async def add_scam_attempt(self, guild_id: int, content: str, categories: List[str]):
        """Add a scam attempt to the recent scams list"""
        self.recent_scams[guild_id].append({
            'content': content,
            'categories': categories,
            'timestamp': datetime.now(timezone.utc)
        })
        # Keep only last 50 scams per guild
        if len(self.recent_scams[guild_id]) > 50:
            self.recent_scams[guild_id].pop(0)

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
        if is_scam and message.guild:
            await self.add_scam_attempt(message.guild.id, content, detected_categories)

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

    async def share_scam_alert(self, guild_id: int, alert: dict):
        """Share a scam alert with other servers"""
        self.shared_scam_alerts[guild_id].append({
            **alert,
            'timestamp': datetime.now(timezone.utc)
        })
        # Keep only last 50 alerts
        self.shared_scam_alerts[guild_id] = self.shared_scam_alerts[guild_id][-50:]

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

class ScamPatternLearner:
    def __init__(self):
        self.known_patterns = set()
        self.reported_messages = []
        self.confidence_thresholds = {
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }

    async def learn_from_report(self, message_content: str, is_confirmed_scam: bool = True):
        """Learn patterns from reported scam messages"""
        if not message_content:
            return
        
        # Extract key phrases (3-5 words)
        words = message_content.lower().split()
        for i in range(len(words)-2):
            for length in range(3, 6):
                if i + length <= len(words):
                    phrase = ' '.join(words[i:i+length])
                    if is_confirmed_scam:
                        self.known_patterns.add(phrase)

    async def analyze_similarity(self, message: str) -> dict:
        """Analyze message similarity to known scam patterns"""
        if not message:
            return {'confidence': 0, 'matching_patterns': []}

        message = message.lower()
        matching_patterns = []
        max_confidence = 0

        for pattern in self.known_patterns:
            similarity = difflib.SequenceMatcher(None, pattern, message).ratio()
            if similarity > self.confidence_thresholds['low']:
                matching_patterns.append({
                    'pattern': pattern,
                    'confidence': similarity
                })
                max_confidence = max(max_confidence, similarity)

        return {
            'confidence': max_confidence,
            'matching_patterns': sorted(matching_patterns, key=lambda x: x['confidence'], reverse=True)[:3]
        }

class CommunityScamDB:
    def __init__(self):
        self.scam_reports = defaultdict(list)  # user_id -> list of reports
        self.confirmed_scammers = set()
        self.suspicious_users = defaultdict(int)  # user_id -> suspicion count
        self.report_threshold = 3  # Number of reports needed to mark as confirmed scammer

    async def add_report(self, user_id: int, reporter_id: int, evidence: str, guild_id: int):
        """Add a new scam report to the database"""
        report = {
            'reporter_id': reporter_id,
            'timestamp': datetime.now(timezone.utc),
            'evidence': evidence,
            'guild_id': guild_id
        }
        
        self.scam_reports[user_id].append(report)
        self.suspicious_users[user_id] += 1

        # Check if user should be marked as confirmed scammer
        if self.suspicious_users[user_id] >= self.report_threshold:
            self.confirmed_scammers.add(user_id)
            return True
        return False

    async def get_user_status(self, user_id: int) -> dict:
        """Get the current status of a user"""
        return {
            'is_confirmed_scammer': user_id in self.confirmed_scammers,
            'report_count': self.suspicious_users[user_id],
            'recent_reports': self.scam_reports[user_id][-5:] if user_id in self.scam_reports else []
        }

class DMScreener:
    def __init__(self):
        self.safe_words = set(['hi', 'hello', 'hey', 'thanks', 'thank you', 'ok', 'okay'])
        self.risky_patterns = [
            r'free\s*(nitro|steam|gift)',
            r'(steam|discord|nitro)\s*giveaway',
            r'claim\s*your\s*(prize|reward|gift)',
            r'limited\s*time\s*offer',
            r'click\s*(here|this\s*link)',
            r'urgent|hurry|quick|fast',
            r'password|email|token'
        ]
        self.url_safety_cache = {}

    async def screen_dm(self, content: str, sender_id: int, mutual_guilds: List[discord.Guild]) -> dict:
        """Screen a DM for suspicious content"""
        risk_factors = []
        risk_score = 0

        # Check message length
        if len(content) < 10:
            return {'is_safe': True, 'risk_score': 0, 'risk_factors': ['Short greeting message']}

        # Check for safe greetings
        words = set(content.lower().split())
        if words.intersection(self.safe_words) and len(content) < 20:
            return {'is_safe': True, 'risk_score': 0, 'risk_factors': ['Safe greeting message']}

        # Check for risky patterns
        for pattern in self.risky_patterns:
            if re.search(pattern, content.lower()):
                risk_factors.append(f"Contains suspicious pattern: {pattern}")
                risk_score += 0.3

        # Check for URLs
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', content)
        if urls:
            risk_factors.append(f"Contains {len(urls)} URLs")
            risk_score += 0.2 * len(urls)

        # Check message characteristics
        if content.isupper() or content.count('!') > 3:
            risk_factors.append("Aggressive formatting")
            risk_score += 0.1

        if len(mutual_guilds) < 2:
            risk_factors.append("Few mutual servers")
            risk_score += 0.2

        return {
            'is_safe': risk_score < 0.5,
            'risk_score': risk_score,
            'risk_factors': risk_factors
        }

class UsernameImpersonationDetector:
    def __init__(self):
        self.protected_terms = {
            'mod', 'admin', 'staff', 'moderator', 'administrator',
            'official', 'support', 'helper', 'discord'
        }
        self.similarity_threshold = 0.85

    def get_username_similarity(self, name1: str, name2: str) -> float:
        """Calculate similarity between two usernames"""
        # Remove common decorators and convert to lowercase
        name1 = self._clean_username(name1)
        name2 = self._clean_username(name2)
        return difflib.SequenceMatcher(None, name1, name2).ratio()

    def _clean_username(self, username: str) -> str:
        """Clean username for comparison"""
        # Convert to lowercase and remove common decorators
        username = username.lower()
        username = re.sub(r'[_\-\.\[\]\(\)]', '', username)
        username = re.sub(r'\d+', '', username)  # Remove numbers
        return username

    async def check_impersonation(self, member: discord.Member, guild_members: List[discord.Member]) -> dict:
        """Check if a member is trying to impersonate others"""
        results = {
            'is_impersonating': False,
            'matched_users': [],
            'protected_term_used': False,
            'risk_level': 'LOW'
        }

        username = member.name.lower()
        display_name = member.display_name.lower()

        # Check for protected terms
        for term in self.protected_terms:
            if term in username or term in display_name:
                results['protected_term_used'] = True
                results['risk_level'] = 'MEDIUM'

        # Compare with other members' names
        for other in guild_members:
            if other.id == member.id:
                continue

            # Check if other member has mod permissions
            if other.guild_permissions.manage_messages or other.guild_permissions.administrator:
                username_similarity = self.get_username_similarity(member.name, other.name)
                display_name_similarity = self.get_username_similarity(member.display_name, other.display_name)

                if username_similarity > self.similarity_threshold or display_name_similarity > self.similarity_threshold:
                    results['is_impersonating'] = True
                    results['risk_level'] = 'HIGH'
                    results['matched_users'].append({
                        'user': other,
                        'similarity': max(username_similarity, display_name_similarity)
                    })

        return results

class LinkPreview:
    def __init__(self):
        self.preview_cache = {}
        self.cache_duration = 3600  # 1 hour cache

    async def get_screenshot(self, url: str) -> Optional[str]:
        """Get a screenshot of a URL using Selenium Wire"""
        try:
            # Check cache first
            if url in self.preview_cache:
                cache_time, image = self.preview_cache[url]
                if time.time() - cache_time < self.cache_duration:
                    return image

            # Use aiohttp to fetch OG meta tags for preview
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        return None
                    
                    html = await response.text()
                    
                    # Try to find OpenGraph image
                    og_image_match = re.search(r'<meta property="og:image" content="([^"]+)"', html)
                    if og_image_match:
                        image_url = og_image_match.group(1)
                        # Cache the result
                        self.preview_cache[url] = (time.time(), image_url)
                        return image_url

            return None
        except Exception as e:
            logging.error(f"Error getting screenshot: {e}")
            return None

    def is_safe_url(self, url: str) -> bool:
        """Basic URL safety check"""
        try:
            parsed = urlparse(url)
            return all([
                parsed.scheme in ('http', 'https'),
                not any(c in url for c in ['<', '>', '"', "'"]),
                len(url) < 2000
            ])
        except Exception:
            return False

class StaffNotifier:
    def __init__(self):
        self.notification_channels = defaultdict(set)  # guild_id -> set of channel_ids
        self.last_notification = defaultdict(float)  # guild_id -> last notification time
        self.cooldown = 300  # 5 minutes between notifications

    async def add_notification_channel(self, guild_id: int, channel_id: int):
        """Add a channel for staff notifications"""
        self.notification_channels[guild_id].add(channel_id)

    async def remove_notification_channel(self, guild_id: int, channel_id: int):
        """Remove a channel from staff notifications"""
        self.notification_channels[guild_id].discard(channel_id)

    async def notify_staff(self, guild: discord.Guild, embed: discord.Embed, urgent: bool = False):
        """Send notification to staff channels"""
        current_time = time.time()
        
        # Check cooldown unless urgent
        if not urgent and current_time - self.last_notification[guild.id] < self.cooldown:
            return

        self.last_notification[guild.id] = current_time
        
        # Add timestamp to embed
        embed.timestamp = datetime.now(timezone.utc)
        
        # Send to all notification channels
        for channel_id in self.notification_channels[guild.id]:
            channel = guild.get_channel(channel_id)
            if channel and isinstance(channel, discord.TextChannel):
                try:
                    await channel.send(
                        content="🚨 **URGENT STAFF NOTIFICATION**" if urgent else None,
                        embed=embed
                    )
                except discord.Forbidden:
                    continue

class UsernameChecker:
    def __init__(self):
        self.similar_cache = {}
        self.protected_terms = {
            'mod', 'admin', 'staff', 'moderator', 'administrator',
            'official', 'support', 'helper', 'discord'
        }
        self.similarity_threshold = 0.85

    def clean_username(self, username: str) -> str:
        """Clean username for comparison"""
        username = username.lower()
        username = re.sub(r'[_\-\.\[\]\(\)]', '', username)
        username = re.sub(r'\d+', '', username)
        return username

    async def find_similar_users(self, guild: discord.Guild, username: str) -> List[dict]:
        """Find users with similar usernames"""
        similar_users = []
        cleaned_name = self.clean_username(username)
        
        for member in guild.members:
            # Skip checking against self
            if member.name == username:
                continue
                
            cleaned_member_name = self.clean_username(member.name)
            similarity = difflib.SequenceMatcher(None, cleaned_name, cleaned_member_name).ratio()
            
            if similarity > self.similarity_threshold:
                similar_users.append({
                    'user': member,
                    'similarity': similarity
                })

        return sorted(similar_users, key=lambda x: x['similarity'], reverse=True)

    def has_protected_terms(self, username: str) -> List[str]:
        """Check if username contains protected terms"""
        found_terms = []
        lowered = username.lower()
        
        for term in self.protected_terms:
            if term in lowered:
                found_terms.append(term)
                
        return found_terms

    async def analyze_username(self, member: discord.Member) -> dict:
        """Analyze a username for potential issues"""
        results = {
            'similar_users': [],
            'protected_terms': [],
            'risk_level': 'LOW',
            'recommendations': []
        }
        
        # Check for similar usernames
        similar = await self.find_similar_users(member.guild, member.name)
        if similar:
            results['similar_users'] = similar
            results['risk_level'] = 'HIGH'
            results['recommendations'].append(
                f"User has similar name to {len(similar)} other member(s)"
            )
        
        # Check for protected terms
        protected = self.has_protected_terms(member.name)
        if protected:
            results['protected_terms'] = protected
            results['risk_level'] = 'HIGH'
            results['recommendations'].append(
                f"Username contains protected terms: {', '.join(protected)}"
            )
        
        return results

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

        # Add new components
        self.pattern_learner = ScamPatternLearner()
        self.community_db = CommunityScamDB()
        self.dm_screener = DMScreener()
        self.username_detector = UsernameImpersonationDetector()
        self.link_preview = LinkPreview()
        self.staff_notifier = StaffNotifier()
        self.username_checker = UsernameChecker()

        # Add commands
        self.add_commands()

    def add_commands(self):
        """Add all commands to the bot"""
        
        # Remove default help command first
        self.remove_command('help')

        @self.command(name='help', help='Shows all available commands')
        async def help_command(ctx):
            embed = discord.Embed(
                title="🛡️ Enforcer Bot Commands",
                description="Here are all available commands:",
                color=discord.Color.blue()
            )

            # User Safety Commands
            embed.add_field(
                name="🛡️ User Safety",
                value="`!scaminfo` - Learn about common scams and safety tips\n"
                      "`!checkuser @user` - Check a user's trust rating\n"
                      "`!reportdm @user` - Report suspicious DMs\n"
                      "`!reportscam` - Report a scam attempt\n"
                      "`!checkname [@user]` - Check for similar usernames\n"
                      "`!previewlink [url]` - Get a safe preview of a link",
                inline=False
            )

            # Server Protection
            embed.add_field(
                name="🔒 Server Protection",
                value="`!lockdown` - View lockdown status\n"
                      "`!lockdown enable [duration]` - Enable lockdown\n"
                      "`!lockdown disable` - Disable lockdown\n"
                      "`!staffchannel add/remove` - Set up staff notification channel",
                inline=False
            )

            # Scam Prevention
            embed.add_field(
                name="🚫 Scam Prevention",
                value="`!scamdomains list` - List known scam domains\n"
                      "`!scamdomains add [domain]` - Add domain to blacklist\n"
                      "`!scamdomains remove [domain]` - Remove domain from blacklist\n"
                      "`!scamexamples` - View examples of common scams",
                inline=False
            )

            # Statistics & Monitoring
            embed.add_field(
                name="📊 Statistics",
                value="`!recentscams` - View recent scam attempts\n"
                      "`!scamstats` - View scam prevention stats",
                inline=False
            )

            await ctx.send(embed=embed)

        @self.command(name='scaminfo', help='Learn about common scams and safety tips')
        async def scaminfo(ctx):
            try:
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
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='recentscams', help='View recent scam attempts in the server')
        @commands.has_permissions(manage_messages=True)
        async def recentscams(ctx, limit: int = 5):
            try:
                if not ctx.guild:
                    await ctx.send("❌ This command can only be used in a server!")
                    return

                recent = self.scam_detector.recent_scams.get(ctx.guild.id, [])[-limit:]
                
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
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='scamdomains')
        @commands.has_permissions(manage_messages=True)
        async def scamdomains(ctx, action: str = "list", domain: str = None):
            try:
                if not ctx.guild:
                    await ctx.send("❌ This command can only be used in a server!")
                    return

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
                else:
                    await ctx.send("❌ Invalid usage! Use `!scamdomains list` or `!scamdomains add/remove [domain]`")
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='lockdown')
        @commands.has_permissions(administrator=True)
        async def lockdown(ctx, action: str = None, duration: int = 60):
            try:
                if not ctx.guild:
                    await ctx.send("❌ This command can only be used in a server!")
                    return

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
                else:
                    await ctx.send("❌ Invalid action! Use `enable` or `disable`")
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='scamstats')
        async def scamstats(ctx):
            try:
                if not ctx.guild:
                    await ctx.send("❌ This command can only be used in a server!")
                    return

                embed = discord.Embed(
                    title="🛡️ Scam Prevention Statistics",
                    color=discord.Color.blue(),
                    timestamp=datetime.now(timezone.utc)
                )
                
                # Get statistics
                total_patterns = len(self.pattern_learner.known_patterns)
                total_scammers = len(self.community_db.confirmed_scammers)
                total_reports = sum(len(reports) for reports in self.community_db.scam_reports.values())
                
                embed.add_field(
                    name="Known Patterns",
                    value=f"🔍 {total_patterns} patterns identified",
                    inline=True
                )
                
                embed.add_field(
                    name="Confirmed Scammers",
                    value=f"🚫 {total_scammers} users",
                    inline=True
                )
                
                embed.add_field(
                    name="Total Reports",
                    value=f"📊 {total_reports} reports processed",
                    inline=True
                )
                
                await ctx.send(embed=embed)
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='checkuser', help='Check a user\'s trust rating and profile')
        async def checkuser(ctx, user: discord.Member = None):
            try:
                if not ctx.guild:
                    await ctx.send("❌ This command can only be used in a server!")
                    return

                # If no user is specified, check the command author
                target_user = user or ctx.author

                # Get trust score
                trust_info = await self.trust_rating.calculate_trust_score(target_user, [ctx.guild])
                
                # Get profile analysis
                profile_analysis = await self.profile_analyzer.analyze_profile(target_user)
                
                # Check community database
                community_status = await self.community_db.get_user_status(target_user.id)

                embed = discord.Embed(
                    title=f"User Trust Analysis: {target_user.name}",
                    color=discord.Color.blue() if trust_info['score'] > 0.6 else discord.Color.orange() if trust_info['score'] > 0.3 else discord.Color.red()
                )

                # Basic Info
                created_ago = (datetime.now(timezone.utc) - target_user.created_at).days
                joined_ago = (datetime.now(timezone.utc) - target_user.joined_at).days if target_user.joined_at else 0
                
                embed.add_field(
                    name="👤 Basic Info",
                    value=f"Account Age: {created_ago} days\n"
                          f"Server Member: {joined_ago} days\n"
                          f"Bot: {'Yes' if target_user.bot else 'No'}",
                    inline=False
                )

                # Trust Score
                embed.add_field(
                    name="🛡️ Trust Rating",
                    value=f"**{trust_info['rating']}** ({trust_info['score']:.1%})\n"
                          + "\n".join(trust_info['reasons']) if trust_info['reasons'] else "No concerns",
                    inline=False
                )

                # Profile Analysis
                if profile_analysis['suspicious_elements']:
                    embed.add_field(
                        name="⚠️ Suspicious Elements",
                        value="\n".join(f"• {element}" for element in profile_analysis['suspicious_elements']),
                        inline=False
                    )

                # Community Database Info
                if community_status['is_confirmed_scammer']:
                    embed.add_field(
                        name="🚫 WARNING",
                        value="This user has been confirmed as a scammer!",
                        inline=False
                    )
                elif community_status['report_count'] > 0:
                    embed.add_field(
                        name="📊 Reports",
                        value=f"This user has been reported {community_status['report_count']} times",
                        inline=False
                    )

                # Recommendations
                if profile_analysis['recommendations']:
                    embed.add_field(
                        name="💡 Recommendations",
                        value="\n".join(f"• {rec}" for rec in profile_analysis['recommendations']),
                        inline=False
                    )

                await ctx.send(embed=embed)
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @checkuser.error
        async def checkuser_error(ctx, error):
            if isinstance(error, commands.MemberNotFound):
                await ctx.send("❌ Could not find that user! Make sure you're mentioning a valid server member.")
            else:
                await ctx.send(f"❌ An error occurred: {str(error)}")

        # Error handlers for common issues
        @recentscams.error
        async def recentscams_error(ctx, error):
            if isinstance(error, commands.MissingPermissions):
                await ctx.send("❌ You need the 'Manage Messages' permission to use this command!")
            else:
                await ctx.send(f"❌ An error occurred: {str(error)}")

        @scamdomains.error
        async def scamdomains_error(ctx, error):
            if isinstance(error, commands.MissingPermissions):
                await ctx.send("❌ You need the 'Manage Messages' permission to use this command!")
            else:
                await ctx.send(f"❌ An error occurred: {str(error)}")

        @lockdown.error
        async def lockdown_error(ctx, error):
            if isinstance(error, commands.MissingPermissions):
                await ctx.send("❌ You need the 'Administrator' permission to use this command!")
            else:
                await ctx.send(f"❌ An error occurred: {str(error)}")

        @self.command(name='reportdm', help='Report a user for suspicious DM behavior')
        async def reportdm(ctx, user: discord.Member, *, reason: str = None):
            try:
                if not ctx.guild:
                    await ctx.send("❌ This command can only be used in a server!")
                    return

                if user.bot:
                    await ctx.send("❌ You cannot report bot accounts!")
                    return

                if user.id == ctx.author.id:
                    await ctx.send("❌ You cannot report yourself!")
                    return

                # Create report
                report = ScamReport(
                    user_id=user.id,
                    reporter_id=ctx.author.id,
                    timestamp=datetime.now(timezone.utc),
                    reason=reason or "Suspicious DM behavior",
                    evidence="Reported via !reportdm command",
                    message_content=None,
                    channel_id=None
                )

                # Add to community database
                is_confirmed = await self.community_db.add_report(
                    user_id=user.id,
                    reporter_id=ctx.author.id,
                    evidence=f"DM Report: {reason}" if reason else "Suspicious DM behavior",
                    guild_id=ctx.guild.id
                )

                # Process the report
                await self.process_detailed_report(ctx.guild, report)

                # Create response embed
                embed = discord.Embed(
                    title="DM Report Submitted",
                    description=f"Report against {user.mention} has been recorded",
                    color=discord.Color.orange(),
                    timestamp=datetime.now(timezone.utc)
                )

                embed.add_field(
                    name="Reporter",
                    value=ctx.author.mention,
                    inline=True
                )

                embed.add_field(
                    name="Reported User",
                    value=f"{user.mention} ({user.id})",
                    inline=True
                )

                if reason:
                    embed.add_field(
                        name="Reason",
                        value=reason,
                        inline=False
                    )

                if is_confirmed:
                    embed.add_field(
                        name="⚠️ Warning",
                        value="This user has been marked as a confirmed scammer due to multiple reports!",
                        inline=False
                    )

                # Get user trust info
                trust_info = await self.trust_rating.calculate_trust_score(user, [ctx.guild])
                embed.add_field(
                    name="User Trust Rating",
                    value=f"**{trust_info['rating']}** ({trust_info['score']:.1%})",
                    inline=False
                )

                # Add recommendations
                recommendations = [
                    "• Block the user if you haven't already",
                    "• Do not click any links they sent",
                    "• Do not share personal information",
                    "• Enable 'Safe Direct Messaging' in your Discord settings"
                ]
                embed.add_field(
                    name="Recommended Actions",
                    value="\n".join(recommendations),
                    inline=False
                )

                await ctx.send(embed=embed)

                # If the user is now a confirmed scammer, notify moderators
                if is_confirmed:
                    for guild in user.mutual_guilds:
                        for channel in guild.channels:
                            if channel.name in ['mod-logs', 'security-logs', 'incident-logs']:
                                if isinstance(channel, discord.TextChannel):
                                    alert_embed = discord.Embed(
                                        title="🚨 Confirmed Scammer Alert",
                                        description=f"{user.mention} has been marked as a confirmed scammer!",
                                        color=discord.Color.red()
                                    )
                                    alert_embed.add_field(
                                        name="User ID",
                                        value=str(user.id),
                                        inline=True
                                    )
                                    alert_embed.add_field(
                                        name="Report Count",
                                        value=str(len(self.community_db.scam_reports[user.id])),
                                        inline=True
                                    )
                                    await channel.send(embed=alert_embed)
                                    break

            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @reportdm.error
        async def reportdm_error(ctx, error):
            if isinstance(error, commands.MemberNotFound):
                await ctx.send("❌ Could not find that user! Make sure you're mentioning a valid server member.")
            elif isinstance(error, commands.MissingRequiredArgument):
                await ctx.send("❌ Please specify a user to report! Usage: `!reportdm @user [reason]`")
            else:
                await ctx.send(f"❌ An error occurred: {str(error)}")

        @self.command(name='reportscam', help='Report a scam attempt')
        async def reportscam(ctx, user: discord.Member = None, *, details: str = None):
            try:
                if not ctx.guild:
                    await ctx.send("❌ This command can only be used in a server!")
                    return

                # If replying to a message, get that message's author
                referenced_msg = ctx.message.reference
                if referenced_msg and referenced_msg.resolved:
                    user = referenced_msg.resolved.author
                    details = details or referenced_msg.resolved.content

                if not user and not details:
                    # Show help message if no parameters provided
                    embed = discord.Embed(
                        title="📝 How to Report a Scam",
                        description="There are several ways to report a scam:",
                        color=discord.Color.blue()
                    )
                    embed.add_field(
                        name="Reply to Message",
                        value="Reply to the scam message with `!reportscam`",
                        inline=False
                    )
                    embed.add_field(
                        name="Report User",
                        value="`!reportscam @user [details]`",
                        inline=False
                    )
                    embed.add_field(
                        name="Report Incident",
                        value="`!reportscam [details]` - Report without specifying a user",
                        inline=False
                    )
                    await ctx.send(embed=embed)
                    return

                # Create report
                report = ScamReport(
                    user_id=user.id if user else None,
                    reporter_id=ctx.author.id,
                    timestamp=datetime.now(timezone.utc),
                    reason="Scam attempt",
                    evidence=details or "No details provided",
                    message_content=details,
                    channel_id=ctx.channel.id
                )

                # Add to community database if user is specified
                is_confirmed = False
                if user:
                    is_confirmed = await self.community_db.add_report(
                        user_id=user.id,
                        reporter_id=ctx.author.id,
                        evidence=details or "Scam attempt",
                        guild_id=ctx.guild.id
                    )

                # Process the report
                await self.process_detailed_report(ctx.guild, report)

                # Learn from the report
                if details:
                    await self.pattern_learner.learn_from_report(details, is_confirmed_scam=True)
                    # Add to recent scams
                    await self.scam_detector.add_scam_attempt(
                        ctx.guild.id,
                        details,
                        ["reported_scam"]
                    )

                # Create response embed
                embed = discord.Embed(
                    title="🚨 Scam Report Submitted",
                    description="Thank you for helping keep the community safe!",
                    color=discord.Color.orange(),
                    timestamp=datetime.now(timezone.utc)
                )

                embed.add_field(
                    name="Reporter",
                    value=ctx.author.mention,
                    inline=True
                )

                if user:
                    embed.add_field(
                        name="Reported User",
                        value=f"{user.mention} ({user.id})",
                        inline=True
                    )
                    
                    # Get user trust info
                    trust_info = await self.trust_rating.calculate_trust_score(user, [ctx.guild])
                    embed.add_field(
                        name="User Trust Rating",
                        value=f"**{trust_info['rating']}** ({trust_info['score']:.1%})",
                        inline=False
                    )

                if details:
                    embed.add_field(
                        name="Details",
                        value=details[:1024],  # Discord field value limit
                        inline=False
                    )

                if is_confirmed:
                    embed.add_field(
                        name="⚠️ Warning",
                        value="This user has been marked as a confirmed scammer due to multiple reports!",
                        inline=False
                    )

                # Add safety tips
                safety_tips = [
                    "• Never click suspicious links",
                    "• Don't share personal information",
                    "• Be wary of 'free' offers",
                    "• Report any further attempts"
                ]
                embed.add_field(
                    name="Safety Tips",
                    value="\n".join(safety_tips),
                    inline=False
                )

                await ctx.send(embed=embed)

                # If the user is now a confirmed scammer, notify moderators
                if is_confirmed and user:
                    for guild in user.mutual_guilds:
                        for channel in guild.channels:
                            if channel.name in ['mod-logs', 'security-logs', 'incident-logs']:
                                if isinstance(channel, discord.TextChannel):
                                    alert_embed = discord.Embed(
                                        title="🚨 Confirmed Scammer Alert",
                                        description=f"{user.mention} has been marked as a confirmed scammer!",
                                        color=discord.Color.red()
                                    )
                                    alert_embed.add_field(
                                        name="User ID",
                                        value=str(user.id),
                                        inline=True
                                    )
                                    alert_embed.add_field(
                                        name="Report Count",
                                        value=str(len(self.community_db.scam_reports[user.id])),
                                        inline=True
                                    )
                                    if details:
                                        alert_embed.add_field(
                                            name="Latest Report Details",
                                            value=details[:1024],
                                            inline=False
                                        )
                                    await channel.send(embed=alert_embed)
                                    break

                # Delete the scam message if it was replied to
                if referenced_msg and referenced_msg.resolved and ctx.channel.permissions_for(ctx.guild.me).manage_messages:
                    try:
                        await referenced_msg.resolved.delete()
                        await ctx.send("✅ Scam message has been deleted.", delete_after=5)
                    except discord.Forbidden:
                        pass

            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @reportscam.error
        async def reportscam_error(ctx, error):
            if isinstance(error, commands.MemberNotFound):
                await ctx.send("❌ Could not find that user! Make sure you're mentioning a valid server member.")
            else:
                await ctx.send(f"❌ An error occurred: {str(error)}")

        @self.command(name='previewlink', help='Get a safe preview of a link')
        async def previewlink(ctx, url: str):
            try:
                if not self.link_preview.is_safe_url(url):
                    await ctx.send("❌ Invalid or unsafe URL provided!")
                    return

                async with ctx.typing():
                    preview_url = await self.link_preview.get_screenshot(url)
                    
                    if not preview_url:
                        await ctx.send("❌ Could not generate preview for this link.")
                        return

                    embed = discord.Embed(
                        title="🔍 Link Preview",
                        description=f"Preview for: {url}",
                        color=discord.Color.blue()
                    )
                    embed.set_image(url=preview_url)
                    embed.set_footer(text="Always be cautious with unknown links!")
                    
                    await ctx.send(embed=embed)
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='staffchannel', help='Set up staff notification channel')
        @commands.has_permissions(administrator=True)
        async def staffchannel(ctx, action: str = "add"):
            try:
                if action.lower() == "add":
                    await self.staff_notifier.add_notification_channel(ctx.guild.id, ctx.channel.id)
                    await ctx.send("✅ This channel has been set up for staff notifications!")
                elif action.lower() == "remove":
                    await self.staff_notifier.remove_notification_channel(ctx.guild.id, ctx.channel.id)
                    await ctx.send("✅ This channel will no longer receive staff notifications.")
                else:
                    await ctx.send("❌ Invalid action! Use `add` or `remove`")
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='checkname', help='Check for similar usernames')
        async def checkname(ctx, member: discord.Member = None):
            try:
                target = member or ctx.author
                analysis = await self.username_checker.analyze_username(target)
                
                embed = discord.Embed(
                    title="👤 Username Analysis",
                    description=f"Analysis for {target.mention}",
                    color=discord.Color.red() if analysis['risk_level'] == 'HIGH' else discord.Color.green()
                )
                
                if analysis['similar_users']:
                    similar_list = []
                    for entry in analysis['similar_users'][:5]:  # Show top 5
                        user = entry['user']
                        similarity = entry['similarity']
                        similar_list.append(f"• {user.name} ({similarity:.1%} similar)")
                    
                    embed.add_field(
                        name="⚠️ Similar Usernames Found",
                        value="\n".join(similar_list),
                        inline=False
                    )

                if analysis['protected_terms']:
                    embed.add_field(
                        name="🚫 Protected Terms Used",
                        value="• " + "\n• ".join(analysis['protected_terms']),
                        inline=False
                    )

                if analysis['recommendations']:
                    embed.add_field(
                        name="💡 Recommendations",
                        value="• " + "\n• ".join(analysis['recommendations']),
                        inline=False
                    )

                await ctx.send(embed=embed)
            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @self.command(name='scamexamples', help='View examples of common scams')
        async def scamexamples(ctx):
            try:
                embeds = []
                
                # Nitro Scam Example
                nitro_embed = discord.Embed(
                    title="Free Nitro Scam",
                    description="Common free Discord Nitro scam example",
                    color=discord.Color.red()
                )
                nitro_embed.add_field(
                    name="🎮 Example Message",
                    value="```Hey! Discord is giving away free Nitro! Claim yours at: dlscord.gift/free-nitro```",
                    inline=False
                )
                nitro_embed.add_field(
                    name="🚩 Red Flags",
                    value="• Misspelled domain (dlscord instead of discord)\n"
                          "• Promises free Nitro\n"
                          "• Suspicious link\n"
                          "• Creates urgency",
                    inline=False
                )
                embeds.append(nitro_embed)

                # Steam Gift Scam Example
                steam_embed = discord.Embed(
                    title="Steam Gift Scam",
                    description="Common Steam gift card scam example",
                    color=discord.Color.red()
                )
                steam_embed.add_field(
                    name="🎮 Example Message",
                    value="```Hi! I'm quitting Steam and giving away my inventory! Claim free games: steamcommunnity.com/trade/gift```",
                    inline=False
                )
                steam_embed.add_field(
                    name="🚩 Red Flags",
                    value="• Misspelled domain (communnity)\n"
                          "• Too good to be true\n"
                          "• Random DM\n"
                          "• Suspicious link",
                    inline=False
                )
                embeds.append(steam_embed)

                # Staff Impersonation Example
                staff_embed = discord.Embed(
                    title="Staff Impersonation Scam",
                    description="Common Discord staff impersonation scam",
                    color=discord.Color.red()
                )
                staff_embed.add_field(
                    name="👤 Example Message",
                    value="```Hello, I am Discord Staff. Your account has been reported. Verify here to avoid suspension: discord.gift/verify```",
                    inline=False
                )
                staff_embed.add_field(
                    name="🚩 Red Flags",
                    value="• Claims to be Discord staff\n"
                          "• Creates fear/urgency\n"
                          "• Suspicious link\n"
                          "• Threatens account suspension",
                    inline=False
                )
                embeds.append(staff_embed)

                # Send all embeds
                for embed in embeds:
                    embed.set_footer(text="Always report scam attempts using !reportscam")
                    await ctx.send(embed=embed)
                    await asyncio.sleep(1)  # Small delay between embeds

            except Exception as e:
                await ctx.send(f"❌ An error occurred: {str(e)}")

        @staffchannel.error
        async def staffchannel_error(ctx, error):
            if isinstance(error, commands.MissingPermissions):
                await ctx.send("❌ You need Administrator permission to manage staff channels!")
            else:
                await ctx.send(f"❌ An error occurred: {str(error)}")

    async def setup_hook(self):
        """Initialize async components"""
        await super().setup_hook()
        self.loop.create_task(self.cleanup_old_data())
        
        # Remove default help command
        self.remove_command('help')
        
        # Register commands
        @self.command(name='help', help='Shows all available commands')
        async def help_command(ctx):
            embed = discord.Embed(
                title="🛡️ Enforcer Bot Commands",
                description="Here are all available commands:",
                color=discord.Color.blue()
            )

            # User Safety Commands
            embed.add_field(
                name="🛡️ User Safety",
                value="`!scaminfo` - Learn about common scams and safety tips\n"
                      "`!checkuser @user` - Check a user's trust rating\n"
                      "`!reportdm @user` - Report suspicious DMs\n"
                      "`!reportscam` - Report a scam attempt\n"
                      "`!checkname [@user]` - Check for similar usernames\n"
                      "`!previewlink [url]` - Get a safe preview of a link",
                inline=False
            )

            # Server Protection
            embed.add_field(
                name="🔒 Server Protection",
                value="`!lockdown` - View lockdown status\n"
                      "`!lockdown enable [duration]` - Enable lockdown\n"
                      "`!lockdown disable` - Disable lockdown\n"
                      "`!staffchannel add/remove` - Set up staff notification channel",
                inline=False
            )

            # Scam Prevention
            embed.add_field(
                name="🚫 Scam Prevention",
                value="`!scamdomains list` - List known scam domains\n"
                      "`!scamdomains add [domain]` - Add domain to blacklist\n"
                      "`!scamdomains remove [domain]` - Remove domain from blacklist\n"
                      "`!scamexamples` - View examples of common scams",
                inline=False
            )

            # Statistics & Monitoring
            embed.add_field(
                name="📊 Statistics",
                value="`!recentscams` - View recent scam attempts\n"
                      "`!scamstats` - View scam prevention stats",
                inline=False
            )

            await ctx.send(embed=embed)

        # Print available commands
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
        """Enhanced check for staff impersonation"""
        content = message.content.lower()
        author = message.author
        
        # Check message content for staff terms
        staff_terms = [
            'mod', 'admin', 'staff', 'official', 'discord staff',
            'moderator', 'administrator', 'support', 'helper'
        ]
        
        content_suspicious = any(term in content for term in staff_terms)
        
        # Check username impersonation
        username_check = await self.username_detector.check_impersonation(
            author, 
            message.guild.members if message.guild else []
        )

        return content_suspicious or username_check['is_impersonating']

    async def handle_staff_impersonation(self, message: discord.Message):
        """Enhanced handling of staff impersonation attempts"""
        # Get detailed impersonation check
        username_check = await self.username_detector.check_impersonation(
            message.author,
            message.guild.members if message.guild else []
        )

        # Create detailed alert
        embed = discord.Embed(
            title="🚫 Staff Impersonation Alert",
            description="A user has been detected attempting to impersonate staff",
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(
            name="User",
            value=f"{message.author.mention} ({message.author.id})\n"
                  f"Username: {message.author.name}\n"
                  f"Display Name: {message.author.display_name}",
            inline=False
        )

        if username_check['matched_users']:
            similar_users = "\n".join(
                f"• {user['user'].name} (Similarity: {user['similarity']:.1%})"
                for user in username_check['matched_users']
            )
            embed.add_field(
                name="Similar to Staff Members",
                value=similar_users,
                inline=False
            )

        if username_check['protected_term_used']:
            embed.add_field(
                name="Protected Terms Used",
                value="Username contains protected staff-related terms",
                inline=False
            )

        embed.add_field(
            name="Risk Level",
            value=f"⚠️ {username_check['risk_level']}",
            inline=True
        )

        embed.add_field(
            name="Message Content",
            value=f"```{message.content}```",
            inline=False
        )

        # Log to all appropriate channels in mutual guilds
        for guild in message.author.mutual_guilds:
            for channel in guild.channels:
                if channel.name in ['security-logs', 'incident-logs']:
                    if isinstance(channel, discord.TextChannel):
                        await channel.send(embed=embed)
                        break

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
        """Enhanced DM message handling with advanced screening"""
        # Screen the DM
        screen_result = await self.dm_screener.screen_dm(
            message.content,
            message.author.id,
            message.author.mutual_guilds
        )

        # Learn from the message
        if not screen_result['is_safe']:
            await self.pattern_learner.learn_from_report(message.content, is_confirmed_scam=screen_result['risk_score'] > 0.7)

        # Check community database
        user_status = await self.community_db.get_user_status(message.author.id)
        
        if user_status['is_confirmed_scammer']:
            # Block message and notify recipient
            warning = "⚠️ **CAUTION**: This user has been reported multiple times for scam attempts."
            try:
                await message.channel.send(warning)
            except discord.Forbidden:
                pass
            return

        if not screen_result['is_safe']:
            # Create warning embed
            embed = discord.Embed(
                title="⚠️ Potential Scam Detected",
                description="This message has been flagged as potentially suspicious:",
                color=discord.Color.red()
            )
            
            embed.add_field(
                name="Risk Score",
                value=f"{screen_result['risk_score']:.1%}",
                inline=True
            )
            
            embed.add_field(
                name="Risk Factors",
                value="\n".join(f"• {factor}" for factor in screen_result['risk_factors']),
                inline=False
            )
            
            embed.add_field(
                name="Recommendation",
                value="Be cautious with this message. You can use `!reportdm @user` to report if this is a scam attempt.",
                inline=False
            )
            
            try:
                await message.channel.send(embed=embed)
            except discord.Forbidden:
                pass

        # Continue with normal DM handling
        await super().handle_dm_message(message)

    @commands.command(name='recentscams', help='View recent scam attempts in the server')
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

    @commands.command(name='scaminfo', help='Learn about common scams and safety tips')
    async def scam_info(self, ctx):
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

    @commands.command(name='scamstats')
    async def scam_statistics(self, ctx):
        """View current scam prevention statistics"""
        embed = discord.Embed(
            title="🛡️ Scam Prevention Statistics",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        # Get statistics
        total_patterns = len(self.pattern_learner.known_patterns)
        total_scammers = len(self.community_db.confirmed_scammers)
        total_reports = sum(len(reports) for reports in self.community_db.scam_reports.values())
        
        embed.add_field(
            name="Known Patterns",
            value=f"🔍 {total_patterns} patterns identified",
            inline=True
        )
        
        embed.add_field(
            name="Confirmed Scammers",
            value=f"🚫 {total_scammers} users",
            inline=True
        )
        
        embed.add_field(
            name="Total Reports",
            value=f"📊 {total_reports} reports processed",
            inline=True
        )
        
        await ctx.send(embed=embed)
 