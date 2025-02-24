# Enforcer Discord Bot

A powerful Discord security bot designed to prevent scams, protect against raids, and ensure server safety.

## Server Setup

1. Create these required channels:
   - `mod-logs` - For moderation actions
   - `security-logs` - For security alerts
   - `incident-logs` - For incident tracking
   - `scam-alerts` - For scam warnings

2. Use `!setmodrole @role` to set your moderator role

## Commands

### General Commands
- `!checkuser @user` - Check user trust rating
- `!scaminfo` - View scam information
- `!reportdm @user` - Report suspicious DMs

### Moderation Commands
- `!setmodrole @role` - Set moderator role
- `!dmprotection` - DM protection settings
- `!recentscams` - View recent scams
- `!lockdown` - Server lockdown
- `!scamdomains` - Manage scam domains
- `!sharescam` - Share scam alerts

### Protection Settings
- `!dmprotection enable/disable` - Toggle protection
- `!dmprotection warn true/false` - Toggle warnings
- `!dmprotection blocknew true/false` - Block new accounts
- `!dmprotection minage <days>` - Set minimum age

## Need Help?
1. Check if all channels are created (`mod-logs`, `security-logs`, etc.)
2. Verify bot has administrator permissions
3. Set up moderator role using `!setmodrole` #   E n f o r c e r  
 