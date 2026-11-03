# Discord Badge Spoofer

Inflate your Discord playtime and games badges. Add thousands of hours and mark thousands of games as played without actually downloading or launching them.

## How It Works

Discord has an analytics endpoint called `/api/v9/science`. When you play a game, your Discord app sends `launch_game` and `running_game_heartbeat` events to this endpoint.

This tool sends those exact same events for you with whatever playtime hours and game count you choose. Discord accepts them with a `204` status, and your profile badges update.

Your token and cookie are stored locally in `science_state.json`. Nothing is ever sent to third parties.

## Requirements

- Python 3.10+
- Dependencies in `requirements.txt` (`curl_cffi` for browser TLS impersonation)

```bash
pip install -r requirements.txt
```

## Quick Start

1. Clone or download this repo:
   ```bash
   git clone https://github.com/16zenkai/discord-badge-spoofer.git
   cd discord-badge-spoofer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run it:
   ```bash
   python main.py
   ```

4. Paste your Discord token and `cf_clearance` cookie when asked on the first run.

## Getting Your Credentials

### 1. Discord Token
1. Open Discord in your browser or desktop app.
2. Press `Ctrl + Shift + I` (or `Cmd + Option + I` on Mac) to open DevTools.
3. Click the **Network** tab.
4. Click any channel or send a message.
5. In the filter box, type `/api`. Click any request that pops up (like `messages` or `@me`).
6. Scroll down to **Request Headers**, find `Authorization`, and copy that entire token.

### 2. Cloudflare Cookie (`cf_clearance`)
1. In the same **Network** tab, find any request made to `discord.com` (like `science` or `@me`).
2. In **Request Headers**, find the `Cookie` line.
3. Copy the `cf_clearance=...` part (or paste the whole cookie header, the tool will extract what it needs).

### 3. Executable Fingerprint (Optional)
- You don't need this for playtime hours.
- If you want the games played badge, you can test it without a fingerprint first. If badges don't update after 2 days, use option `4` in the menu to generate a fingerprint from any 64-bit game `.exe` or running process PID.

## Menu Options

```text
[07:50:17] (/) Menu Options
[07:50:17]      ├── [1] Claim Games Playtime Badge
[07:50:17]      ├── [2] Claim Games Variety Badge
[07:50:17]      ├── [3] Refresh Auth
[07:50:17]      ├── [4] Set Fingerprint
[07:50:17]      └── [5] Exit
```

- `[1] Claim Games Playtime Badge`: Choose how many games and how many hours per game (e.g. 10,000 hours total).
- `[2] Claim Games Variety Badge`: Marks games as played (1 minute each) so your variety/total games count goes up.
- `[3] Refresh Auth`: Update your cookie or grab a fresh analytics token if your session expires.
- `[4] Set Fingerprint`: Bind an executable fingerprint to your user ID.
- `[5] Exit`: Quit the tool.

## Good To Know

- **Badges take time**: Discord calculates badge progress in batches. It usually takes **24 to 48 hours** for numbers to update on your profile. Be patient.
- **TOS Warning**: This breaks Discord Terms of Service. Don't use it on accounts you care about losing.

## Disclaimer

This software is strictly for **educational and research purposes**. It is not designed or intended to disrupt, harm, or bypass Discord's security infrastructure, nor does it encourage violating Discord's Terms of Service. The developers take zero responsibility for any actions taken using this tool or any account penalties that may occur. Use entirely at your own risk.

## Author & Contact

- **Developer**: 16zenkai
- **GitHub**: [@16zenkai](https://github.com/16zenkai)
- **Discord**: `16zenkai`
- **Telegram**: [@wzenkai](https://t.me/wzenkai)

## License

MIT License. Check [LICENSE](LICENSE) for details.
