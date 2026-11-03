# 🎮 zenkai • discord badge spoofer

<div align="left">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)
![Telegram](https://img.shields.io/badge/Telegram-@wzenkai-2CA5E0?style=flat-square&logo=telegram&logoColor=white)

</div>

Inflate your Discord playtime and games badges. Add thousands of hours and mark thousands of games as played without downloading or launching them.

---

## ✨ Features

- ⏱️ **Playtime Spoofer**: Add custom hours across 10,000+ verifiable Discord games.
- 🎯 **Variety Spoofer**: Rapidly register individual game titles for the games-played badge.
- 🛡️ **Browser TLS Impersonation**: Uses `curl_cffi` to mimic real Chrome 131 fingerprints.
- 🔒 **100% Local & Safe**: Credentials never leave your machine (`science_state.json`).
- ⚡ **Zero Hassle**: Pre-configured automatic session generation and dynamic build number resolution.

---

## ⚙️ How It Works

Discord tracks game activity through an analytics endpoint at `/api/v9/science`. When you play a game, your Discord client dispatches `launch_game` and `running_game_heartbeat` events.

This tool simulates those exact telemetry events with configurable durations and game lists. Discord accepts them with a `204` status, updating your profile badges.

> [!IMPORTANT]
> Your Discord token is saved strictly on your local machine in `science_state.json`. Never share your state file with anyone.

> [!NOTE]
> Badges take **24 to 48 hours** to refresh on your Discord profile because Discord computes telemetry in background batches.

---

## 🚀 Quick Start

### 1. Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`

### 2. Installation

Clone the repository and install requirements:

```bash
git clone https://github.com/16zenkai/discord-badge-spoofer.git
cd discord-badge-spoofer
pip install -r requirements.txt
```

### 3. Run

```bash
python main.py
```

Enter your Discord account token when prompted on first launch.

---

## 🔑 Getting Your Credentials

### 1. Discord Token (Required)
1. Open Discord in your web browser or desktop app.
2. Press `Ctrl + Shift + I` (or `Cmd + Option + I` on macOS) to open Developer Tools.
3. Switch to the **Network** tab.
4. Click any channel or send a message.
5. In the filter box, type `/api`. Click any request (such as `messages` or `@me`).
6. Scroll down to **Request Headers**, find `Authorization`, and copy that entire token.

*(Optional)* **Cloudflare Cookie (`cf_clearance`)**: Not required for normal runs. Only needed if your network or proxy triggers a Cloudflare challenge. You can add it anytime via Option `3` (Refresh Auth).

### 2. Executable Fingerprint (Optional)
- Setting a fingerprint is completely optional. Playtime hours and badges register with only your token.
- If you want to bind an authentic Windows PE fingerprint, use Option `4` in the menu to bind one from any 64-bit Windows game `.exe` or running process PID.

---

## 📋 Menu Overview

```text
[07:50:17] (/) Menu Options
[07:50:17]      ├── [1] Claim Games Playtime Badge
[07:50:17]      ├── [2] Claim Games Variety Badge
[07:50:17]      ├── [3] Refresh Auth
[07:50:17]      ├── [4] Set Fingerprint
[07:50:17]      └── [5] Exit
```

| Option | Action | Description |
| :---: | :--- | :--- |
| `[1]` | **Claim Games Playtime Badge** | Distribute custom playtime hours across games (e.g. 10,000 hours) |
| `[2]` | **Claim Games Variety Badge** | Mark games as played (1 min each) to inflate total games count |
| `[3]` | **Refresh Auth** | Update token/cookie and fetch a fresh analytics token |
| `[4]` | **Set Fingerprint** | Bind an executable fingerprint to your user ID |
| `[5]` | **Exit** | Close the tool |

---

## ⚠️ Disclaimer

> [!WARNING]
> This software is strictly for **educational and research purposes**. It is not designed or intended to disrupt, harm, or bypass Discord's security infrastructure, nor does it encourage violating Discord's Terms of Service. The developers take zero responsibility for any actions taken using this tool or any account penalties that may occur. Use entirely at your own risk.

---

## 👤 Author & Contact

| Platform | Handle | Link |
| :--- | :--- | :--- |
| **Developer** | `16zenkai` | — |
| **GitHub** | `@16zenkai` | [@16zenkai](https://github.com/16zenkai) |
| **Telegram** | `@wzenkai` | [@wzenkai](https://t.me/wzenkai) |
| **Discord** | `16zenkai` | — |

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
