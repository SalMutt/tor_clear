# qBittorrent Ratio Checker

## What does this script do?

This Python script helps manage your qBittorrent torrents automatically. It does two main things:

1. It checks all your torrents in qBittorrent.
2. If any torrent has a ratio of 1.0 or higher (meaning you've uploaded as much as you've downloaded), it stops seeding that torrent.

## Why is this useful?

- It saves you time by automatically managing your torrents.
- It helps you maintain good seeding practices without manual work.
- It can be scheduled to run daily, so you don't have to remember to check your torrents.

## What you need to use this script

1. Python 3.6 or newer.
2. qBittorrent installed with Web UI enabled.
3. Two Python libraries: `qbittorrent-api` and `cryptography`.

## How to set up and use the script

1. **Install Python libraries:**
   Open your command prompt or terminal and type:
   ```
   pip install qbittorrent-api cryptography
   ```

2. **Download the script:**
   - Unzip the file on your computer.

3. **Run the script:**
   - Open a terminal.
   - Navigate to the folder where you unzipped the script.
   - Type: `python tor_cleaner.py`

4. **First-time setup:**
   - The first time you run the script, it will ask for your qBittorrent Web UI username and password.
   - It will save these securely for future use.

5. **Future runs:**
   - The script will use the saved login details automatically.
