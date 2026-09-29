# RDP Brute Force Simulation — T1110

## Command
```bash
hydra -l labuser -P wordlist.txt rdp://192.168.56.5
```

## What this does
- `-l labuser`: the username targeted (matches the local account created on the Windows VM)
- `-P wordlist.txt`: a small test wordlist of candidate passwords, tried one at a time
- `rdp://192.168.56.5`: target protocol and IP, the Windows VM on the isolated lab network

## Environment
- Run from: Kali Linux VM (192.168.56.4)
- Target: Windows 11 VM (192.168.56.5), RDP enabled, isolated Internal Network
- Wordlist: 5 candidate passwords, intentionally small for a controlled test rather than a real crack attempt

## Expected result
Multiple Event ID 4625 (failed logon) entries on the Windows Security log in quick succession, from the same source IP and target account — the pattern Wazuh rule 100010 is built to catch.