# Lessons Learned

Three issues came up while building this lab that aren't obvious from any tutorial, and each one taught me something worth writing down.

## 1. Wazuh's indexer crashed on first boot — missing SSL certificates

**Symptom:** all three Wazuh containers (manager, indexer, dashboard) showed as running, but restarted every few seconds. The Wazuh dashboard wasn't reachable at `https://localhost`.

**Root cause:** the Wazuh Docker Compose setup expects SSL certificate files to already exist in a specific folder before the stack starts. I ran `docker compose up -d` without first running the separate certificate-generation step, so Docker silently created empty directories where certificate *files* were expected. The indexer's logs made this exact problem visible:
```
OpenSearchException[Is a directory: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
Expected a file for plugins.security.ssl.transport.pemcert_filepath]
```

**Fix:**
```bash
sudo docker compose down
sudo rm -rf config/wazuh_indexer_ssl_certs
sudo docker compose -f generate-indexer-certs.yml run --rm generator
sudo docker compose up -d
```

**What I'd check first next time:** any Docker Compose stack that expects certificates or credentials to exist beforehand usually documents a separate "init" or "setup" command — I should run any documented one-time setup step before the main `up -d`, rather than assuming the stack bootstraps everything itself. The error message itself ("Is a directory... expected a file") is also a strong, specific signal — worth learning to recognize that pattern as "something wasn't generated, a placeholder was created instead."

## 2. The MSHTA detection rule didn't fire — regex vs literal string

**Symptom:** rule 100011 (MITRE T1218.005) never triggered, even though the attack simulation ran successfully and the corresponding Event ID 4688 was visible in the Wazuh dashboard. A separate, simpler rule matching on `win.system.eventID` worked fine, which narrowed the problem down to something specific about the field I was trying to match.

**Root cause:** Wazuh's `<field>` tags treat their value as a **regular expression**, not a literal string. My rule was written as:
```xml
<field name="win.eventdata.newProcessName">C:\Windows\System32\mshta.exe</field>
```
Backslashes and dots are special characters in regex — an unescaped backslash can be interpreted as the start of an escape sequence, and an unescaped dot means "match any character" rather than a literal period. The Windows file path, written in plain form, simply isn't valid as a matching pattern the way I'd written it.

**Fix:** stopped trying to match the full path, and matched on the binary name with the dot properly escaped and the pattern explicitly marked as regex:
```xml
<field name="win.eventdata.newProcessName" type="pcre2">mshta\.exe$</field>
```
I also added a second condition on the command line (`(?i)vbscript.*powershell`), which turned out to be an improvement rather than just a workaround — it made the rule detect the actual malicious *behavior* pattern instead of just "this binary ran," which is both more accurate and harder to accidentally trigger on legitimate use.

**What I'd check first next time:** any config field described as accepting a "pattern" or that silently accepts arbitrary strings without validating them is worth assuming is regex until proven otherwise, especially in Windows-path contexts, since backslashes are exactly the character most likely to cause a silent (non-erroring) mismatch. Also — `wazuh-logtest` (the built-in rule tester) would have caught this in seconds if I'd used it from the start instead of re-running the full attack simulation each time I wanted to test a rule change.

## 3. Windows wasn't logging command-line arguments at all

**Symptom:** Event ID 4688 (process creation) events were arriving in Wazuh, but the `commandLine` field was empty or missing — meaning no rule depending on command-line content (like the mshta detection) could ever have worked, regardless of the regex issue above.

**Root cause:** Windows does not log process command-line arguments by default, even with basic process-creation auditing turned on. There's a separate, easy-to-miss Group Policy setting specifically for this: **Computer Configuration → Administrative Templates → System → Audit Process Creation → "Include command line in process creation events."** Without it, you get the fact that a process started, but not what it was actually told to do — which for LOLBin-style detections is the entire point.

**Fix:** enabled that specific policy, then forced it to apply immediately:
```
gpupdate /force
```

**What I'd check first next time:** when a detection rule fails to fire, check the raw log data itself before assuming the rule syntax is wrong — I initially spent time on the regex issue above without first confirming the command-line field actually had data in it at all. Verifying the input exists and looks correct should come before debugging the rule that reads it.

## General takeaway

All three issues share a pattern: something failed *silently* rather than with a clear error pointing at the actual cause (empty directories instead of a clear "certs missing" message, a rule that just never matches instead of a regex syntax error, a log field that's simply blank instead of an explicit warning). The lesson that generalizes best beyond this specific lab: when something "isn't working" with no error message, verify each layer of the pipeline independently, starting from the raw data and working outward — is the log being generated at all, does it contain the field I think it does, does my rule's pattern actually match that field's real format — rather than guessing at higher-level explanations first.