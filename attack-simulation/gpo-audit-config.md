# Windows Audit Policy Configuration

Required before either simulation above produces usable log data.

1. `gpedit.msc` → Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration → System Audit Policies → Detailed Tracking → Audit Process Creation → Success + Failure
2. Same path → Logon/Logoff → Audit Logon → Success + Failure
3. Computer Configuration → Administrative Templates → System → Audit Process Creation → "Include command line in process creation events" → Enabled
4. Apply immediately: `gpupdate /force`

Without step 3 specifically, Event ID 4688 fires but without command-line data — which silently breaks the mshta detection rule, since it depends entirely on inspecting the command line content.

Please note: The Local Group Policy Editor (gpedit.msc) is only available in Windows Pro, Enterprise, and Education. If you are running Windows Home, this command will not work.