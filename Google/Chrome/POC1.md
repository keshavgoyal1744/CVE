
Step 1) Install official system-level Google Chrome as admin.
Use Chrome Enterprise MSI so you get the real Google updater.
https://chromeenterprise.google/download/

<img width="895" height="235" alt="image" src="https://github.com/user-attachments/assets/9242273a-3a4a-491e-9f98-c68828260970" />


Step 2) Create a non-admin user and open PowerShell as that user.

```bash
net user bb-low "LabPass123!" /add
runas /user:.\bb-low powershell.exe
runas /user:%COMPUTERNAME%\bb-low powershell.exe
```
<img width="864" height="230" alt="image" src="https://github.com/user-attachments/assets/d03242e7-48bb-4d1d-be4c-24be233c3ccc" />
