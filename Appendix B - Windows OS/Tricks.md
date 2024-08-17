## ping sweep
```powershell
1..20 | % {"192.168.1.$($_): $(Test-Connection -count 1 -comp 192.168.1.$($_) -quiet)"}
```

## run cmd commands from powershell
```powershell
cmd.exe /c <commands>
cmd.exe /c start <commands>
```