# multi-instance

Run two Roblox clients on the same PC. No DLL swap, no patching, no admin.

## Use

1. Close Roblox if it's open.
2. Double-click `multiclient.exe`. Roblox opens.
3. Sign in, pick a game.
4. The second client opens on its own once the first one is up.
5. Sign in on the second client with a different account.

Ctrl+C in the terminal, or closing either client, stops it and cleans up.

## How

Two things normally stop the second client. The first one is a named event that the first client watches, so when a second instance appears it tells the first one to reload; the tool holds that name with a deny-all security descriptor before Roblox starts, so the watcher never gets off the ground. The second one is a shared section handoff keyed on the EXE path, so the second instance sees the first one's HWND and hands over. The tool launches the second client through a Windows drive letter mapping the image name is still `RobloxPlayerBeta.exe` (pro Hyperion happy) but the path is `Z:\RobloxPlayerBeta.exe`, so the keyed name doesn't match and the handoff never happens.

No bytes of Roblox are modified on disk or in memory.

## Subcommands

The no-args flow does the right thing; these are here if you want to poke:

```
multiclient probe [--all]    list session named object entries
multiclient hold [names]     hold the singleton names until Ctrl+C
multiclient spawn <exe>      spawn a second client against a specific EXE
multiclient run              same as no args
```

## Requirements

Windows 10 or 11, x64. NTFS on the drive Roblox is installed to every default install.

## License

MIT.
