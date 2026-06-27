# **SLSsteam-Plus - Steamclient Modification for Linux**
![](https://github.com/AceSLS/SLSsteam/blob/dev/res/banner.png?raw=true "SLSsteam")

## Index

1. [About this hard fork](#about-this-hard-fork)
2. [Disclaimer & risk](#disclaimer--risk)
3. [Getting started](#getting-started)
4. [Hall of Fame 👑](#hall-of-fame-aka-credits)
5. [Hall of Shame 🚨](#hall-of-shame-aka-scammers-leechers-etc)
6. [Support](#support)
7. [Related Projects](#related-projects)

## About this hard fork

SLSsteam-Plus is a hard fork of [SLSsteam](https://github.com/AceSLS/SLSsteam), originally created by [AceSLS](https://github.com/AceSLS). This fork adds Lua configuration, depot key injection, access tokens, and manifest pinning on top of the original Linux Steam client mod. It uses the same `~/.config/SLSsteam` layout and library names as upstream; only the release archives are named `SLSsteam-Plus-*`.

**This fork is not affiliated with AceSLS or the original SLSsteam project.** All the foundational work is his. He has no involvement in SLSsteam-Plus, so please don't bring fork issues to him or his channels.

The Lua and manifest parts are based on [OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool), ported to work with the Linux/SLSsteam hooking model instead of Windows DLLs.

### Why this fork exists

Upstream SLSsteam doesn't do depot keys or manifests, and that's intentional. AceSLS said so in [#112](https://github.com/AceSLS/SLSsteam/issues/112) ("Steamtools does it via decryptionkeys & manifests but I won't add either") and [#35](https://github.com/AceSLS/SLSsteam/issues/35) ("I don't think that would be wise. So most likely not in my repo anyway"). Fair enough, but I needed it for my setup, so this fork adds it.

> [!IMPORTANT]
> **Primarily a personal project.** I maintain it mainly for my wife's Steam Deck. 
> Expect churn: APIs, config keys, and behaviour can change between versions, and support is best-effort.

## Disclaimer & risk

> [!CAUTION]
> **Use at your own risk.** This talks to the live Steam client. I try to suppress or fake requests that would reach Valve, but I can't promise nothing identifying ever leaks, and a Steam update can break that at any time. No warranty. You accept the risk for your account, saves, and install. If account safety matters to you, don't use this.

## Getting started

Check out the [Installation](https://github.com/AceSLS/SLSsteam/wiki/Installation) section in our Wiki!


## Hall of Fame aka Credits

Contributors:
- [Parasitic-Hollow](https://github.com/Parasitic-Hollow/): Fixing gamepad issues caused by FakeAppIds
- [amione](https://github.com/xamionex/): Creating the SLSsteam banner & logo the instant he found out I was looking around for one <3
- [DeveloperMikey](https://github.com/DeveloperMikey): Added Nix support 
- [skrimix](https://github.com/skrimix): Added flatpak support
- thismanq: Informing me that DisableFamilyShareLockForOthers is possible

Others:
- All the staff members of the Anti Denuvo Sanctuary for all their hard work they do. They also found a way to use SLSsteam I didn't even intend to, so shoutout to them
- Riku_Wayfinder: Being extremely supportive and lightening my workload by a lot. So show him some love my guys <3
- Gnanf: Helping me test the Family Sharing bypass
- rdbo: For his great libmem library, which saved me a lot of development and learning time
- jbeder: For the awesome yaml-cpp library which allowed me to easily add a configuration file
- oleavr and all the other awesome people working on Frida for easy instrumentation which helps a lot in analyzing, testing and debugging
- All the folks working on Ghidra, this was my first project using it and I'm in love with it!
- And many more I can't possibly list here for reporting bugs and giving feedback! Thank you guys <3


## Hall of Shame aka Scammers, Leechers, etc

🚨This list exists purely for educational and entertainment purposes!
Please do not seek out Projects listed here!
If you decide to ignore the aforementioned warning you do so on your own risk!🚨

OnetapBeta by Hammer Steam: Resells Steamless & SLSsteam. Intellectually went far enough to rename SLSsteam to deckloader2, that's about as far as their skill extends.

## Support

Bugs, questions, or anything about **this fork** (download, cloud-save, etc.) go in this repo's [Issues](../../issues) and [Discussions](../../discussions). That's where I track fork stuff.

> [!NOTE]
> The [Discord](https://discord.gg/j3ZzjeV4eQ) linked from upstream is AceSLS's, for the original SLSsteam. **Don't ask about SLSsteam-Plus there.** It's not their project to support. Keep upstream channels for upstream.

## Related Projects

[OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool): Where the Lua config and manifest handling ideas came from.

[h3adcr-b](https://github.com/Deadboy666/h3adcr-b): Universal SLSsteam installer & steamclient downgrader

[steamnetsock-patch](https://github.com/yesyes0649/steamnetsock-patch): Makes FakeAppIds work in some games where it otherwise wouldn't
