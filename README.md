# **SLSsteam-Plus - Steamclient Modification for Linux**
![](https://github.com/AceSLS/SLSsteam/blob/dev/res/banner.png?raw=true "SLSsteam")

## Index

1. [About this hard fork](#about-this-hard-fork)
2. [Getting started](#getting-started)
3. [Hall of Fame 👑](#hall-of-fame-aka-credits)
4. [Hall of Shame 🚨](#hall-of-shame-aka-scammers-leechers-etc)
5. [Support](#support)
6. [Related Projects](#related-projects)

## About this hard fork

SLSsteam-Plus is a hard fork of the original
[SLSsteam](https://github.com/AceSLS/SLSsteam) project. It keeps the Linux Steam
client modification base while adding a Lua-driven configuration layer and
manifest support for depot keys, access tokens, and manifest pinning. It stays a
drop-in replacement for upstream — same `~/.config/SLSsteam` layout and library
names — so only the released archives are named `SLSsteam-Plus-*` to tell them
apart.

The Lua and manifest workflows are inspired by
[OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool), adapted for the
Linux/SLSsteam environment rather than the Windows DLL model used upstream.

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

Please do not treat the issue tracker like a private support hotline!
Feel free to join our [Discord](https://discord.gg/j3ZzjeV4eQ) instead.

## Related Projects

[OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool): Inspiration for
the Lua configuration and manifest workflows in this hard fork.

[h3adcr-b](https://github.com/Deadboy666/h3adcr-b): Universal SLSsteam installer & steamclient downgrader

[steamnetsock-patch](https://github.com/yesyes0649/steamnetsock-patch): Makes FakeAppIds work in some games where it otherwise wouldn't
