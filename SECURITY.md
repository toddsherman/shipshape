# Security policy

## Reporting a vulnerability

Please report security issues in Shipshape privately, not in a public issue. Use GitHub's **Report a vulnerability** button on this repository's Security tab. Include the version, what you found and how to reproduce it. You should hear back within a week.

Examples of what to report:
- a command Shipshape recommends that could do something other than what it says, such as a quoting or injection problem with a package or folder name;
- a way for a lockfile, settings file or advisory response to make the app run, open or send something it shouldn't;
- a way to make Shipshape install an update that isn't signed by its developer;
- private data (paths, package names, keys) leaving the Mac other than as documented in the README.

If Shipshape misses a known vulnerability or reports a wrong one, that's a coverage bug. Open a regular issue for it.

## Supported versions

Only the latest release gets fixes.

## What Shipshape will never do

- Run, install, remove or change other software. It only shows commands for you to review and run. The one thing it installs is its own signed update, when you click Install Update.
- Run code from your projects or from programs another account controls. Homebrew is read from its folders, and the few programs it asks for a version number must belong to you or root.
- Open a project file with anything but your text editor, or open one that is a link, executable, or outside your project folders.
- Recommend piping a download into a shell.
- Read or keep environment variables, API keys or tokens from MCP settings. Only server commands and arguments are read.
- Send analytics, or send your inventory anywhere except the advisory lookups documented in the README.
