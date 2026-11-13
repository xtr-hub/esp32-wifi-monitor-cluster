@echo off
rem wimon launcher for Windows.
rem Runs the toolkit from this directory so it works from any working directory.
rem Uses the Python launcher (py) because "python" may resolve to the Windows
rem Store stub, which does not run scripts.
rem %~dp0 ends with a backslash, so append the subdirectory without one.
setlocal
set "WIMON_HOME=%~dp0wimon"
py "%WIMON_HOME%\cli.py" %*
