@echo off
rem wimon launcher for Windows.
rem
rem Changes into the repository root before running, so the default data paths
rem (captures/, telemetry.jsonl, sdkconfig) resolve the same way regardless of
rem where the launcher was invoked from.
rem
rem Uses the Python launcher (py) because "python" may resolve to the Windows
rem Store stub, which does not run scripts.
rem
rem Ctrl+C: calling py directly (not through cmd /c) lets the console deliver the
rem interrupt to Python, so an interactive view stops without the extra
rem "Terminate batch job (Y/N)?" prompt.
setlocal
set "WIMON_HOME=%~dp0"
cd /d "%WIMON_HOME%"
py "%WIMON_HOME%wimon\cli.py" %*
