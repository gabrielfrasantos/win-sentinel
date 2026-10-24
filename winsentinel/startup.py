"""Start with Windows: a Task Scheduler task that launches the app at logon, minimized,
with administrator rights and no UAC prompt.

The Startup folder can't do this: Windows silently skips startup programs that need
elevation. The task runs only while you're signed in (it is a tray app) and has no
run-time limit (the default 72 hours would stop it).
"""

from __future__ import annotations

import logging
import os
import sys
from xml.sax.saxutils import escape

from winsentinel import APP_NAME, winapi, wmi

logger = logging.getLogger(__name__)

TASK_NAME = APP_NAME
TASK_CREATE_OR_UPDATE = 6
TASK_LOGON_INTERACTIVE_TOKEN = 3

TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Starts win-sentinel in the tray at logon, elevated.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def current_user() -> str:
    domain = os.environ.get("USERDOMAIN", "")
    user = os.environ.get("USERNAME", "")
    return f"{domain}\\{user}" if domain else user


def launch_command() -> tuple[str, str]:
    """(program, arguments) that start this app minimized: the exe when installed,
    pythonw + module from a checkout."""
    if getattr(sys, "frozen", False):
        return sys.executable, "--minimized"
    pythonw = sys.executable.replace("python.exe", "pythonw.exe")
    return pythonw, "-m winsentinel.gui --minimized"


def task_xml(command: str, arguments: str, user: str) -> str:
    return TASK_XML.format(user=escape(user), command=escape(command), arguments=escape(arguments))


def _root_folder() -> object:
    service = wmi.dispatch("Schedule.Service")
    service.Connect()
    return service.GetFolder("\\")


def is_enabled() -> bool:
    if not winapi.WINDOWS:
        return False
    try:
        _root_folder().GetTask(TASK_NAME)  # type: ignore[attr-defined]
    except Exception:
        return False
    return True


def enable() -> None:
    """Create (or update) the logon task. Needs administrator. Raises WmiError."""
    if not winapi.WINDOWS:
        raise wmi.WmiError("Start with Windows needs Windows")
    import pythoncom
    import pywintypes

    command, arguments = launch_command()
    try:
        _root_folder().RegisterTask(  # type: ignore[attr-defined]
            TASK_NAME,
            task_xml(command, arguments, current_user()),
            TASK_CREATE_OR_UPDATE,
            pythoncom.Empty,
            pythoncom.Empty,
            TASK_LOGON_INTERACTIVE_TOKEN,
        )
    except pywintypes.com_error as e:
        raise wmi.WmiError(f"could not create the logon task: {wmi.com_message(e)}") from None
    logger.info("Start with Windows: on (%s %s)", command, arguments)


def disable() -> None:
    if not winapi.WINDOWS:
        return
    import pywintypes

    try:
        _root_folder().DeleteTask(TASK_NAME, 0)  # type: ignore[attr-defined]
    except pywintypes.com_error as e:
        if not is_enabled():
            return
        raise wmi.WmiError(f"could not remove the logon task: {wmi.com_message(e)}") from None
    logger.info("Start with Windows: off")
