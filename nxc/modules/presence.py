import re
from impacket.dcerpc.v5 import samr, tsch, transport
from impacket.dcerpc.v5 import tsts as TSTS
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from contextlib import suppress
import traceback


class NXCModule:
    """
    Module to find Domain and Enterprise Admin presence on target systems over SMB.
    Made by @crosscutsaw, @NeffIsBack
    """

    name = "presence"
    description = "Traces Domain and Enterprise Admin presence in the target over SMB"
    supported_protocols = ["smb"]

    def options(self, context, module_options):
        """There are no module options."""

    # --- helper: build/bind DCE-RPC while pinning TCP to IP and using safe server name ---
    def get_dce_rpc(self, tcp_host, string_binding, dce_binding, connection, remote_name=None):
        """
        tcp_host: the TCP destination (IP)
        string_binding: ncacn_np binding (FQDN for Kerberos SPN; IP for NTLM is fine)
        remote_name: SMB server name for auth ('*SMBSERVER' for NTLM; FQDN for Kerberos)
        """
        rpctransport = transport.DCERPCTransportFactory(string_binding)

        # Pin the actual TCP destination to the IP we intend to hit.
        rpctransport.setRemoteHost(tcp_host)

        # Choose the SMB "server name" used by the session.
        if remote_name is None:
            remote_name = (
                f"{connection.hostname}.{connection.domain}"
                if connection.kerberos
                else "*SMBSERVER"
            )
        rpctransport.setRemoteName(remote_name)

        rpctransport.set_credentials(
            connection.username,
            connection.password,
            connection.domain,
            connection.lmhash,
            connection.nthash,
            aesKey=connection.aesKey,
        )
        rpctransport.set_kerberos(connection.kerberos, connection.kdcHost)

        dce = rpctransport.get_dce_rpc()
        if connection.kerberos:
            dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.bind(dce_binding)
        return dce

    def on_admin_login(self, context, connection):
        try:
            admin_users = self.enumerate_admin_users(context, connection)
            if not admin_users:
                context.log.fail("No admin users found.")
                return

            # Update user objects to check if they are in tasklist, users directory or in scheduled tasks
            self.check_users_directory(context, connection, admin_users)
            self.check_tasklist(context, connection, admin_users)
            self.check_scheduled_tasks(context, connection, admin_users)

            # print grouped/logged results nicely
            self.print_grouped_results(context, admin_users)
        except Exception as e:
            context.log.fail(str(e))
            context.log.debug(traceback.format_exc())

    def enumerate_admin_users(self, context, connection):
        admin_users = []

        try:
            tcp_ip = connection.host  # e.g., 10.10.11.181
            # Binding name: FQDN for Kerberos SPN; IP is fine for NTLM.
            bind_name = (
                f"{connection.hostname}.{connection.domain}"
                if connection.kerberos
                else tcp_ip
            )
            string_binding = fr"ncacn_np:{bind_name}[\pipe\samr]"
            dce = self.get_dce_rpc(
                tcp_host=tcp_ip,
                string_binding=string_binding,
                dce_binding=samr.MSRPC_UUID_SAMR,
                connection=connection,
                remote_name=(f"{connection.hostname}.{connection.domain}"
                             if connection.kerberos else "*SMBSERVER"),
            )
        except Exception as e:
            context.log.fail(f"Failed to connect to SAMR: {e}")
            context.log.debug(traceback.format_exc())
            return admin_users

        try:
            server_handle = samr.hSamrConnect2(dce)["ServerHandle"]
            domain = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"][0]["Name"]
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)
            self.domain_sid = resp["DomainId"].formatCanonical()
            domain_handle = samr.hSamrOpenDomain(
                dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, resp["DomainId"]
            )["DomainHandle"]
            context.log.debug(f"Resolved domain SID for {domain}: {self.domain_sid}")
        except Exception as e:
            context.log.fail(f"Failed to open domain {domain}: {e!s}")
            context.log.debug(traceback.format_exc())
            return admin_users

        admin_rids = {
            "Domain Admins": 512,
            "Enterprise Admins": 519,
        }

        # Enumerate admin groups and their members
        for group_name, group_rid in admin_rids.items():
            context.log.debug(f"Looking up group: {group_name} with RID {group_rid}")

            try:
                group_handle = samr.hSamrOpenGroup(dce, domain_handle, samr.GROUP_LIST_MEMBERS, group_rid)["GroupHandle"]
                resp = samr.hSamrGetMembersInGroup(dce, group_handle)
                for member in resp["Members"]["Members"]:
                    rid = int.from_bytes(member.getData(), byteorder="little")
                    try:
                        user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, rid)["UserHandle"]
                        username = samr.hSamrQueryInformationUser2(
                            dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation
                        )["Buffer"]["All"]["UserName"]

                        # If user already exists, append group name
                        if any(u["sid"] == f"{self.domain_sid}-{rid}" for u in admin_users):
                            user = next(u for u in admin_users if u["sid"] == f"{self.domain_sid}-{rid}")
                            user["group"].append(group_name)
                        else:
                            admin_users.append(
                                {
                                    "username": username,
                                    "sid": f"{self.domain_sid}-{rid}",
                                    "domain": domain,
                                    "group": [group_name],
                                    "in_tasks": False,
                                    "in_directory": False,
                                    "in_scheduled_tasks": False,
                                }
                            )
                        context.log.debug(f"Found user: {username} with RID {rid} in group {group_name}")
                    except Exception as e:
                        context.log.debug(f"Failed to get user info for RID {rid}: {e!s}")
                    finally:
                        with suppress(Exception):
                            samr.hSamrCloseHandle(dce, user_handle)
            except Exception as e:
                context.log.debug(f"Failed to get members of group {group_name}: {e!s}")
            finally:
                with suppress(Exception):
                    samr.hSamrCloseHandle(dce, group_handle)

        return admin_users

    def check_users_directory(self, context, connection, admin_users):
        dirs_found = set()

        # try C$\Users first
        try:
            files = connection.conn.listPath("C$", "\\Users\\*")
        except Exception as e:
            context.log.debug(f"C$\\Users unavailable: {e}, trying Documents and Settings")
            try:
                files = connection.conn.listPath("C$", "\\Documents and Settings\\*")
            except Exception as e:
                context.log.fail(f"Error listing fallback directory: {e}")
                return
        else:
            context.log.debug("Successfully listed C$\\Users")

        # collect folder names (lowercase) ignoring "." and ".."
        dirs_found.update([f.get_shortname().lower() for f in files if f.get_shortname().lower() not in [".", "..", "administrator"]])

        # for admin users, check for folder presence
        for user in admin_users:
            # Look for administrator.domain to check if SID 500 Administrator is present (second check)
            if user["username"].lower() in dirs_found or \
                    (user["username"].lower() == "administrator" and f"{user['username'].lower()}.{user['domain']}" in dirs_found):
                user["in_directory"] = True
                context.log.info(f"Found user {user['username']} in directories")

    def check_tasklist(self, context, connection, admin_users):
        """Checks tasklist over rpc."""
        # Choose a stable server name for the RPC layer (matches our SMB session)
        remote_name = (
            f"{connection.hostname}.{connection.domain}"
            if connection.kerberos else "*SMBSERVER"
        )
        try:
            # LegacyAPI reuses the existing SMB connection; give it the right name
            with TSTS.LegacyAPI(connection.conn, remote_name, kerberos=connection.kerberos) as legacy:
                handle = legacy.hRpcWinStationOpenServer()
                processes = legacy.hRpcWinStationGetAllProcesses(handle)
        except Exception as e:
            msg = str(e)
            # If the WinStation/TSTS pipe or object isn't there, just skip this check
            if "STATUS_OBJECT_NAME_NOT_FOUND" in msg or "0xc0000034" in msg.lower():
                context.log.debug("TSTS/WinStation endpoint not present; skipping tasklist enumeration")
                return []
            # Other errors: log and continue without failing the whole module
            context.log.fail(f"Error in check_tasklist RPC method: {e}")
            return []

        context.log.debug(f"Enumerated {len(processes)} processes on {connection.host}")

        for process in processes:
            context.log.debug(f"ImageName: {process['ImageName']}, UniqueProcessId: {process['SessionId']}, pSid: {process['pSid']}")
            for user in admin_users:
                if process["pSid"] == user["sid"]:
                    user["in_tasks"] = True
                    context.log.info(f"Matched process {process['ImageName']} with user {user['username']}")

    def check_scheduled_tasks(self, context, connection, admin_users):
        """Checks scheduled tasks over rpc."""
        try:
            tcp_ip = connection.host
            target_name = (
                f"{connection.hostname}.{connection.domain}"
                if connection.kerberos
                else tcp_ip
            )
            stringbinding = f"ncacn_np:{target_name}[\\pipe\\atsvc]"
            dce = self.get_dce_rpc(
                tcp_host=tcp_ip,
                string_binding=stringbinding,
                dce_binding=tsch.MSRPC_UUID_TSCHS,
                connection=connection,
                remote_name=(f"{connection.hostname}.{connection.domain}"
                             if connection.kerberos else "*SMBSERVER"),
            )

            # Also extract non admins where we can get the password
            self.non_admins = []
            non_admin_sids = set()

            tasks = tsch.hSchRpcEnumTasks(dce, "\\")["pNames"]
            for task in tasks:
                xml = tsch.hSchRpcRetrieveTask(dce, task["Data"])["pXml"]
                # Extract SID and LogonType from the XML, if LogonType is "Password" we should be able to extract the password
                sid = re.search(fr"<UserId>({self.domain_sid}-\d{{3,}})</UserId>", xml)
                logon_type = re.search(r"<LogonType>(\w+)</LogonType>", xml)

                # Check if SID and LogonType are found, then check if SID matches any admin user
                if sid and logon_type and logon_type.group(1) == "Password":
                    context.log.debug(f"Found scheduled task '{task['Data']}' with SID {sid} and LogonType {logon_type.group(1)}")
                    if any(user["sid"] == sid.group(1) for user in admin_users):
                        user = next(user for user in admin_users if user["sid"] == sid.group(1))
                        user["in_scheduled_tasks"] = True
                    else:
                        # If not an admin user, add to non_admin_sids for further processing
                        non_admin_sids.add(sid.group(1))

            if non_admin_sids:
                # Re-use SAMR with pinned TCP to IP and correct server name.
                tcp_ip = connection.host
                bind_name = (
                    f"{connection.hostname}.{connection.domain}"
                    if connection.kerberos
                    else tcp_ip
                )
                string_binding = fr"ncacn_np:{bind_name}[\pipe\samr]"
                dce = self.get_dce_rpc(
                    tcp_host=tcp_ip,
                    string_binding=string_binding,
                    dce_binding=samr.MSRPC_UUID_SAMR,
                    connection=connection,
                    remote_name=(f"{connection.hostname}.{connection.domain}"
                                 if connection.kerberos else "*SMBSERVER"),
                )

                # Get Domain Handle
                server_handle = samr.hSamrConnect2(dce)["ServerHandle"]
                domain = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)["Buffer"]["Buffer"][0]["Name"]
                domain_sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain)["DomainId"]
                domain_handle = samr.hSamrOpenDomain(
                    dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, domain_sid
                )["DomainHandle"]

                for sid in non_admin_sids:
                    user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, int(sid.split("-")[-1]))["UserHandle"]
                    username = samr.hSamrQueryInformationUser2(
                        dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation
                    )["Buffer"]["All"]["UserName"]
                    self.non_admins.append(username)

        except Exception as e:
            context.log.fail(f"Failed to enumerate scheduled tasks: {e}")
            context.log.debug(traceback.format_exc())

    def print_grouped_results(self, context, admin_users):
        """Logs all results grouped per host in order"""
        # Make less verbose for scanning large ranges
        context.log.info(f"Identified Admin Users: {', '.join([user['username'] for user in admin_users])}")

        # Print directory users
        dir_users = [user for user in admin_users if user["in_directory"]]
        if dir_users:
            context.log.success("Found admins in directories:")
            for user in dir_users:
                context.log.highlight(f"{user['username']} ({', '.join(user['group'])})")

        # Print tasklist users
        tasklist_users = [user for user in admin_users if user["in_tasks"]]
        if tasklist_users:
            context.log.success("Found admins in tasklist:")
            for user in tasklist_users:
                context.log.highlight(f"{user['username']} ({', '.join(user['group'])})")

        # Print scheduled tasks users
        scheduled_tasks_users = [user for user in admin_users if user["in_scheduled_tasks"]]
        if scheduled_tasks_users:
            context.log.success("Found admins in scheduled tasks:")
            for user in scheduled_tasks_users:
                context.log.highlight(f"{user['username']} ({', '.join(user['group'])})")
        if getattr(self, "non_admins", None):
            context.log.info(f"Found {len(self.non_admins)} non-admin scheduled tasks:")
            for sid in self.non_admins:
                context.log.info(sid)

        # Making this less verbose to better scan large ranges
        if not dir_users and not tasklist_users:
            context.log.info("No matches found in users directory, tasklist or scheduled tasks.")
