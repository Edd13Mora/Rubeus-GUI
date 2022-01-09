using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using Rubeus.lib.Interop;

namespace Rubeus
{
    public class Helpers
    {

        #region Friendly Name Helpers

        public static string GetDescriptionForKrbErrorCode(Interop.KERBEROS_ERROR errorCode)
        {
            switch (errorCode)
            {
                case Interop.KERBEROS_ERROR.KDC_ERR_NONE:
                    return "No error";
                case Interop.KERBEROS_ERROR.KDC_ERR_NAME_EXP:
                    return "Client's entry in KDC database has expired";
                case Interop.KERBEROS_ERROR.KDC_ERR_SERVICE_EXP:
                    return "Server's entry in KDC database has expired";
                case Interop.KERBEROS_ERROR.KDC_ERR_BAD_PVNO:
                    return "Requested Kerberos version number not supported";
                case Interop.KERBEROS_ERROR.KDC_ERR_C_OLD_MAST_KVNO:
                    return "Client's key encrypted in old master key";
                case Interop.KERBEROS_ERROR.KDC_ERR_S_OLD_MAST_KVNO:
                    return "Server's key encrypted in old master key";
                case Interop.KERBEROS_ERROR.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                    return "Client username not found in Kerberos database";
                case Interop.KERBEROS_ERROR.KDC_ERR_S_PRINCIPAL_UNKNOWN:
                    return "Service principal name not found in Kerberos database";
                case Interop.KERBEROS_ERROR.KDC_ERR_PRINCIPAL_NOT_UNIQUE:
                    return "Multiple principal entries in KDC database";
                case Interop.KERBEROS_ERROR.KDC_ERR_NULL_KEY:
                    return "The client or server has a null key (master key)";
                case Interop.KERBEROS_ERROR.KDC_ERR_CANNOT_POSTDATE:
                    return "Ticket (TGT) not eligible for postdating";
                case Interop.KERBEROS_ERROR.KDC_ERR_NEVER_VALID:
                    return "Requested start time is later than end time";
                case Interop.KERBEROS_ERROR.KDC_ERR_POLICY:
                    return "Requested start time is later than end time";
                case Interop.KERBEROS_ERROR.KDC_ERR_BADOPTION:
                    return "KDC cannot accommodate requested option";
                case Interop.KERBEROS_ERROR.KDC_ERR_ETYPE_NOTSUPP:
                    return "KDC has no support for encryption type";
                case Interop.KERBEROS_ERROR.KDC_ERR_SUMTYPE_NOSUPP:
                    return "KDC has no support for checksum type";
                case Interop.KERBEROS_ERROR.KDC_ERR_PADATA_TYPE_NOSUPP:
                    return "KDC has no support for PADATA type (pre-authentication data)";
                case Interop.KERBEROS_ERROR.KDC_ERR_TRTYPE_NO_SUPP:
                    return "KDC has no support for transited type";
                case Interop.KERBEROS_ERROR.KDC_ERR_CLIENT_REVOKED:
                    return "Client’s credentials have been revoked. This is usually caused by the account being disabled";
                case Interop.KERBEROS_ERROR.KDC_ERR_SERVICE_REVOKED:
                    return "Credentials for server have been revoked";
                case Interop.KERBEROS_ERROR.KDC_ERR_TGT_REVOKED:
                    return "TGT has been revoked";
                case Interop.KERBEROS_ERROR.KDC_ERR_CLIENT_NOTYET:
                    return "Client not yet valid - try again later";
                case Interop.KERBEROS_ERROR.KDC_ERR_SERVICE_NOTYET:
                     return "Server not yet valid - try again later";
                case Interop.KERBEROS_ERROR.KDC_ERR_KEY_EXPIRED:
                     return "Password has expired";
                case Interop.KERBEROS_ERROR.KDC_ERR_PREAUTH_FAILED:
                     return "Pre-authentication information was invalid. This is usually caused by an incorrect password";
                case Interop.KERBEROS_ERROR.KDC_ERR_PREAUTH_REQUIRED:
                     return "Additional preauthentication required";
                case Interop.KERBEROS_ERROR.KDC_ERR_SERVER_NOMATCH:
                     return "KDC does not know about the requested server";
                case Interop.KERBEROS_ERROR.KDC_ERR_SVC_UNAVAILABLE:
                     return "KDC is unavailable";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BAD_INTEGRITY:
                     return "Integrity check on decrypted field failed";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_TKT_EXPIRED:
                     return "The ticket has expired";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_TKT_NYV:
                     return "The ticket is not yet valid";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_REPEAT:
                     return "The request is a replay";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_NOT_US:
                     return "The ticket is not for us";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BADMATCH:
                     return "The ticket and authenticator do not match";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_SKEW:
                     return "The clock skew is too great. Ensure your clock is set to the same time as the server";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BADADDR:
                     return "Network address in network layer header doesn't match address inside ticket";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BADVERSION:
                     return "Protocol version numbers don't match (PVNO)";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_MSG_TYPE:
                     return "Message type is unsupported";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_MODIFIED:
                     return "Message stream modified and checksum didn't match";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BADORDER:
                     return "Message out of order (possible tampering)";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BADKEYVER:
                     return "Specified version of key is not available";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_NOKEY:
                     return "Service key not available";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_MUT_FAIL:
                     return "Mutual authentication failed";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BADDIRECTION:
                     return "Incorrect message direction";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_METHOD:
                     return "Alternative authentication method required";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_BADSEQ:
                     return "Incorrect sequence number in message";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_INAPP_CKSUM:
                     return "Inappropriate type of checksum in message (checksum may be unsupported)";
                case Interop.KERBEROS_ERROR.KRB_AP_PATH_NOT_ACCEPTED:
                     return "Desired path is unreachable";
                case Interop.KERBEROS_ERROR.KRB_ERR_RESPONSE_TOO_BIG:
                     return "Too much data";
                case Interop.KERBEROS_ERROR.KRB_ERR_GENERIC:
                     return "Generic error";
                case Interop.KERBEROS_ERROR.KRB_ERR_FIELD_TOOLONG:
                     return "Field is too long for this implementation";
                case Interop.KERBEROS_ERROR.KDC_ERR_CLIENT_NOT_TRUSTED:
                     return "The client trust failed or is not implemented";
                case Interop.KERBEROS_ERROR.KDC_ERR_KDC_NOT_TRUSTED:
                     return "The KDC server trust failed or could not be verified";
                case Interop.KERBEROS_ERROR.KDC_ERR_INVALID_SIG:
                     return "The signature is invalid";
                case Interop.KERBEROS_ERROR.KDC_ERR_KEY_TOO_WEAK:
                     return "A higher encryption level is needed";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_USER_TO_USER_REQUIRED:
                     return "User-to-user authorization is required";
                case Interop.KERBEROS_ERROR.KRB_AP_ERR_NO_TGT:
                     return "No TGT was presented or available";
                case Interop.KERBEROS_ERROR.KDC_ERR_WRONG_REALM:
                     return "Incorrect domain or principal";
               default:
                    return string.Empty;
            }
        }

        public static string GetFriendlyNameForEType(Interop.KERB_ETYPE etype)
        {
            switch (etype)
            {
                case Interop.KERB_ETYPE.unknown:
                    return "Unknown";
                case Interop.KERB_ETYPE.des_cbc_crc:
                    return "DES CRC";
                case Interop.KERB_ETYPE.des_cbc_md4:
                    return "DES MD4";
                case Interop.KERB_ETYPE.des_cbc_md5:
                    return "DES MD5";
                case Interop.KERB_ETYPE.des3_cbc_md5:
                    return "DES3 MD5";
                case Interop.KERB_ETYPE.des3_cbc_sha1:
                    return "DES3 SHA1";
                case Interop.KERB_ETYPE.aes128_cts_hmac_sha1:
                    return "AES-128";
                case Interop.KERB_ETYPE.aes256_cts_hmac_sha1:
                    return "AES-256";
                case Interop.KERB_ETYPE.rc4_hmac:
                    return "RC4";
                case Interop.KERB_ETYPE.rc4_hmac_exp:
                    return "RC4 EXP";
                default:
                    return etype.ToString();
            }
        }

        public static string GetFriendlyNameForETypeFlags(Interop.SUPPORTED_ETYPE etype)
        {
            System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder();
            if (etype.HasFlag(Interop.SUPPORTED_ETYPE.DES_CBC_CRC) || etype.HasFlag(Interop.SUPPORTED_ETYPE.DES_CBC_MD5))
            {
                stringBuilder.Append(" DES,");
            }
            if (etype.HasFlag(Interop.SUPPORTED_ETYPE.RC4_HMAC_DEFAULT) || etype.HasFlag(Interop.SUPPORTED_ETYPE.RC4_HMAC))
            {
                stringBuilder.Append(" RC4,");
            }
            if (etype.HasFlag(Interop.SUPPORTED_ETYPE.AES128_CTS_HMAC_SHA1_96))
            {
                stringBuilder.Append(" AES-128,");
            }
            if (etype.HasFlag(Interop.SUPPORTED_ETYPE.AES256_CTS_HMAC_SHA1_96))
            {
                stringBuilder.Append(" AES-256,");
            }
            return stringBuilder.ToString().TrimEnd(',').TrimStart(' ');
        }

        #endregion

        #region String Helpers

        public static IEnumerable<string> Split(string text, int partLength)
        {
            // splits a string into partLength parts
            if (text == null) { Console.WriteLine("[ERROR] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[ERROR] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        private static Random random = new Random();
        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        public static byte[] StringToByteArray(string hex)
        {
            // converts a rc4/AES/etc. string into a byte array representation

            if ((hex.Length % 16) != 0)
            {
                Console.WriteLine("\r\n[X] Hash must be 16, 32 or 64 characters in length\r\n");
                // This kills the GUI as well, so I've replaced it with an exception
                //System.Environment.Exit(1);
                throw new RubeusException("Hash must be 16, 32 or 64 characters in length");
            }

            // yes I know this inefficient
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        //StackOverflow goodness
        public static string ByteArrayToString(byte[] bytes)
        {
            char[] c = new char[bytes.Length * 2];
            int b;
            for (int i = 0; i < bytes.Length; i++)
            {
                b = bytes[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = bytes[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }
            return new string(c);
        }

        public static DateTime? FutureDate(DateTime date, string increase)
        {
            int multiplier;
            DateTime? returnDate = null;
            try
            {
                multiplier = Int32.Parse(increase.Substring(0, increase.Length - 1));
            }
            catch
            {
                Console.WriteLine("[X] Error invalid multiplier specified {0}, skipping.", increase.Substring(0, increase.Length - 1));
                return returnDate;
            }

            string period = increase.Substring(increase.Length - 1);

            switch (period)
            {
                case "m":
                    returnDate = date.AddMinutes(multiplier);
                    break;
                case "h":
                    returnDate = date.AddHours(multiplier);
                    break;
                case "d":
                    returnDate = date.AddDays(multiplier);
                    break;
                case "M":
                    returnDate = date.AddMonths(multiplier);
                    break;
                case "y":
                    returnDate = date.AddYears(multiplier);
                    break;
            }

            return returnDate;
        }

        #endregion


        #region Token Helpers

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM for Kerberos ticket enumeration via token impersonation
            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                if (!IsSystem())
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsSystem()
        {
            // returns true if the current user is "NT AUTHORITY\SYSTEM"
            var currentSid = WindowsIdentity.GetCurrent().User;
            return currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }

        public static LUID GetCurrentLUID()
        {
            // helper that returns the current logon session ID by using GetTokenInformation w/ TOKEN_INFORMATION_CLASS

            var TokenInfLength = 0;
            var luid = new LUID();

            // first call gets lenght of TokenInformation to get proper struct size
            var Result = Interop.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);

            // second call actually gets the information
            Result = Interop.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, TokenInformation, TokenInfLength, out TokenInfLength);

            if (Result)
            {
                var TokenStatistics = (Interop.TOKEN_STATISTICS)Marshal.PtrToStructure(TokenInformation, typeof(Interop.TOKEN_STATISTICS));
                luid = new LUID(TokenStatistics.AuthenticationId);
            }
            else
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] GetTokenInformation error: {0}", lastError);
                Marshal.FreeHGlobal(TokenInformation);
            }

            return luid;
        }

        public static LUID CreateProcessNetOnly(string commandLine, bool show = false)
        {
            // creates a hidden process with random /netonly credentials,
            //  displayng the process ID and LUID, and returning the LUID

            // Note: the LUID can be used with the "ptt" action

            Interop.PROCESS_INFORMATION pi;
            var si = new Interop.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            if (!show)
            {
                // hide the window
                si.wShowWindow = 0;
                si.dwFlags = 0x00000001;
            }
            Console.WriteLine("[*] Showing process : {0}", show);
            var luid = new LUID();

            // 0x00000002 == LOGON_NETCREDENTIALS_ONLY
            if (!Interop.CreateProcessWithLogonW(Helpers.RandomString(8), Helpers.RandomString(8), Helpers.RandomString(8), 0x00000002, commandLine, String.Empty, 0, 0, null, ref si, out pi))
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] CreateProcessWithLogonW error: {0}", lastError);
                return new LUID();
            }

            Console.WriteLine("[+] Process         : '{0}' successfully created with LOGON_TYPE = 9", commandLine);
            Console.WriteLine("[+] ProcessID       : {0}", pi.dwProcessId);

            var hToken = IntPtr.Zero;
            // TOKEN_QUERY == 0x0008
            var success = Interop.OpenProcessToken(pi.hProcess, 0x0008, out hToken);
            if (!success)
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] OpenProcessToken error: {0}", lastError);
                return new LUID();
            }

            var TokenInfLength = 0;
            bool Result;

            // first call gets lenght of TokenInformation to get proper struct size
            Result = Interop.GetTokenInformation(hToken, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);

            // second call actually gets the information
            Result = Interop.GetTokenInformation(hToken, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, TokenInformation, TokenInfLength, out TokenInfLength);

            if (Result)
            {
                var TokenStats = (Interop.TOKEN_STATISTICS)Marshal.PtrToStructure(TokenInformation, typeof(Interop.TOKEN_STATISTICS));
                luid = new LUID(TokenStats.AuthenticationId);
                Console.WriteLine("[+] LUID            : {0}", luid);
            }
            else
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] GetTokenInformation error: {0}", lastError);
                Marshal.FreeHGlobal(TokenInformation);
                Interop.CloseHandle(hToken);
                return new LUID();
            }

            Marshal.FreeHGlobal(TokenInformation);
            Interop.CloseHandle(hToken);

            return luid;
        }

        #endregion


        #region File Helpers

        static public string GetBaseFromFilename(string filename)
        {
            return SplitBaseAndExtension(filename)[0];
        }

        static public string GetExtensionFromFilename(string filename)
        {
            return SplitBaseAndExtension(filename)[1];
        }

        // Splits filename by into a basename and extension 
        // Returns an array representing [basename, extension]
        static public string[] SplitBaseAndExtension(string filename)
        {
            string[] result = { filename, "" };
            string[] splitName = filename.Split('.');

            if (splitName.Length > 1)
            {
                result[1] = $".{splitName.Last()}";
                result[0] = filename.Substring(0, filename.Length - result[1].Length);
            }

            return result;
        }

        static public string MakeValidFileName(string filePath)
        {
            // Can't use IO.Path.GetFileName and IO.Path.GetDirectoryName because they get confused by illegal file name characters (the whole reason we are here)
            string fileName = filePath;
            string directoryPath = string.Empty;
            int lastSeparatorPosition = filePath.LastIndexOf(Path.DirectorySeparatorChar);
            if ((lastSeparatorPosition > -1) && (filePath.Length > lastSeparatorPosition))
            {
                fileName = filePath.Substring(lastSeparatorPosition + 1);
                directoryPath = filePath.Substring(0, lastSeparatorPosition + 1);
            }

            // Great method from http://forcewake.me/today-i-learned-sanitize-file-name-in-csharp/
            string invalidChars = new string(Path.GetInvalidFileNameChars());
            string escapedInvalidChars = Regex.Escape(invalidChars);
            string invalidRegex = string.Format(@"([{0}]*\.+$)|([{0}]+)", escapedInvalidChars);
            return directoryPath + Regex.Replace(fileName, invalidRegex, "_");
        }


        #endregion


        #region Misc Helpers

        public static string EncryptPassword(string domain,string username,string password, Interop.KERB_ETYPE encType)
        {
            string salt = String.Format("{0}{1}", domain.ToUpper(), username);

            // special case for computer account salts
            if (username.EndsWith("$"))
            {
                salt = String.Format("{0}host{1}.{2}", domain.ToUpper(), username.TrimEnd('$').ToLower(), domain.ToLower());
            }

            return Crypto.KerberosPasswordHash(encType, password, salt);
        }

        public static void RandomDelayWithJitter(int delay, int jitter)
        {
            // given delay == ms and jitter = %, sleep for that amount

            var timeToSleep = 0;

            if (delay == 0)
            {
                timeToSleep = 0;
            }
            else if (jitter == 0)
            {
                timeToSleep = delay;
            }
            else
            {
                var rnd = new Random();
                var percent = (int)Math.Floor((double)(jitter * (delay / 100)));
                timeToSleep = delay + rnd.Next(-percent, percent);
            }

            if (timeToSleep != 0)
            {
                Thread.Sleep(timeToSleep);
            }
        }

        static public int SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++)
            {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength)
                {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern))
                    {
                        return i;
                    }
                }
            }
            return 0;
        }

        static public bool WriteBytesToFile(string filename, byte[] data, bool overwrite = false)
        {
            bool result = true;
            string filePath = Path.GetFullPath(filename);

            try
            {
                if (!overwrite)
                {
                    if (File.Exists(filePath))
                    {
                        throw new Exception(String.Format("{0} already exists! Data not written to file.\r\n", filePath));
                    }
                }
                File.WriteAllBytes(filePath, data);
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\nException: {0}", e.Message);
                result = false;
            }

            return result;
        }

        // variables specifying non default AD attribute types
        private static string[] stringArrayAttributeName =
        {
            "serviceprincipalname",
            "memberof"
        };
        private static string[] datetimeAttributes =
        {
            "lastlogon",
            "lastlogoff",
            "pwdlastset",
            "badpasswordtime",
            "lastlogontimestamp",
        };
        private static string[] dateStringAttributes =
        {
            "whenchanged",
            "whencreated"
        };
        private static string[] intAttributes =
        {
            "useraccountcontrol",
            "msds-supportedencryptiontypes"
        };

        static public List<IDictionary<string, Object>> GetADObjects(List<SearchResultEntry> searchResults)
        {
            var ActiveDirectoryObjects = new List<IDictionary<string, Object>>();

            foreach (SearchResultEntry result in searchResults)
            {
                IDictionary<string, Object> ActiveDirectoryObject = new Dictionary<string, Object>();

                foreach (string attribute in result.Attributes.AttributeNames)
                {
                    // for string arrays like serviceprincipalname
                    if (stringArrayAttributeName.Contains(attribute))
                    {
                        ActiveDirectoryObject.Add(attribute, result.Attributes[attribute].GetValues(typeof(string)));
                    }
                    // datetime attributes
                    else if (datetimeAttributes.Contains(attribute))
                    {
                        if (Int64.Parse((string)result.Attributes[attribute].GetValues(typeof(string))[0]) != 0)
                        {
                            ActiveDirectoryObject.Add(attribute, DateTime.FromFileTimeUtc(Int64.Parse((string)result.Attributes[attribute].GetValues(typeof(string))[0])));
                        }
                        else
                        {
                            ActiveDirectoryObject.Add(attribute, DateTime.MinValue);
                        }
                    }
                    // deal with objectsid
                    else if (attribute.Equals("objectsid"))
                    {
                        ActiveDirectoryObject.Add(attribute, new SecurityIdentifier((byte[])result.Attributes[attribute].GetValues(typeof(byte[]))[0], 0).Value);
                    }
                    // deal with ints
                    else if (intAttributes.Contains(attribute))
                    {
                        ActiveDirectoryObject.Add(attribute, Int32.Parse((string)result.Attributes[attribute].GetValues(typeof(string))[0]));
                    }
                    // default action convert to string
                    else
                    {
                        ActiveDirectoryObject.Add(attribute, result.Attributes[attribute].GetValues(typeof(string))[0]);
                    }
                }

                ActiveDirectoryObjects.Add(ActiveDirectoryObject);
            }

            return ActiveDirectoryObjects;
        }

        static public List<IDictionary<string, Object>> GetADObjects(SearchResultCollection searchResults)
        {
            var ActiveDirectoryObjects = new List<IDictionary<string, Object>>();

            foreach (SearchResult result in searchResults)
            {
                IDictionary<string, Object> ActiveDirectoryObject = new Dictionary<string, Object>();

                foreach (string attribute in result.Properties.PropertyNames)
                {
                    // for string arrays like serviceprincipalname
                    if (stringArrayAttributeName.Contains(attribute))
                    {
                        List<string> values = new List<string>();
                        foreach (var value in result.Properties[attribute])
                        {
                            values.Add(value.ToString());
                        }
                        ActiveDirectoryObject.Add(attribute, values.ToArray());
                    }
                    // datetime attributes
                    else if (datetimeAttributes.Contains(attribute))
                    {
                        if (Int64.Parse(result.Properties[attribute][0].ToString()) != 0)
                        {
                            ActiveDirectoryObject.Add(attribute, DateTime.FromFileTimeUtc((long)result.Properties[attribute][0]));
                        }
                        else
                        {
                            ActiveDirectoryObject.Add(attribute, DateTime.MinValue);
                        }
                    }
                    // deal with objectsid
                    else if (attribute.Equals("objectsid"))
                    {
                        ActiveDirectoryObject.Add(attribute, new SecurityIdentifier((byte[])result.Properties[attribute][0], 0).Value);
                    }
                    // deal with ints
                    else if (intAttributes.Contains(attribute))
                    {
                        ActiveDirectoryObject.Add(attribute, result.Properties[attribute][0]);
                    }
                    // default action convert to string
                    else
                    {
                        ActiveDirectoryObject.Add(attribute, result.Properties[attribute][0].ToString());
                    }
                }

                ActiveDirectoryObjects.Add(ActiveDirectoryObject);
            }

            return ActiveDirectoryObjects;
        }

        #endregion
    }
}