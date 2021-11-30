using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus.Domain
{
    public class KerberoastSettings
    {
        public DomainSettings Domain { get; set; } = new DomainSettings();
        public string Username { get; set; } = string.Empty;
        public List<string> Spns { get; set; } = new List<string>();
        public bool NoTgsRequests { get; set; }
        public string LdapFilter { get; set; } = string.Empty;
        public bool Rc4Opsec { get; set; }
        public bool UseTgtDelegationTrick { get; set; }
        public KRB_CRED Tgt { get; set; }
        public bool Enterprise { get; set; }
        public bool AutoEnterprise { get; set; }
        public int ResultsLimit { get; set; }
        public int Delay { get; set; }
        public int Jitter { get; set; }
        public string OuPath { get; set; } = string.Empty;
        public string OutputFilePath { get; set; } = string.Empty;
        public bool SimpleOutput { get; set; }
        public ETypeMode EncryptionMode { get; set; } = ETypeMode.Rc4;
        public string PasswordSetAfter { get; set; } = string.Empty;
        public string PasswordSetBefore { get; set; } = string.Empty;

        public enum ETypeMode
        {
            Rc4,
            Rc4Opsec,
            Aes
        }

    }

    

}
