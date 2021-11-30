using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus.Domain
{
    public class KerberoastResult
    {

        public string Username { get; set; } = "<unknown>";
        public string DistinguishedName { get; set; }
        public string ServicePrincipalName { get; set; }
        public Interop.SUPPORTED_ETYPE? SupportedEncryption { get; set; }
        public DateTime? PasswordLastSet { get; set; }
        public TicketHash HashData { get; set; }

        public string SupportedEncryptionString
        {
            get
            {
                if (this.SupportedEncryption.HasValue)
                {
                    return Helpers.GetFriendlyNameForETypeFlags(SupportedEncryption.Value);
                }
                else
                {
                    return string.Empty;
                }

            }
        }



    }
}
