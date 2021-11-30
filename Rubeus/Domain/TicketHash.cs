using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus.Domain
{
    public class TicketHash
    {

        public string Hash { get; set; } = String.Empty;
        public Interop.KERB_ETYPE Encryption { get; set; }

        public string EncryptionString
        {
            get
            {
                return Helpers.GetFriendlyNameForEType(Encryption);
            }
        }

        public TicketHash() { }

        public TicketHash(string hash, Interop.KERB_ETYPE etype)
        {
            Hash = hash;
            Encryption = etype;
        }




    }
}
