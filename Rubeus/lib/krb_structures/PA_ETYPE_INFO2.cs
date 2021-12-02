using Asn1;

namespace Rubeus
{

    // ETYPE-INFO2-ENTRY       ::= SEQUENCE
    //      etype      [0]     Int32,
    //      salt       [1]     KerberosString OPTIONAL,
    //      s2kparams  [2]     OCTET STRING OPTIONAL

    public class PA_ETYPE_INFO2
    {

        const int EtypeTag = 0;
        const int SaltTag = 1;
        const int S2kTag = 2;

        public Interop.KERB_ETYPE etype { get; set; }
        public string salt { get; set; }
        public byte[] s2kparams { get; set; }
        
        public PA_ETYPE_INFO2(AsnElt asnBody)
        {
            foreach (AsnElt asnSub in asnBody.Sub[0].Sub)
            {
                switch (asnSub.TagValue)
                {
                    case EtypeTag:
                        this.etype = (Interop.KERB_ETYPE)asnSub.Sub[0].GetInteger();
                        break;
                    case SaltTag:
                        this.salt = asnSub.Sub[0].GetString();
                        break;
                    case S2kTag:
                        this.s2kparams = asnSub.Sub[0].GetOctetString();
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
