using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RubeusGui
{

    public enum EncryptionType
    {
        Plaintext,
        RC4,
        DES,
        AES128,
        AES256
    }

    public class EncryptionDisplayItem
    {

        public EncryptionDisplayItem(EncryptionType encryption)
        {
            this.Encryption = encryption;
        }

        public EncryptionDisplayItem(EncryptionType encryption, string overrideDisplayName) : this(encryption)
        {
            this.OverrideDisplayName = overrideDisplayName;
        }

        public EncryptionType Encryption { get; set; }
        public string OverrideDisplayName { get; set; }
        public string DisplayName
        {
            get
            {
                if (OverrideDisplayName != null)
                {
                    return OverrideDisplayName;
                }
                switch (Encryption)
                {
                    case EncryptionType.AES128:
                        return "AES 128";
                    case EncryptionType.AES256:
                        return "AES 256";
                    default:
                        return Encryption.ToString();
                }
            }
        }

        public Rubeus.Interop.KERB_ETYPE NativeEncryption
        {
            get
            {
                switch (Encryption)
                {
                    case EncryptionType.RC4:
                        return Rubeus.Interop.KERB_ETYPE.rc4_hmac;
                    case EncryptionType.DES:
                        return Rubeus.Interop.KERB_ETYPE.des_cbc_md5;
                    case EncryptionType.AES128:
                        return Rubeus.Interop.KERB_ETYPE.aes128_cts_hmac_sha1;
                    case EncryptionType.AES256:
                        return Rubeus.Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                    default:
                        throw new ApplicationException("Unexpected encryption type in EncryptionDisplay.Encryption property");
                }
            }
        }


    }
}
