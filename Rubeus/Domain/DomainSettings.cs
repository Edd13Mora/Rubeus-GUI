using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Rubeus.Domain
{
    public class DomainSettings
    {

        public string DomainName { get; set; }
        public string DomainController { get; set; }
        public bool Ldaps { get; set; }
        public System.Net.NetworkCredential Credentials { get; set; }

    }
}
