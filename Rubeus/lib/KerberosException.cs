using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rubeus
{
    public class KerberosException : RubeusException
    {

        // Important to throw KerberosErrorException instead of general exception in some places because other code relies on catching this exception type specifically

        public Interop.KERBEROS_ERROR ErrorType { get; set; }
        public long ErrorCode { get; set; }
        public DateTime ServerTime { get; set; }
        public string Description { get; set; }
        public List<PA_ETYPE_INFO2> PreAuthInfo { get; set; } = new List<PA_ETYPE_INFO2>();

        public KerberosException(string message)
            : base(message)
        {
        }

        public static KerberosException FromNativeError(KRB_ERROR krbError)
        {
            Interop.KERBEROS_ERROR errorType = (Interop.KERBEROS_ERROR)krbError.error_code;
            long errorCode = krbError.error_code;
            string errorDescription = Helpers.GetDescriptionForKrbErrorCode(errorType);
            string extraInfo = string.Empty;
            if (errorType == Interop.KERBEROS_ERROR.KRB_AP_ERR_SKEW)
            {
                extraInfo = $". The current time on the server is {krbError.stime}";
            }
            KerberosException kerberosException = new KerberosException($"{errorDescription}{extraInfo}. Error code {errorCode} ({errorType}).");
            kerberosException.ErrorType = errorType;
            kerberosException.ErrorCode = errorCode;
            kerberosException.Description = errorDescription;
            kerberosException.ServerTime = krbError.stime;
            if (krbError.e_data != null)
            {
                foreach (PA_DATA paData in krbError.e_data)
                {
                    if (paData.type == Interop.PADATA_TYPE.ETYPE_INFO2)
                    {
                        kerberosException.PreAuthInfo.Add((PA_ETYPE_INFO2)paData.value);
                    }
                }
            }
           
            return kerberosException;
        }
    }

}
