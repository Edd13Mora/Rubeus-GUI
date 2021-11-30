using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;

namespace RubeusGui
{
    public class BruteResult
    {

        // This class should ideally implement INotifyPropertyChanged but because we're only adding results to the ListView after all properties have been set on them (and then
        // they're never changed again), its fine this way
               
        public BruteResult(string username)
        {
            this.Username = username;
        }

        public enum CredentialStatus
        {
            Unknown,
            Error,
            UsernameAndPwdValid,
            UsernameAndPwdValidButPwdExpired,
            UsernameValid,
            UsernameValidButDisabled,
            UsernameValidButError,
            UsernameInvalid
        }

        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public byte[] Tgt { get; set; }
        public CredentialStatus Status { get; set; } = CredentialStatus.Unknown;

        public string StatusDescription
        {
            get
            {
                switch (Status)
                {
                    case CredentialStatus.UsernameAndPwdValid:
                        return "Valid username and password!";
                    case CredentialStatus.UsernameValid:
                        return "Valid username";
                    case CredentialStatus.UsernameValidButDisabled:
                        return "Valid username but account is disabled or locked out";
                    case CredentialStatus.UsernameValidButError:
                        return "Valid username but error encountered: " + ErrorMessage;
                    case CredentialStatus.Error:
                        return "Error encountered whilst validating username: " + ErrorMessage;
                    case CredentialStatus.UsernameInvalid:
                        return "Username not found in domain";
                    case CredentialStatus.UsernameAndPwdValidButPwdExpired:
                        return "Valid username and password but password has expired";
                    default:
                        return "Unknown";
                }
            }
        }

        public string TgtBase64
        {
            get
            {
                if (Tgt == null || Tgt.Length == 0)
                {
                    return string.Empty;
                }
                else
                {
                    return Convert.ToBase64String(Tgt);
                }
            }
        }
        public System.Windows.Media.SolidColorBrush ForegroundColor
        {
            get
            {
                switch (Status)
                {
                    case CredentialStatus.UsernameAndPwdValid:
                        return System.Windows.Media.Brushes.LightGreen;
                    case CredentialStatus.UsernameAndPwdValidButPwdExpired:
                        return System.Windows.Media.Brushes.LightBlue;
                    default:
                        //TODO: See if we can get the default text color instead of hard coding white here
                        return System.Windows.Media.Brushes.White;
                }
            }
        }

        public BitmapImage Icon
        {
            get
            {
                switch (Status)
                {
                    case CredentialStatus.UsernameAndPwdValid:
                        return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/ok_16px.png"));
                    case CredentialStatus.UsernameValid:
                        return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/male_user_16px.png"));
                    case CredentialStatus.UsernameValidButDisabled:
                        return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/lock_blue_16px.png"));
                    case CredentialStatus.UsernameAndPwdValidButPwdExpired:
                        return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/ok_grey_16px.png"));
                    case CredentialStatus.UsernameValidButError:
                    case CredentialStatus.Error:
                        return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/cancel_16px.png"));
                    case CredentialStatus.UsernameInvalid:
                        return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/delete_16px.png"));
                    default:
                        return new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/help_16px.png"));
                }
            }
        }

    }
}
