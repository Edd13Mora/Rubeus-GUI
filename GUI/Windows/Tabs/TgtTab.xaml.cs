using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace RubeusGui.Windows.Tabs
{
    /// <summary>
    /// Interaction logic for TgtTab.xaml
    /// </summary>
    public partial class TgtTab : RubeusTab
    {

        public TgtTab()
        {
            InitializeComponent();
        }

        public override bool ValidateSettings()
        {
            if (string.IsNullOrEmpty(TxtUsername.Text))
            {
                MessageBox.Show("Please specify a username to get the TGT for", "No User Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (TxtUsername.Text.Contains(@"\"))
            {
                MessageBox.Show("Username should not include domain", "Invalid Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (string.IsNullOrEmpty(TxtPassword.Text))
            {
                MessageBox.Show("Please specify the user's password or password hash", "No Password Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if ((bool)ChkOpsec.IsChecked && !(bool)RdoPwdAes256.IsChecked && !(bool)RdoEncyptWithAes256.IsChecked)
            {
                if (MessageBox.Show("OpSec mode should ideally use AES 256 encryption to look as legitimate as possible. Are you sure you want to continue using the selected encryption type?", "Not So OpSec",
                    MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                {
                    return false;
                }
            }
            if ((bool)ChkOutputFile.IsChecked && string.IsNullOrEmpty(TxtOutputFilePath.Text))
            {
                MessageBox.Show("Please specify a file path to save the TGT to, or uncheck the option to output to file", "No File Path Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if (string.IsNullOrEmpty(this.Domain) && (bool)RdoPwdPlaintext.IsChecked && ((bool)RdoEncyptWithAes128.IsChecked || (bool)RdoEncyptWithAes256.IsChecked))
            {
                MessageBox.Show("When using AES encryption you must specify a domain, as this is used as part of the hash salt", "No Domain Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            return true;
        }

        protected override Dictionary<string, string> GetRubeusArgs()
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            args.Add("/user", TxtUsername.Text);
            if ((bool)RdoPwdPlaintext.IsChecked)
            {
                args.Add("/password", TxtPassword.Text);
                if ((bool)RdoEncyptWithRc4.IsChecked) { args.Add("/enctype", "RC4"); }
                if ((bool)RdoEncyptWithDes.IsChecked) { args.Add("/enctype", "DES"); }
                if ((bool)RdoEncyptWithAes128.IsChecked) { args.Add("/enctype", "AES128"); }
                if ((bool)RdoEncyptWithAes256.IsChecked) { args.Add("/enctype", "AES256"); }
            }
            else
            {
                if ((bool)RdoPwdRc4.IsChecked) { args.Add("/rc4", TxtPassword.Text); }
                if ((bool)RdoPwdDes.IsChecked) { args.Add("/des", TxtPassword.Text); }
                if ((bool)RdoPwdAes128.IsChecked) { args.Add("/aes128", TxtPassword.Text); }
                if ((bool)RdoPwdAes256.IsChecked) { args.Add("/aes256", TxtPassword.Text); }
            }
            if ((bool)ChkOpsec.IsChecked)
            {
                args.Add("/opsec", string.Empty);
                args.Add("/force", string.Empty);
            }
            if ((bool)ChkOutputFile.IsChecked) { args.Add("/outfile", TxtOutputFilePath.Text); }
            if ((bool)ChkPtt.IsChecked) { args.Add("/ptt", string.Empty); }
            return args;
        }

        protected override Rubeus.Commands.ICommand GetRubeusCommand()
        {
            return new Rubeus.Commands.Asktgt();
        }

        private void LnkHideDescription_Click(object sender, RoutedEventArgs e)
        {
            LblDescription.Visibility = _descriptionHidden ? Visibility.Visible : Visibility.Collapsed;
            _descriptionHidden = !_descriptionHidden;
            LnkHideDescription.Inlines.Clear();
            LnkHideDescription.Inlines.Add(_descriptionHidden ? "Show description" : "Hide description");
        }

        private void BtnOutputFileBrowse_Click(object sender, RoutedEventArgs e)
        {
            Microsoft.Win32.SaveFileDialog sfd = new Microsoft.Win32.SaveFileDialog();
            sfd.Filter = "KIRBI Files (*.kirbi)|*.kirbi|All files (*.*)|*.*";
            sfd.FileName = "TGT.kirbi";
            if ((bool)sfd.ShowDialog())
            {
                TxtOutputFilePath.Text = sfd.FileName;
            }
        }

        private void RdoPwdPlaintext_Checked(object sender, RoutedEventArgs e)
        {
            if (this.IsLoaded)
            {
                TxtPassword.Visibility = Visibility.Visible;
                RowEncryption.Height = new GridLength(31);
                PnlEncryption.Visibility = Visibility.Visible;
            }
        }

        private void RdoPwdPlaintext_Unchecked(object sender, RoutedEventArgs e)
        {
            if (this.IsLoaded)
            {
                TxtPassword.Visibility = Visibility.Collapsed;
                RowEncryption.Height = new GridLength(0);
                PnlEncryption.Visibility = Visibility.Collapsed;
            }
        }
    }
}
