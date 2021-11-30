using Rubeus.Domain;
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

        private string _lastUsername = string.Empty;
        private Rubeus.KRB_CRED _lastTgt = null;

        public TgtTab()
        {
            InitializeComponent();
            CboInputEncryption.ItemsSource = new List<EncryptionDisplayItem>() {new EncryptionDisplayItem(EncryptionType.Plaintext),
                                                                                new EncryptionDisplayItem(EncryptionType.RC4,"RC4 (NTLM)"),
                                                                                new EncryptionDisplayItem(EncryptionType.DES),
                                                                                new EncryptionDisplayItem(EncryptionType.AES128),
                                                                                new EncryptionDisplayItem(EncryptionType.AES256)};
            CboRequiresEncryption.ItemsSource = new List<EncryptionDisplayItem>() {new EncryptionDisplayItem(EncryptionType.RC4),
                                                                                   new EncryptionDisplayItem(EncryptionType.DES),
                                                                                   new EncryptionDisplayItem(EncryptionType.AES128),
                                                                                   new EncryptionDisplayItem(EncryptionType.AES256)};
            CboInputEncryption.SelectedIndex = 1;
            CboRequiresEncryption.SelectedIndex = 0;
        }

        private void LnkHideDescription_Click(object sender, RoutedEventArgs e)
        {
            ToggleDescriptionVisibility(LblDescription, LnkHideDescription);
        }

        private void BtnExecute_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                DomainSettings domainSettings = null;
                try
                {
                    domainSettings = OwnerWindow.GetDomainSettings();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message, "Invalid Domain Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(TxtUsername.Text))
                {
                    MessageBox.Show("Please specify a username to get the TGT for", "No User Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (TxtUsername.Text.IndexOf('\\') > 0)
                {
                    string usernameDomain = TxtUsername.Text.Split('\\')[0];
                    if (string.IsNullOrEmpty(domainSettings.DomainName))
                    {
                        domainSettings.DomainName = usernameDomain;
                    }
                    else if (string.Compare(usernameDomain, domainSettings.DomainName, true) != 0)
                    {
                        MessageBox.Show("Username includes domain that is different to the global domain name setting. Please remove the domain from one of these locations or make sure they are both the same", "Invalid Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }
                if (string.IsNullOrEmpty(TxtPassword.Text))
                {
                    MessageBox.Show("Please specify the user's password or password hash", "No Password Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if ((bool)ChkOpsec.IsChecked && ((EncryptionDisplayItem)CboInputEncryption.SelectedItem).Encryption != EncryptionType.AES256 && ((EncryptionDisplayItem)CboRequiresEncryption.SelectedItem).Encryption != EncryptionType.AES256)
                {
                    if (MessageBox.Show("OpSec mode should use AES 256 encryption to look as legitimate as possible. Are you sure you want to continue using the selected encryption type?", "Not So OpSec",
                        MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                    {
                        return;
                    }
                }

                // If no domain was specified and user is asking us to encrypt plaintext password with either of the AES options then tell them we need the domain name for the salt
                if (string.IsNullOrEmpty(domainSettings.DomainName) &&
                                        ((EncryptionDisplayItem)CboInputEncryption.SelectedItem).Encryption == EncryptionType.Plaintext &&
                                        (((EncryptionDisplayItem)CboRequiresEncryption.SelectedItem).Encryption == EncryptionType.AES128 ||
                                        ((EncryptionDisplayItem)CboRequiresEncryption.SelectedItem).Encryption == EncryptionType.AES256))
                {
                    MessageBox.Show("When using AES encryption you must specify a domain, as this is used as part of the hash salt", "No Domain Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                string hash;
                Rubeus.Interop.KERB_ETYPE etype;
                if (((EncryptionDisplayItem)CboInputEncryption.SelectedItem).Encryption == EncryptionType.Plaintext)
                {
                    etype = ((EncryptionDisplayItem)CboRequiresEncryption.SelectedItem).NativeEncryption;
                    try
                    {
                        hash = Rubeus.Helpers.EncryptPassword(domainSettings.DomainName, TxtUsername.Text, TxtPassword.Text, etype);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error encrypting plaintext password with " + etype.ToString() + " : " + ex.Message, "Error Encrypting Password", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }
                }
                else
                {
                    etype = ((EncryptionDisplayItem)CboInputEncryption.SelectedItem).NativeEncryption;
                    hash = TxtPassword.Text;
                }

                LblExecuteBtn.Text = "Running...";
                ImgExecuteBtn.Source = new BitmapImage(UiHelpers.HourglassIconPath);
                BtnExecute.IsEnabled = false;
                ProgBar.Visibility = Visibility.Visible;
                this.IsEnabled = false;
                TxtTgt.Clear();
                _lastUsername = String.Empty;
                _lastTgt = null;
                string username = TxtUsername.Text;
                bool ptt = (bool)ChkPtt.IsChecked;
                bool opsec = (bool)ChkOpsec.IsChecked;

                System.Threading.Thread bgThread = new System.Threading.Thread(() => RunTgtRequest(domainSettings, username, hash, etype, ptt, opsec));
                bgThread.IsBackground = true;
                bgThread.Start();
            }
            catch (Exception ex)
            {
                ExecuteFinished(null, "Error preparing to run TGT request: " + ex.Message);
            }
        }

        // Run on background thread
        private void RunTgtRequest(DomainSettings domain, string username, string passwordHash, Rubeus.Interop.KERB_ETYPE etype, bool ptt, bool opSec)
        {
            Rubeus.KRB_CRED tgt = null;
            string errorMessage = string.Empty;
            try
            {
                tgt = Rubeus.Ask.TGT(username, domain.DomainName, passwordHash, etype, String.Empty, ptt, domainController: domain.DomainController, opsec: opSec);
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
            }
            // Switch back to UI thread and call ExecuteFinished method, passing it the results to be displayed
            this.Dispatcher.Invoke(new Action<Rubeus.KRB_CRED, string>(ExecuteFinished), tgt, errorMessage);
        }

        private void ExecuteFinished(Rubeus.KRB_CRED tgt, string errorMessage)
        {
            // This check avoids null references if program was closed and thread has not terminated (shouldn't happen as we set Thread.IsBackground to true, but better safe than sorry)
            if (this.OwnerWindow.IsLoaded)
            {
                this.IsEnabled = true;
                PnlResults.IsEnabled = true;
                _lastUsername = TxtUsername.Text;
                _lastTgt = tgt;
                if (tgt != null && tgt.RawBytes != null)
                {
                    TxtTgt.Text = Convert.ToBase64String(tgt.RawBytes);
                }
                else
                {
                    PnlResults.IsEnabled = false;
                }
                LblExecuteBtn.Text = "Run";
                ImgExecuteBtn.Source = new BitmapImage(UiHelpers.PlayIconPath);
                BtnExecute.IsEnabled = true;
                ProgBar.Visibility = Visibility.Collapsed;
                if (!string.IsNullOrEmpty(errorMessage))
                {
                    MessageBox.Show(errorMessage, "Error Executing TGT Request", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BtnExportKirbi_Click(object sender, RoutedEventArgs e)
        {
            if (_lastTgt == null)
            {
                MessageBox.Show("No TGT to export", "No TGT", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else
            {
                Microsoft.Win32.SaveFileDialog sfd = new Microsoft.Win32.SaveFileDialog();
                sfd.Filter = "KIRBI Files (*.kirbi)|*.kirbi|All files (*.*)|*.*";
                sfd.FileName = "TGT_" + _lastUsername + ".kirbi";
                if ((bool)sfd.ShowDialog())
                {
                    try
                    {
                        System.IO.File.WriteAllBytes(sfd.FileName, _lastTgt.RawBytes);
                        MessageBox.Show("TGT exported to file successfully", "Exported Successfully", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error saving file: " + ex.Message, "Error Saving File", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private void BtnExportBase64_Click(object sender, RoutedEventArgs e)
        {
            if (_lastTgt == null)
            {
                MessageBox.Show("No TGT to export", "No TGT", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else
            {
                Microsoft.Win32.SaveFileDialog sfd = new Microsoft.Win32.SaveFileDialog();
                sfd.Filter = "Text Files (*.txt)|*.txt|All files (*.*)|*.*";
                sfd.FileName = "TGT_Base64_" + _lastUsername + ".txt";
                if ((bool)sfd.ShowDialog())
                {
                    try
                    {
                        System.IO.File.WriteAllText(sfd.FileName, TxtTgt.Text);
                        MessageBox.Show("TGT exported to file successfully", "Exported Successfully", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error saving file: " + ex.Message, "Error Saving File", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private void CboInputEncryption_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CboInputEncryption.SelectedItem != null && ((EncryptionDisplayItem)CboInputEncryption.SelectedItem).Encryption == EncryptionType.Plaintext)
            {
                RowRequiredEncryption.Height = new GridLength(31);
                CboRequiresEncryption.IsEnabled = true;
                TxtPassword.ToolTip = "The user's plaintext password";
            }
            else
            {
                RowRequiredEncryption.Height = new GridLength(0);
                CboRequiresEncryption.IsEnabled = false;
                TxtPassword.ToolTip = "Encrypted hash of the user's password";
            }
        }

        private void BtnCopyTgt_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(TxtTgt.Text);
        }
    }
}
