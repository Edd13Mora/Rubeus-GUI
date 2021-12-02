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
    /// <summary>
    /// Interaction logic for PreAuthTab.xaml
    /// </summary>
    public partial class PreAuthTab : RubeusTab
    {
                
        public PreAuthTab()
        {
            InitializeComponent();
        }

        private void LnkHideDescription_Click(object sender, RoutedEventArgs e)
        {
            ToggleDescriptionVisibility(LblDescription,LnkHideDescription);
        }

        private void RdoSpecificOu_Checked(object sender, RoutedEventArgs e)
        {
            // We could do this in XAML but then setting focus doesn't work
            TxtOu.IsEnabled = true;
            TxtOu.Focus();
        }

        private void RdoSpecificOu_Unchecked(object sender, RoutedEventArgs e)
        {
            TxtOu.IsEnabled = false;
        }

        private void RdoSpecificUser_Checked(object sender, RoutedEventArgs e)
        {
            // We could do this in XAML but then setting focus doesn't work
            TxtUsername.IsEnabled = true;
            TxtUsername.Focus();
        }

        private void RdoSpecificUser_Unchecked(object sender, RoutedEventArgs e)
        {
            TxtUsername.IsEnabled = false;
        }

        private void BtnExecute_Click(object sender, RoutedEventArgs e)
        {
            DomainSettings domainSettings = null;
            string username = string.Empty;
            string ou = string.Empty;
            Rubeus.Roast.HashFormat hashFormat = Rubeus.Roast.HashFormat.hashcat;

            try
            {
                domainSettings = OwnerWindow.GetDomainSettings();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Invalid Domain Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if ((bool)RdoSpecificUser.IsChecked)
            {
                if (string.IsNullOrEmpty(TxtUsername.Text))
                {
                    MessageBox.Show("Please specify a username or select another target option", "No Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                username = TxtUsername.Text;
            }
            else if ((bool)RdoSpecificOu.IsChecked)
            {
                if (string.IsNullOrEmpty(TxtOu.Text))
                {
                    MessageBox.Show("Please specify an OU distinguished name or select another target option", "No OU Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                username = TxtUsername.Text;
            }
            if ((bool)RdoJohn.IsChecked)
            {
                hashFormat = Rubeus.Roast.HashFormat.john;
            }

            LblExecuteBtn.Text = "Running...";
            ImgExecuteBtn.Source = new BitmapImage(UiHelpers.HourglassIconPath);
            BtnExecute.IsEnabled = false;
            ProgBar.Visibility = Visibility.Visible;
            this.IsEnabled = false;

            System.Threading.Thread bgThread = new System.Threading.Thread(() => RunAsRepRoast(domainSettings, username, ou, hashFormat));
            bgThread.IsBackground = true;
            bgThread.Start();
        }

        // Run on background thread
        private void RunAsRepRoast(DomainSettings domain, string username, string ou, Rubeus.Roast.HashFormat hashFormat)
        {
            List<AsRepRoastResult> results = new List<AsRepRoastResult>();
            string errorMessage = string.Empty;
            try
            {
                results = Rubeus.Roast.ASRepRoast(domain.DomainName, username, ou, domain.DomainController, hashFormat, domain.Credentials, ldaps: domain.Ldaps);
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
            }
            // Switch back to UI thread and call ExecuteFinished method, passing it the results to be displayed
            this.Dispatcher.Invoke(new Action<List<AsRepRoastResult>, string>(ExecuteFinished), results, errorMessage);
        }

        private void ExecuteFinished(List<AsRepRoastResult> results, string errorMessage)
        {
            // This check avoids null references if program was closed and thread has not terminated (shouldn't happen as we set Thread.IsBackground to true, but better safe than sorry)
            if (this.OwnerWindow.IsLoaded)
            {
                this.IsEnabled = true;
                PnlExport.IsEnabled = true; 
                LblResults.IsEnabled = true;
                LsvResults.IsEnabled = true;
                LsvResults.ItemsSource = results;
                LblResults.Text = "Results (" + results.Count + " users found):";
                LblExecuteBtn.Text = "Run";
                ImgExecuteBtn.Source = new BitmapImage(UiHelpers.PlayIconPath);
                BtnExecute.IsEnabled = true;
                ProgBar.Visibility = Visibility.Collapsed;
                if (!string.IsNullOrEmpty(errorMessage))
                {
                    MessageBox.Show(errorMessage, "Error Executing AS-REP Roast", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void CtxResultsListView_Opened(object sender, RoutedEventArgs e)
        {
            CtxItemCopyUsername.IsEnabled = LsvResults.SelectedItem != null;
            CtxItemCopyHash.IsEnabled = LsvResults.SelectedItem != null;
            CtxItemCopyDn.IsEnabled = LsvResults.SelectedItem != null;
        }

        private void CtxItemCopyHash_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(((AsRepRoastResult)LsvResults.SelectedItem)?.HashData?.Hash);
        }

        private void CtxItemCopyUsername_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(((AsRepRoastResult)LsvResults.SelectedItem)?.Username);
        }

        private void CtxItemCopyDn_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.CopyToClipboard(((AsRepRoastResult)LsvResults.SelectedItem)?.DistinguishedName);
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
                    sfd.FileName = "AsRepRoastResults.csv";
                    if ((bool)sfd.ShowDialog())
                    {
                        using (StreamWriter writer = new StreamWriter(sfd.FileName, false, new UTF8Encoding(false)))
                        {
                            writer.WriteLine("\"Username\",\"Hash\",\"Distinguished Name\"");
                            foreach (AsRepRoastResult result in LsvResults.ItemsSource)
                            {
                                string username = UiHelpers.MakeCsvSafe(result.Username);
                                string hash = result.HashData?.Hash; hash = UiHelpers.MakeCsvSafe(hash);
                                string dn = UiHelpers.MakeCsvSafe(result.DistinguishedName);
                                writer.WriteLine($"{username},{hash},{dn}");
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
                            foreach (AsRepRoastResult result in LsvResults.ItemsSource)
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
