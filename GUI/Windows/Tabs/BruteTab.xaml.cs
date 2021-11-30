using Rubeus;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Collections.ObjectModel;
using Rubeus.Domain;

namespace RubeusGui.Windows.Tabs
{
    /// <summary>
    /// Interaction logic for BruteTab.xaml
    /// </summary>
    public partial class BruteTab : RubeusTab
    {
        private int _validCredsCount;
        private int _validUsernamesCount;
        private int _invalidUsernamesCount;
        private ObservableCollection<BruteResult> _results = new ObservableCollection<BruteResult>();
        private GuiBruteForcer _brute = new GuiBruteForcer();


        public BruteTab()
        {
            InitializeComponent();
            _brute.ResultAdded += Brute_ResultAdded;
            LsvResults.ItemsSource = _results;
            CollectionView view = (CollectionView)CollectionViewSource.GetDefaultView(LsvResults.ItemsSource);
            view.Filter = FilterResults;
        }

        private void BtnExecute_Click(object sender, RoutedEventArgs e)
        {
            DomainSettings domain;
            try
            {
                domain = OwnerWindow.GetDomainSettings();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Invalid Domain Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            try
            {
                List<string> usernames = new List<string>();
                List<string> passwords = new List<string>();
                bool getUsersFromDomain = false;
                bool useParallel = (bool)ChkParallel.IsChecked;

                // Get username wordlist settings

                if ((bool)RdoSingleUsername.IsChecked)
                {
                    if (string.IsNullOrEmpty(TxtSingleUsername.Text))
                    {
                        MessageBox.Show("Please enter a username or select another method of submitting usernames", "Invalid Username Selection", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    usernames.Add(TxtSingleUsername.Text);
                }
                else if ((bool)RdoUsernamesFromFile.IsChecked)
                {
                    try
                    {
                        usernames.AddRange(System.IO.File.ReadAllLines(TxtUsernameList.Text));
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error loading username list from file: " + ex.Message, "Error Reading File", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }
                }
                else if ((bool)RdoUsernamesFromDomain.IsChecked)
                {
                    getUsersFromDomain = true;
                }

                // Get password wordlist settings

                if ((bool)RdoNoPasswords.IsChecked)
                {
                    // User just wants to validate usernames but we need SOMETHING to use as a password so this will have to do
                    passwords.Add("F");
                }
                else if ((bool)RdoSinglePassword.IsChecked)
                {
                    if (string.IsNullOrEmpty(TxtSinglePassword.Text))
                    {
                        MessageBox.Show("Please enter a passwrd or select another method of submitting passwords", "Invalid Password Selection", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    passwords.Add(TxtSinglePassword.Text);
                }
                else if ((bool)RdoPasswordsFromFile.IsChecked)
                {
                    try
                    {
                        passwords.AddRange(System.IO.File.ReadAllLines(TxtPasswordList.Text));
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Error loading password list from file: " + ex.Message, "Error Reading File", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }
                }

                _validUsernamesCount = 0;
                _validCredsCount = 0;
                _invalidUsernamesCount = 0;

                _results.Clear();
                BtnCancel.IsEnabled = true;
                LblExecuteBtn.Text = "Running...";
                ImgExecuteBtn.Source = new BitmapImage(UiHelpers.HourglassIconPath);
                BtnExecute.IsEnabled = false;
                ProgBar.Visibility = Visibility.Visible;
                BtnCancel.Visibility = Visibility.Visible;

                System.Threading.Thread bgThread = new System.Threading.Thread(() => RunBrute(domain, getUsersFromDomain, useParallel, usernames, passwords));
                bgThread.IsBackground = true;
                bgThread.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error preparing to run brute force: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }

        // Runs on background thread
        private void RunBrute(DomainSettings domain, bool getUsersFromDomain, bool useParallel, List<string> usernames, List<string> passwords)
        {
            string errorMessage = string.Empty;
            bool cancelled = false;
            string dc = domain.DomainController;
            try
            {
                try
                {
                    if (string.IsNullOrEmpty(dc))
                    {
                        dc = Networking.GetDCName(domain.DomainName);
                    }
                }
                catch (Exception ex)
                {
                    errorMessage = "Error trying to locate domain controller: " + ex.Message;
                    // Try-Finally block will handle calling BruteFinished for us instead of the thread just exiting
                    return;
                }

                if (getUsersFromDomain)
                {
                    usernames = new List<string>();
                    try
                    {
                        List<IDictionary<string, object>> users = Networking.GetLdapQuery(domain.Credentials, String.Empty, dc, domain.DomainName, "(sAMAccountType=805306368)", domain.Ldaps);
                        foreach (var user in users)
                        {
                            if (user.ContainsKey("samaccountname"))
                            {
                                usernames.Add((string)user["samaccountname"]);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        errorMessage = "Error getting list of usernames from domain: " + ex.Message;
                        // Try-Finally block will handle calling BruteFinished for us instead of the thread just exiting
                        return;
                    }
                }

                // If we have at least one username then run the brute force operation
                if (usernames?.Count > 0)
                {
                    try
                    {
                        cancelled = !_brute.Run(domain.DomainName, dc, usernames, passwords, useParallel);
                    }
                    catch (Exception ex)
                    {
                        errorMessage = ex.Message;
                    }
                }
            }
            finally
            {
                this.Dispatcher.Invoke(new Action<string, bool>(BruteFinished), errorMessage, cancelled);
            }
        }

        // Called each time a new result should be added to the results listview.
        // NOTE: Called from background thread or if user chose to use parallel processing then this could be called from multiple threads at once. 
        // The fact we need to use Dispatcher.Invoke() to execute the method on the UI thread should also mean there's no locking required to make the
        // rest of this thread safe even if called simulatanously by multiple threads
        private void Brute_ResultAdded(object sender, BruteResult result)
        {
            // Make sure we're back on the UI thread before we add an item to the collection that's bound to the listview
            if (Dispatcher.CheckAccess())
            {
                // This check avoids unhandled null reference exception if the program was closed and we end up here because the worker thread has
                // not terminated (shouldn't happen as we set Thread.IsBackground to true, but better safe than sorry)
                if (this.OwnerWindow.IsLoaded)
                {
                    // Because this is an ObservableCollection it will update the UI with the new item
                    _results.Add(result);
                    // Increment counters that are just used to track stats to tell user at the end
                    switch (result.Status)
                    {
                        case BruteResult.CredentialStatus.UsernameAndPwdValid:
                            _validCredsCount++;
                            break;
                        case BruteResult.CredentialStatus.UsernameAndPwdValidButPwdExpired:
                            _validCredsCount++;
                            break;
                        case BruteResult.CredentialStatus.UsernameValid:
                        case BruteResult.CredentialStatus.UsernameValidButError:
                        case BruteResult.CredentialStatus.UsernameValidButDisabled:
                            _validUsernamesCount++;
                            break;
                        case BruteResult.CredentialStatus.UsernameInvalid:
                            _invalidUsernamesCount++;
                            break;
                        default:
                            break;
                    }
                }
            }
            else // If we're not on the UI thread then invoke this method again there
            {
                this.Dispatcher.Invoke(new Action<Object, BruteResult>(Brute_ResultAdded), sender, result);
            }
        }

        private void BruteFinished(string errorMessage, bool cancelled)
        {
            // This check avoids unhandled null reference exception if the program was closed and we end up here because the worker thread has
            // not terminated (shouldn't happen as we set Thread.IsBackground to true, but better safe than sorry)
            if (this.OwnerWindow.IsLoaded)
            {
                LsvResults.IsEnabled = true;
                PnlFilters.IsEnabled = true;
                LblExecuteBtn.Text = "Run";
                BtnExecute.IsEnabled = true;
                ImgExecuteBtn.Source = new BitmapImage(UiHelpers.PlayIconPath);
                ProgBar.Visibility = Visibility.Collapsed;
                BtnCancel.Visibility = Visibility.Collapsed;
                if (!string.IsNullOrEmpty(errorMessage))
                {
                    MessageBox.Show(errorMessage, "Error Executing Brute Force", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                else
                {
                    string msgStart;
                    string msgTitle;
                    if (cancelled)
                    {
                        msgTitle = "Operation Cancelled";
                        msgStart = "Before the brute force was cancelled it found: \n\n";
                    }
                    else
                    {
                        msgTitle = "Brute Force Finished";
                        msgStart = "Brute force finished and found: \n\n";
                    }
                    MessageBox.Show(msgStart
                        + _validCredsCount + " valid credentials\n"
                        + _validUsernamesCount + " valid usernames without valid passwords\n"
                        + _invalidUsernamesCount + " invalid usernames", msgTitle, MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        // Called every time one of the filter checkboxes are checked/unchecked and each item in the results listview is passed in to see if it matches the current filter
        private bool FilterResults(object item)
        {
            if ((bool)ChkFilterAll.IsChecked)
            {
                return true;
            }

            BruteResult.CredentialStatus status = ((BruteResult)item).Status;
            switch (status)
            {
                case BruteResult.CredentialStatus.Error:
                    return (bool)ChkFilterErrors.IsChecked;
                case BruteResult.CredentialStatus.UsernameAndPwdValid:
                    return (bool)ChkFilterValidCreds.IsChecked || (bool)ChkFilterValidUsernames.IsChecked;
                case BruteResult.CredentialStatus.UsernameAndPwdValidButPwdExpired:
                    return (bool)ChkFilterValidCreds.IsChecked || (bool)ChkFilterValidUsernames.IsChecked;
                case BruteResult.CredentialStatus.UsernameValid:
                    return (bool)ChkFilterValidUsernames.IsChecked;
                case BruteResult.CredentialStatus.UsernameValidButDisabled:
                    return (bool)ChkFilterValidUsernames.IsChecked;
                case BruteResult.CredentialStatus.UsernameValidButError:
                    return ((bool)ChkFilterErrors.IsChecked) || ((bool)ChkFilterValidUsernames.IsChecked && (bool)ChkFilterErrors.IsChecked);
                case BruteResult.CredentialStatus.UsernameInvalid:
                    return (bool)ChkFilterInvalidUsernames.IsChecked;
                default:
                    return false;
            }
        }

        private void LnkHideDescription_Click(object sender, RoutedEventArgs e)
        {
            ToggleDescriptionVisibility(LblDescription, LnkHideDescription);
        }

        private void BtnBrowseUsernameList_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new Microsoft.Win32.OpenFileDialog();
            ofd.Filter = "Text Files (*.txt)|*.txt|All Files|*.*";
            if ((bool)ofd.ShowDialog())
            {
                TxtUsernameList.Text = ofd.FileName;
            }
        }

        private void BtnBrowsePasswordList_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new Microsoft.Win32.OpenFileDialog();
            ofd.Filter = "Text Files (*.txt)|*.txt|All Files|*.*";
            if ((bool)ofd.ShowDialog())
            {
                TxtPasswordList.Text = ofd.FileName;
            }
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            _brute.Cancel();
            BtnCancel.IsEnabled = false;
        }

        private void UpdateFilter(object sender, RoutedEventArgs e)
        {
            // Avoid null references when XAML calls this during initialization
            if (this.IsLoaded)
            {
                ((CollectionView)CollectionViewSource.GetDefaultView(LsvResults.ItemsSource)).Refresh();
            }
        }

        private void ChkFilterAll_Checked(object sender, RoutedEventArgs e)
        {
            // Avoid null references when XAML calls this during initialization
            if (this.IsLoaded)
            {
                PnlSubFilters.IsEnabled = false;
                ChkFilterInvalidUsernames.IsChecked = true;
                ChkFilterErrors.IsChecked = true;
                ChkFilterValidCreds.IsChecked = true;
                ChkFilterValidUsernames.IsChecked = true;
            }
        }

        private void ChkFilterAll_Unchecked(object sender, RoutedEventArgs e)
        {
            PnlSubFilters.IsEnabled = true;
        }

        private void CtxItemCopyUsernameAndPassword_Click(object sender, RoutedEventArgs e)
        {
            BruteResult selectedResult = (BruteResult)LsvResults.SelectedItem;
            if (selectedResult != null)
            {
                UiHelpers.CopyToClipboard(selectedResult.Username + " : " + selectedResult.Password);
            }
        }

        private void CtxItemCopyUsername_Click(object sender, RoutedEventArgs e)
        {
            if (LsvResults.SelectedItem != null)
            {
                UiHelpers.CopyToClipboard(((BruteResult)LsvResults.SelectedItem).Username);
            }
        }

        private void CtxItemCopyPassword_Click(object sender, RoutedEventArgs e)
        {
            if (LsvResults.SelectedItem != null)
            {
                UiHelpers.CopyToClipboard(((BruteResult)LsvResults.SelectedItem).Password);
            }
        }

        private void CtxItemCopyTgt_Click(object sender, RoutedEventArgs e)
        {
            if (LsvResults.SelectedItem != null)
            {
                UiHelpers.CopyToClipboard(((BruteResult)LsvResults.SelectedItem).TgtBase64);
            }
        }

        private void CtxItemDetails_Click(object sender, RoutedEventArgs e)
        {
            if (LsvResults.SelectedItem != null)
            {
                UiHelpers.CopyToClipboard(((BruteResult)LsvResults.SelectedItem).StatusDescription);
            }
        }
    }
}
