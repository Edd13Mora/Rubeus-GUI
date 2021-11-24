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
using System.IO;
using RubeusGui.Windows.Tabs;
using System.Text.RegularExpressions;

namespace RubeusGui
{

    public partial class MainWindow : Window
    {

        private bool _outputVisible = false;
        private UserPreferences _userPrefs = new UserPreferences();
        private readonly StringWriter _outputWriter = new StringWriter();


        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Redirect all the Rubeus Console.WriteLine calls to a string that we can add to our output textbox
            Console.SetOut(_outputWriter);
            Console.SetError(_outputWriter);

            // No idea why this one Rubeus option is a field on the Program class when everything else is passed in as arguments to functions
            Rubeus.Program.wrapTickets = false;

            // Load user preferences and last used domain name etc from XML file
            LoadUserPreferences();
        }

        private bool ValidateGlobalSettings()
        {
            if ((bool)ChkAltCreds.IsChecked)
            {
                if (String.IsNullOrWhiteSpace(TxtCredUsername.Text) || String.IsNullOrWhiteSpace(TxtCredPassword.Password))
                {
                    MessageBox.Show("Please enter a username and password or uncheck the option to use alternate credentials", "No Credentials Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }

                if (!UiHelpers.UsernameContainsDomain(TxtCredUsername.Text))
                {
                    MessageBox.Show(@"Username must include domain name and must be in FQDN format (domain.local\username)", "Invalid Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            return true;
        }

        private void MenuItemFileExit_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void LnkRubeus_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchUrl("https://github.com/GhostPack/Rubeus");
        }

        private void ChkAltCreds_Checked(object sender, RoutedEventArgs e)
        {
            PnlCredentials.Visibility = Visibility.Visible;
        }

        private void ChkAltCreds_Unchecked(object sender, RoutedEventArgs e)
        {
            PnlCredentials.Visibility = Visibility.Hidden;
        }

        private void LoadUserPreferences()
        {
            try
            {
                _userPrefs = UserPreferences.GetPreferences();
                TxtDomain.Text = _userPrefs.Domain;
                TxtDomainController.Text = _userPrefs.DomainController;
                if (!String.IsNullOrEmpty(_userPrefs.CredUser))
                {
                    CredentialsWindow credsWindow = new CredentialsWindow();
                    credsWindow.Domain = _userPrefs.Domain;
                    credsWindow.Username = _userPrefs.CredUser;
                    if ((bool)credsWindow.ShowDialog())
                    {
                        ChkAltCreds.IsChecked = true;
                        TxtCredUsername.Text = credsWindow.Username;
                        TxtCredPassword.Password = credsWindow.Password;
                    }
                }
                ChkLdaps.IsChecked = _userPrefs.Ldaps;
                SetTabPreferences();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error loading preferences from local XML file: " + ex.Message, "Error Loading Preference", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void SaveUserPreferences()
        {
            try
            {
                _userPrefs.Domain = TxtDomain.Text;
                _userPrefs.DomainController = TxtDomainController.Text;
                if ((bool)ChkAltCreds.IsChecked)
                {
                    _userPrefs.CredUser = TxtCredUsername.Text;
                }
                _userPrefs.Ldaps = (bool)ChkLdaps.IsChecked;
                UserPreferences.SavePreferences(_userPrefs);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving preferences and recently used settings to XML file: " + ex.Message + "\n You can disable saving recently used settings in Tools -> Options", "Error Saving Preferences", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void BtnExecute_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (ValidateGlobalSettings())
                {
                    if (_userPrefs.SaveMru)
                    {
                        // Save current domain etc to user preferences file for next launch
                        SaveUserPreferences();
                    }

                    // MVVM lovers look away
                    RubeusTab selectedTab = (RubeusTab)((TabItem)TabCtrlMain.SelectedItem).Content;
                    // Set global options from main window on the currently selected tab
                    selectedTab.Domain = TxtDomain.Text;
                    selectedTab.DomainController = TxtDomainController.Text;
                    selectedTab.Ldaps = (bool)ChkLdaps.IsChecked;
                    if ((bool)ChkAltCreds.IsChecked)
                    {
                        selectedTab.CredUser = TxtCredUsername.Text;
                        selectedTab.CredPassword = TxtCredPassword.Password;
                    }
                    // Each tab will check it has valid settings and it will prompt user if not
                    if (selectedTab.ValidateSettings())
                    {
                        if (_userPrefs.ExpandOutputOnRun && !_outputVisible)
                        {
                            ToggleOutputVisibility();
                        }
                        TxtOutput.AppendText("\n======= Running Rubeus =======\n");
                        TxtOutput.ScrollToEnd();
                        LblExecuteBtn.Text = "Running...";
                        ImgExecuteBtn.Source = new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/progress_indicator_16px.png"));
                        BtnExecute.IsEnabled = false;
                        ProgBar.Visibility = Visibility.Visible;
                        // Let the tab execute the relevant Rubeus command on a background thread and then it will call our ExecuteFinished callback when complete
                        selectedTab.ExecuteAsync(new Action<string>(ExecuteFinished));
                    }
                }
            }
            catch (Exception ex)
            {
                // Any exceptions thrown by Rubeus itself will be caught in the background thread and passed to our callback, so if we actually hit an 
                // exception here then it must be our problem rather than something that went wrong in Rubeus
                ExecuteFinished("Unexpected error in Rubeus GUI (not Rubeus) : " + ex.Message);
            }
        }

        private void ExecuteFinished(string errorMessage)
        {
            // Make sure we are on the UI thread
            if (Dispatcher.CheckAccess())
            {
                if (this.IsLoaded)
                {
                    LblExecuteBtn.Text = "Run";
                    ImgExecuteBtn.Source = new BitmapImage(new Uri("pack://application:,,,/RubeusGui;component/images/play_16px.png"));
                    BtnExecute.IsEnabled = true;
                    ProgBar.Visibility = Visibility.Collapsed;
                    // All of the Rubeus "Console.Writeline" calls will have ended up in our StringWriter, so write that to our output textbox and then clear the StringWriter
                    _outputWriter.Flush();
                    TxtOutput.AppendText(_outputWriter.ToString());
                    _outputWriter.GetStringBuilder().Clear();
                    if (!string.IsNullOrEmpty(errorMessage))
                    {
                        TxtOutput.AppendText("\nError: " + errorMessage);
                    }
                    TxtOutput.AppendText("\n\n========== Finished ==========\n");
                    TxtOutput.ScrollToEnd();
                }
            }
            else  // If we're not on the UI thread, invoke the function again there
            {
                Dispatcher.Invoke(new Action<string>(ExecuteFinished), errorMessage);
            }
        }

        private void BtnClearOutput_Click(object sender, RoutedEventArgs e)
        {
            TxtOutput.Clear();
        }

        private void BtnSaveOutput_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var sfd = new Microsoft.Win32.SaveFileDialog();
                sfd.Filter = "Text Files (*.txt)|*.txt";
                sfd.FileName = "Rubeus output.txt";
                if ((bool)sfd.ShowDialog())
                {
                    File.WriteAllText(sfd.FileName, TxtOutput.Text);
                    MessageBox.Show("File saved successfully", "File Saved", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving file: " + ex.Message, "Error Saving File", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void TxtOutput_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (Keyboard.IsKeyDown(Key.LeftCtrl))
            {
                if (e.Delta > 0)
                {
                    TxtOutput.FontSize += 1;
                }
                else if (e.Delta < 0)
                {
                    TxtOutput.FontSize -= 1;
                }
                e.Handled = true;
            }
        }

        private void BtnDecreaseFontSize_Click(object sender, RoutedEventArgs e)
        {
            TxtOutput.FontSize -= 1;
        }

        private void BtnIncreaseFontSize_Click(object sender, RoutedEventArgs e)
        {
            TxtOutput.FontSize += 1;
        }

        private void MenuItemHelpAbout_Click(object sender, RoutedEventArgs e)
        {
            AboutWindow aboutWindow = new AboutWindow();
            aboutWindow.ShowDialog();
        }

        private void MenuToolsOptions_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OptionsWindow optionsWindow = new OptionsWindow();
                optionsWindow.UserPrefs = _userPrefs;
                if ((bool)optionsWindow.ShowDialog())
                {
                    _userPrefs = optionsWindow.UserPrefs;
                    UserPreferences.SavePreferences(_userPrefs);
                    SetTabPreferences();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving preferences to XML file: " + ex.Message, "Error Saving Settings", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SetTabPreferences()
        {
            foreach (TabItem tab in TabCtrlMain.Items)
            {
                ((RubeusTab)tab.Content).ExpandAdvancedOptions = _userPrefs.ShowAdvancedOptionsByDefault;
            }
        }

        private void ExpOutput_Expanded(object sender, RoutedEventArgs e)
        {
            RowOutput.Height = new GridLength(300);
        }

        private void ExpOutput_Collapsed(object sender, RoutedEventArgs e)
        {
            RowOutput.Height = new GridLength(38);
        }

        private void BtnShowOutput_Click(object sender, RoutedEventArgs e)
        {
            ToggleOutputVisibility();
        }

        private void ToggleOutputVisibility()
        {
            if (_outputVisible)
            {
                RowOutput.Height = new GridLength(0);
                BtnShowOutput.Visibility = Visibility.Visible;
                BtnHideOutput.Visibility = Visibility.Collapsed;
            }
            else
            {
                RowOutput.Height = new GridLength(350);
                BtnShowOutput.Visibility = Visibility.Collapsed;
                BtnHideOutput.Visibility = Visibility.Visible;
            }
            _outputVisible = !_outputVisible;
        }
        
        private void MenuFeedback_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubEnhancementUrl();
        }

        private void LnkTwitter_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchVbScrubTwitterUrl();
        }

        private void BtnHideOutput_Click(object sender, RoutedEventArgs e)
        {
            ToggleOutputVisibility();
        }

        private void MenuBugReport_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubBugReportUrl();
        }
    }
}
