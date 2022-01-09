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
using Rubeus.Domain;

namespace RubeusGui
{

    public partial class MainWindow : Window
    {

        private UserPreferences _userPrefs = new UserPreferences();
        private readonly StringWriter _outputWriter = new StringWriter();

        public MainWindow()
        {
            try
            {
                InitializeComponent();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unexpected error in application startup: " + ex.Message + "\n" + ex.InnerException?.Message, "Unexpected Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // Redirect all the Rubeus Console.WriteLine calls to a string that we can add to our log
                Console.SetOut(_outputWriter);
                Console.SetError(_outputWriter);

                // Give each tab a reference to this main window so that they can get the global settings like domain and username etc 
                foreach (TabItem tab in TabCtrlMain.Items)
                {
                    ((RubeusTab)tab.Content).OwnerWindow = this;
                }

                // Load user preferences and last used domain name etc from XML file
                LoadUserPreferences();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unexpected error in window load: " + ex.Message + "\n" + ex.InnerException?.Message, "Unexpected Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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
                else
                {
                    _userPrefs.CredUser = null;
                }
                _userPrefs.Ldaps = (bool)ChkLdaps.IsChecked;
                UserPreferences.SavePreferences(_userPrefs);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving preferences and recently used settings to XML file: " + ex.Message + "\n You can disable saving recently used settings in Tools -> Options", "Error Saving Preferences", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // Called by individual tabs to get the global domain settings from this main window
        public DomainSettings GetDomainSettings()
        {
            DomainSettings settings = new DomainSettings();
            settings.DomainName = TxtDomain.Text;
            settings.DomainController = TxtDomainController.Text;
            if (!string.IsNullOrWhiteSpace(TxtDomain.Text) && !TxtDomain.Text.Contains('.'))
            {
                throw new ApplicationException("Domain name must be in DNS format (mydomain.local) not NetBIOS format (MYDOMAIN)");
            }

            if ((bool)ChkAltCreds.IsChecked)
            {
                if (string.IsNullOrWhiteSpace(TxtCredUsername.Text) || string.IsNullOrWhiteSpace(TxtCredPassword.Password))
                {
                    throw new ApplicationException("Please specify a username and password or uncheck the option to use alternate credentials");
                }
                else if (TxtCredUsername.Text.Contains('\\'))
                {
                    string[] usernameWithDomain = TxtCredUsername.Text.Split('\\');
                    settings.Credentials = new System.Net.NetworkCredential(usernameWithDomain[1], TxtCredPassword.Password, usernameWithDomain[0]);
                }
                else if (!string.IsNullOrWhiteSpace(TxtDomain.Text))
                {
                    settings.Credentials = new System.Net.NetworkCredential(TxtCredUsername.Text, TxtCredPassword.Password, TxtDomain.Text);
                }
                else
                {
                    settings.Credentials = new System.Net.NetworkCredential(TxtCredUsername.Text, TxtCredPassword.Password);
                }
            }
            settings.Ldaps = (bool)ChkLdaps.IsChecked;
            return settings;
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

        private void MenuFeedback_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubEnhancementUrl();
        }

        private void LnkTwitter_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchVbScrubTwitterUrl();
        }

        private void MenuBugReport_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubBugReportUrl();
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            try
            {
                if (_userPrefs.SaveMru)
                {
                    SaveUserPreferences();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving user preferences and last used domain settings to XML file: " + ex.Message, "Error Saving Preferences", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
