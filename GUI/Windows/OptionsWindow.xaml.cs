using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;


namespace RubeusGui
{
    /// <summary>
    /// Interaction logic for OptionsWindow.xaml
    /// </summary>
    public partial class OptionsWindow : Window
    {

        public UserPreferences UserPrefs { get; set; }

        public OptionsWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                ChkRememberLastUsed.IsChecked = this.UserPrefs.SaveMru;
                ChkShowAdvanced.IsChecked = this.UserPrefs.ShowAdvancedOptionsByDefault;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error loading current settings: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
        }

        private void BtnOk_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                UserPreferences newPrefs = new UserPreferences();
                newPrefs.SaveMru = (bool)ChkRememberLastUsed.IsChecked;
                newPrefs.ShowAdvancedOptionsByDefault = (bool)ChkShowAdvanced.IsChecked;
                if (newPrefs.SaveMru)
                {
                    newPrefs.Domain = this.UserPrefs.Domain;
                    newPrefs.DomainController = this.UserPrefs.DomainController;
                    newPrefs.CredUser = this.UserPrefs.CredUser;
                    newPrefs.Ldaps = this.UserPrefs.Ldaps;
                }
                this.UserPrefs = newPrefs;
                this.DialogResult = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error saving preferences: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LnkFeedback_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubEnhancementUrl();
        }
    }
}
