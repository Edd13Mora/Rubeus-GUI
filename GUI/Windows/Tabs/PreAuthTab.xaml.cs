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
    /// Interaction logic for PreAuthTab.xaml
    /// </summary>
    public partial class PreAuthTab : RubeusTab
    {

        public PreAuthTab()
        {
            InitializeComponent();
        }

        public override bool ValidateSettings()
        {
            if ((bool)RdoSpecificUser.IsChecked && string.IsNullOrWhiteSpace(TxtUsername.Text))
            {
                MessageBox.Show("Please specify a username or select another target option", "No Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if ((bool)RdoSpecificOu.IsChecked && string.IsNullOrEmpty(TxtOu.Text))
            {
                MessageBox.Show("Please specify a distinguished name for the OU you would like to query or select another target option", "No OU Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if ((bool)ChkOutputFile.IsChecked && string.IsNullOrEmpty(TxtOutputFilePath.Text))
            {
                MessageBox.Show("Please specify the path you would like to export hashes to or uncheck the option to export hashes", "No File Path Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            return true;
        }

        private void LnkHideDescription_Click(object sender, RoutedEventArgs e)
        {
            LblDescription.Visibility = _descriptionHidden ? Visibility.Visible : Visibility.Collapsed;
            _descriptionHidden = !_descriptionHidden;
            LnkHideDescription.Inlines.Clear();
            LnkHideDescription.Inlines.Add(_descriptionHidden ? "Show description" : "Hide description");
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

        private void BtnOutputFileBrowse_Click(object sender, RoutedEventArgs e)
        {
            TxtOutputFilePath.Text = UiHelpers.SaveTextFileDialog();
        }

        protected override Dictionary<string, string> GetRubeusArgs()
        {
            // Arguments to pass to Rubeus    
            Dictionary<string, string> rubeusArgs = new Dictionary<string, string>();
            if ((bool)RdoSpecificUser.IsChecked)
            {
                rubeusArgs.Add("/user", TxtUsername.Text);
            }
            else if ((bool)RdoSpecificOu.IsChecked)
            {
                rubeusArgs.Add("/ou", TxtOu.Text);
            }
            if ((bool)RdoHashcat.IsChecked)
            {
                rubeusArgs.Add("/format", "hashcat");
            }
            else if ((bool)RdoJohn.IsChecked)
            {
                rubeusArgs.Add("/format", "john");
            }
            if ((bool)ChkOutputFile.IsChecked)
            {
                rubeusArgs.Add("/outfile", TxtOutputFilePath.Text);
            }

            return rubeusArgs;
        }

        protected override Rubeus.Commands.ICommand GetRubeusCommand()
        {
            return new Rubeus.Commands.Asreproast();
        }
    }
}
