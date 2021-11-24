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
            LblDescription.Visibility = _descriptionHidden ? Visibility.Visible : Visibility.Collapsed;
            _descriptionHidden = !_descriptionHidden;
            LnkHideDescription.Inlines.Clear();
            LnkHideDescription.Inlines.Add(_descriptionHidden ? "Show description" : "Hide description");
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

        public override bool ValidateSettings()
        {

            if ((bool)RdoKerberoastSpecificUser.IsChecked && string.IsNullOrEmpty(TxtKerberosSpecificUsername.Text))
            {
                MessageBox.Show("Please specify a username or select another target option", "No Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if ((bool)RdoKerberoastSpecificSpn.IsChecked && string.IsNullOrEmpty(TxtKerberosSpecificSpnName.Text))
            {
                MessageBox.Show("Please specify at least one SPN or select another target option", "No SPN Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if ((bool)ChkOutputFile.IsChecked && string.IsNullOrEmpty(TxtOutputFilePath.Text))
            {
                MessageBox.Show("Please specify the path you would like to export hashes to or uncheck the option to export hashes", "No File Path Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if ((bool)RdoKerberoastSpecificSpn.IsChecked && string.IsNullOrEmpty(TxtKerberosSpecificSpnName.Text))
            {
                MessageBox.Show("Please specify at leaste one SPN or select another target option", "No SPN Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            if ((bool)RdoTgtFromFile.IsChecked)
            {
                if (string.IsNullOrEmpty(TxtTgtPath.Text))
                {
                    MessageBox.Show("Please specify the path to your TGT file or select another TGT option", "No TGT Path Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            if ((bool)ChkDelay.IsChecked)
            {
                int delay;
                if (!int.TryParse(TxtDelay.Text, out delay) || delay < 0)
                {
                    MessageBox.Show("Please specify a valid timespan in milliseconds that should be used to wait between network requests", "Invalid Time Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
                int jitter;
                if (!int.TryParse(TxtJitter.Text, out jitter) || jitter < 0 || jitter > 100)
                {
                    MessageBox.Show("Please specify a valid percentage between 0 and 100 that should be used to randomize the delay", "Invalid Jitter Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            if ((bool)RdoTgtBase64.IsChecked && string.IsNullOrEmpty(TxtTgtBase64.Text))
            {
                MessageBox.Show("Please enter the base64 representation of a TGT or select another TGT option", "No TGT Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            return true;
        }


        private void BtnOutputFileBrowse_Click(object sender, RoutedEventArgs e)
        {
            TxtOutputFilePath.Text = UiHelpers.SaveTextFileDialog();
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
            RdoTgtDefault.IsChecked = true;
        }

        protected override Dictionary<string, string> GetRubeusArgs()
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            if ((bool)RdoKerberoastSpecificUser.IsChecked) { args.Add("/user", TxtKerberosSpecificUsername.Text); }
            if ((bool)RdoKerberoastSpecificSpn.IsChecked) { args.Add("/spns", TxtKerberosSpecificSpnName.Text); }
            if ((bool)ChkStatsOnly.IsChecked) { args.Add("/stats", string.Empty); }
            if ((bool)ChkOutputFile.IsChecked) { args.Add("/outfile", TxtOutputFilePath.Text); }
            if (!string.IsNullOrWhiteSpace(TxtLdapFilter.Text)) { args.Add("/ldapfilter", TxtLdapFilter.Text); }
            if ((bool)ChkRc4opsec.IsChecked)
            {
                args.Add("/rc4opsec", string.Empty);
            }
            else
            {
                if ((bool)RdoTgtDeleg.IsChecked) { args.Add("/usetgtdeleg", string.Empty); }
                if ((bool)RdoTgtFromFile.IsChecked) { args.Add("/ticket", TxtTgtPath.Text); }
                if ((bool)RdoTgtBase64.IsChecked) { args.Add("/ticket", TxtTgtBase64.Text); }
                if ((bool)ChkAes.IsChecked) { args.Add("/aes", string.Empty); }
            }
            if ((bool)ChkDelay.IsChecked) { args.Add("/delay", TxtDelay.Text); }
            if ((bool)ChkDelay.IsChecked) { args.Add("/jitter", TxtJitter.Text); }
            if ((bool)ChkDelay.IsChecked) { args.Add("/resultlimit", TxtResultsLimit.Text); }
            if ((bool)RdoEnterprise.IsChecked) { args.Add("/enterprise", string.Empty); }
            if ((bool)RdoAutoEnterprise.IsChecked) { args.Add("/autoenterprise", string.Empty); }
            return args;
        }

        protected override Rubeus.Commands.ICommand GetRubeusCommand()
        {
            return new Rubeus.Commands.Kerberoast();
        }


    }
}
