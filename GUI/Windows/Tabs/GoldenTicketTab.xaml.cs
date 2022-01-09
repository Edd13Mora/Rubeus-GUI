using Rubeus.Domain;
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

namespace RubeusGui.Windows.Tabs
{
    /// <summary>
    /// Interaction logic for GoldenTicketTab.xaml
    /// </summary>
    public partial class GoldenTicketTab : RubeusTab
    {

        //TODO: Finish implementing silver/golden ticket calls and then add this tab to the main window

        public GoldenTicketTab()
        {
            InitializeComponent();
            CboPasswordHashType.ItemsSource = new List<EncryptionDisplayItem>() { new EncryptionDisplayItem(EncryptionType.RC4),
                                                                                  new EncryptionDisplayItem(EncryptionType.DES),
                                                                                  new EncryptionDisplayItem(EncryptionType.AES128),
                                                                                  new EncryptionDisplayItem(EncryptionType.AES256)};
            CboPasswordHashType.SelectedIndex = 0;
        }

        private void LnkHideDescription_Click(object sender, RoutedEventArgs e)
        {
            ToggleDescriptionVisibility(LblDescription, LnkHideDescription);
        }

        private void CboTicketType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (this.IsLoaded)
            {
                if (CboTicketType.SelectedIndex == 0)
                {
                    RowSpn.Height = new GridLength(31);
                    TxtSpn.Visibility = Visibility.Visible;
                    LblServicePassword.Text = "Service password hash:";
                    ChkSilverPtt.Visibility = Visibility.Visible;
                    ChkGoldenPtt.Visibility = Visibility.Collapsed;
                }
                else
                {
                    RowSpn.Height = new GridLength(0);
                    TxtSpn.Visibility = Visibility.Collapsed;
                    LblServicePassword.Text = "Krbtgt password hash:";
                    ChkSilverPtt.Visibility = Visibility.Collapsed;
                    ChkGoldenPtt.Visibility = Visibility.Visible;
                }
            }
        }

        private void LnkFeedback_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubEnhancementUrl();
        }

        private void RubeusTab_Loaded(object sender, RoutedEventArgs e)
        {
            if (this.ExpandAdvancedOptions)
            {
                ExpAdvancedTicket.IsExpanded = true;
                ExpAdvancedUser.IsExpanded = true;
            }
        }

        private void BtnExecute_Click(object sender, RoutedEventArgs e)
        {

        }

        private void CreateTicket()
        {
            //Rubeus.ForgeTickets.ForgeTicket()
        }

        private void CreateTicketFinished(string ticket, string errorMessage)
        {

        }

        private void BtnCopyTgt_Click(object sender, RoutedEventArgs e)
        {

        }

        private void BtnExportKirbi_Click(object sender, RoutedEventArgs e)
        {
            
        }

        private void BtnExportBase64_Click(object sender, RoutedEventArgs e)
        {

        }

        private void BtnLookupDomainSid_Click(object sender, RoutedEventArgs e)
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

            //TODO: Get SID from domain

        }
    }
}
