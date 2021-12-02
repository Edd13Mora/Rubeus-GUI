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
using System.Windows.Shapes;

namespace RubeusGui
{
    /// <summary>
    /// Interaction logic for AboutWindow.xaml
    /// </summary>
    public partial class AboutWindow : Window
    {
        public AboutWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            LblVersion.Text = UiHelpers.GetAppVersionString();
            LblBuildDate.Text = "2nd December 2021"; // TODO: Update build date label before compiling
        }

        private void WebsiteLnk_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchUrl("http://vbscrub.com");
        }

        private void CloseBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void LnkTwitter_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchVbScrubTwitterUrl();
        }

        private void LnkRubeus_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchUrl("https://github.com/GhostPack/Rubeus");
        }

        private void LnkIcons_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchUrl("http://icons8.com");
        }

        private void LnkGithub_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubMainUrl();
        }
    }
}
