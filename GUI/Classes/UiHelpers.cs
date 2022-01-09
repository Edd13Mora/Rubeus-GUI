using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;

namespace RubeusGui
{
    class UiHelpers
    {

        public static Uri HourglassIconPath => new Uri("pack://application:,,,/RubeusGui;component/images/hourglass_16px.png");
        public static Uri PlayIconPath => new Uri("pack://application:,,,/RubeusGui;component/images/play_16px.png");

        public static void CopyToClipboard(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }

            try
            {
                Clipboard.SetText(text);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error setting clipboard text: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
                       
        //public static bool UsernameContainsDomain(string username)
        //{
        //    // I'm not good with RegEx and the one Rubeus uses to validate the username format doesn't actually work correctly, so I created this mess instead
        //    return (!string.IsNullOrEmpty(username)) && (username.IndexOf(@"\") > 0) && username.IndexOf(".") > 0 && username.IndexOf(".") < username.IndexOf(@"\");
        //}

        public static void LaunchGithubMainUrl()
        {
            LaunchUrl("https://github.com/VbScrub/Rubeus-GUI");
        }

        public static void LaunchGithubEnhancementUrl()
        {
            LaunchUrl("https://github.com/VbScrub/Rubeus-GUI/issues/new?labels=enhancement&body=Version%3A+" + UiHelpers.GetAppVersionString());
        }

        public static void LaunchGithubBugReportUrl()
        {
            LaunchUrl("https://github.com/VbScrub/Rubeus-GUI/issues/new?labels=bug&title=[BUG]+%3Cinsert+title%3E&body=Version%3A+" + UiHelpers.GetAppVersionString());
        }

        public static void LaunchVbScrubTwitterUrl()
        {
            LaunchUrl("https://twitter.com/vbscrub");
        }

        public static void LaunchUrl(string url)
        {
            try
            {
                System.Diagnostics.Process.Start(url);
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show("Error launching URL " + url + "\n" + ex.Message, "Error Launching URL", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            }
        }

        public static string SaveTextFileDialog()
        {
            var sfd = new Microsoft.Win32.SaveFileDialog();
            sfd.Filter = "Text Files (*.txt)|*.txt|All Files|*.*";
            sfd.FileName = string.Empty;
            if ((bool)sfd.ShowDialog())
            {
                return sfd.FileName;
            }
            else
            {
                return string.Empty;
            }
        }

        public static string GetAppVersionString()
        {
            try
            {
                Version appVersion = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                return appVersion.Major + "." + appVersion.Minor + "." + appVersion.Build;
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

    }
}
