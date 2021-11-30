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
    /// Interaction logic for CredentialsWindow.xaml
    /// </summary>
    public partial class CredentialsWindow : Window
    {

        public string Domain { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }

        public CredentialsWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(this.Domain))
            {
                LblDomain.Text = "My logon domain";
            }
            else
            {
                LblDomain.Text = this.Domain;
            }
            TxtUsername.Text = this.Username;
            TxtPassword.Focus();
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
        }

        private void BtnOk_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(TxtUsername.Text))
            {
                MessageBox.Show("Please enter a username, or click Cancel to use your Windows logon credentials instead", "No Username Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (String.IsNullOrEmpty(TxtPassword.Password))
            {
                MessageBox.Show("Please enter a password, or click Cancel to use your Windows logon credentials instead", "No Password Specified", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            this.Username = TxtUsername.Text;
            this.Password = TxtPassword.Password;
            this.DialogResult = true;
        }
    }
}
