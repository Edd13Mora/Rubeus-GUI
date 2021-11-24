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

    // Use this class (and the XAML) as a template for new tabs
    public partial class ComingSoonTab : RubeusTab
    {
        public ComingSoonTab()
        {
            InitializeComponent();
        }

        private void LnkRubeusGuiGithub_Click(object sender, RoutedEventArgs e)
        {
            UiHelpers.LaunchGithubMainUrl();
        }

        private void BaseTab_Loaded(object sender, RoutedEventArgs e)
        {
            LblVersion.Text = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
        }

        public override bool ValidateSettings()
        {
            //TODO: When adding new tabs, validate tab specific settings here (empty text boxes etc)
            return false;
        }
        
       
        protected override Dictionary<string, string> GetRubeusArgs()
        {
            throw new NotImplementedException();
        }

        protected override Rubeus.Commands.ICommand GetRubeusCommand()
        {
            throw new NotImplementedException();
        }
    }
}
