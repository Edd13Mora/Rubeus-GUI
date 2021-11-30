using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Controls;

namespace RubeusGui.Windows.Tabs
{

    // This is the base class that all of the individual tabs in the UI inherit from. 

    // Each tab must provide implementations of ValidateSettings, GetRubeusArgs, and GetRubeusCommand (the main window will
    // call these functions on the currently selected tab when user clicks Run)

    public abstract class RubeusTab : System.Windows.Controls.UserControl
    {

        public MainWindow OwnerWindow { get; set; }

        public bool ExpandAdvancedOptions { get; set; }

        private bool _descriptionHidden = true;

        protected void ToggleDescriptionVisibility(TextBlock description, System.Windows.Documents.Hyperlink link)
        {
            description.Visibility = _descriptionHidden ? System.Windows.Visibility.Visible : System.Windows.Visibility.Collapsed;
            link.Inlines.Clear();
            link.Inlines.Add(_descriptionHidden ? "Hide description" : "Show description");
            _descriptionHidden = !_descriptionHidden;
        }

    }
}
