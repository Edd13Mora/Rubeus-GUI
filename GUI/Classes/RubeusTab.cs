using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace RubeusGui.Windows.Tabs
{

    // This is the base class that all of the individual tabs in the UI inherit from. 

    // Each tab must provide implementations of ValidateSettings, GetRubeusArgs, and GetRubeusCommand (the main window will
    // call these functions on the currently selected tab when user clicks Run)

    public abstract class RubeusTab : System.Windows.Controls.UserControl
    {

        public string Domain { get; set; }

        public string DomainController { get; set; }

        public string CredUser { get; set; }

        public string CredPassword { get; set; }

        public bool Ldaps { get; set; }

        public bool ExpandAdvancedOptions { get; set; }

        protected bool _descriptionHidden = true;

        /// <summary>
        /// Each tab validates their own settings based on user input and returns true if all settings are valid
        /// </summary>
        public abstract bool ValidateSettings();

        /// <summary>
        /// Each tab uses this to provide the settings the user has selected
        /// </summary>
        protected abstract Dictionary<string, string> GetRubeusArgs();

        /// <summary>
        /// For some tabs this will always be the same thing (e.g Kerberoasting tab always uses Kerberoasting command) but for some tabs it is dynamic based on user selection  
        /// (e.g golden/silver ticket tab will use different Rubeus commands for golden vs silver ticket)
        /// </summary>
        protected abstract Rubeus.Commands.ICommand GetRubeusCommand();

               
        // Main window will call this method on the currently selected tab when user clicks the Run button
        public void ExecuteAsync(Action<string> callback)
        {
            // Setup arguments that will be passed to Rubeus
            Dictionary<string, string> rubeusArgs = new Dictionary<string, string>();
            if (!string.IsNullOrEmpty(this.Domain)) rubeusArgs.Add("/domain", this.Domain);
            if (!string.IsNullOrEmpty(this.DomainController)) rubeusArgs.Add("/dc", this.DomainController);
            if (!string.IsNullOrEmpty(this.CredUser)) rubeusArgs.Add("/creduser", this.CredUser);
            if (!string.IsNullOrEmpty(this.CredPassword)) rubeusArgs.Add("/credpassword", this.CredPassword);
            if (this.Ldaps) rubeusArgs.Add("/ldaps", string.Empty);
            // Get tab specific rubeus arguments and add them to our list (can't do this on the background thread as it won't have access to UI controls)
            foreach (var argPair in GetRubeusArgs())
            {
                rubeusArgs.Add(argPair.Key, argPair.Value);
            }
            // Start a background thread that will run the tab specific Rubeus command and then call our callback when finished
            Thread workerThread = new Thread(() => ExecuteInternal(GetRubeusCommand(), rubeusArgs, callback));
            workerThread.IsBackground = true;
            workerThread.Start();
        }

        // Run on the background thread
        private void ExecuteInternal(Rubeus.Commands.ICommand rubeusCommand, Dictionary<string,string> args,Action<string> callback)
        {
            string errorMessage = string.Empty;
            try
            {
                rubeusCommand.Execute(args);
            }
            catch (Exception ex)
            {
                errorMessage = ex.Message;
            }
            callback.Invoke(errorMessage);
        }

        

    }
}
