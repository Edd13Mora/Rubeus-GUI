using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Xml.Serialization;

namespace RubeusGui
{
   public class UserPreferences
    {
                
        public static string XmlFilePath => Path.Combine(Environment.CurrentDirectory, "RubeusGUI_Prefs.xml");

        // Recently used settings (apart from password)
        public string Domain { get; set; }
        public string DomainController { get; set; }
        public string CredUser { get; set; }
        public bool Ldaps { get; set; }

        // Settings from Tools -> Options
        public bool ShowAdvancedOptionsByDefault { get; set; }
        public bool SaveMru { get; set; } = true;
                
        static public void SavePreferences(UserPreferences prefs)
        {
            using (FileStream stream = new FileStream(XmlFilePath, FileMode.Create))
            {
                XmlSerializer xml = new XmlSerializer(typeof(UserPreferences));
                xml.Serialize(stream,prefs);
            }
        }

        static public UserPreferences GetPreferences()
        {
            if (File.Exists(XmlFilePath))
            {
                using (FileStream stream = new FileStream(XmlFilePath, FileMode.Open))
                {
                    XmlSerializer xml = new XmlSerializer(typeof(UserPreferences));
                    return (UserPreferences)xml.Deserialize(stream);
                }
            } 
            else
            {
                return new UserPreferences();
            }
        }

        

    }
}
