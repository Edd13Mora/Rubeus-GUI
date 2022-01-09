using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RubeusGui
{
    public class CsvWriter
    {

        //public static void SaveCsvWithPrompt(string defaultFileName, List<Dictionary<string, string>> data)
        //{
        //    if (data?.Count == 0 || data[0].Count == 0)
        //    {
        //        return;
        //    }
        //    var sfd = new Microsoft.Win32.SaveFileDialog();
        //    sfd.Filter = "CSV Files (*.csv)|*.csv";
        //    sfd.FileName = defaultFileName;
        //    if ((bool)sfd.ShowDialog())
        //    {
        //        using (StreamWriter writer = new StreamWriter(sfd.FileName, false, new UTF8Encoding(false)))
        //        {
        //            foreach (Dictionary<string, string> currentRow in data)
        //            {
        //
        //
        //            }
        //        }
        //    }
        //}

        public static string MakeCsvSafe(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "\" \"";
            }
            else
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
        }
    }


}
