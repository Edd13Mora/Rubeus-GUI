using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rubeus
{
    public class Log
    {

        public static event Action<string> MessageLogged;

        public static void WriteLine(string message)
        {
            try
            {
                MessageLogged?.Invoke(message);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Error writing log message: " + ex.Message);
            }
        }

    }
}
