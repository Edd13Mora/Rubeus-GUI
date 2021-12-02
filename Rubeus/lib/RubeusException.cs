using System;

namespace Rubeus
{
    public class RubeusException : Exception
    {
        public RubeusException(string message)
            : base(message)
        {
        }
    }
}
