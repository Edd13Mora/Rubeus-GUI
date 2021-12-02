using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rubeus
{
    public class TicketDecryptException : RubeusException
    {

        public Ask.TicketType Ticket { get; set; }

        public TicketDecryptException(string message, Ask.TicketType ticketType) : base(message)
        {
            this.Ticket = ticketType;
        }
    }
}
