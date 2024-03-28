using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bink.Signing
{
    public class SimpleMultiSignedObject : MultiSignedObject
    {
        public string Message { get; set; } = "";
        public SimpleMultiSignedObject() { }
        public SimpleMultiSignedObject(string message)
        {
            Message = message;
        }
    }
}
