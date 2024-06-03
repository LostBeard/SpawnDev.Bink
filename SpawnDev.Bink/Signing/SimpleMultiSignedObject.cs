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
