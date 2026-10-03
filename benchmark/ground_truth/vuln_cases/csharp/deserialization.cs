using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class SessionStore
{
    public object Load(Stream incoming)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(incoming);
    }
}
