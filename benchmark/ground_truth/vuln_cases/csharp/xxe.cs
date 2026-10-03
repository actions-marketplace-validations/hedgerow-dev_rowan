using System.Xml;

public class ConfigLoader
{
    public XmlDocument Load(string path)
    {
        var doc = new XmlDocument();
        doc.Load(path);
        return doc;
    }
}
