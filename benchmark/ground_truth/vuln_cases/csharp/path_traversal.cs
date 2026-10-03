using System.IO;

public class FileController
{
    public byte[] GetFile(string root)
    {
        return File.ReadAllBytes(Path.Combine(root, Request.Query["file"]));
    }
}
