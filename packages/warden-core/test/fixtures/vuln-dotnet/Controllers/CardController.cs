using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
public class CardController {
    public byte[] Weak(byte[] d) => MD5.Create().ComputeHash(d);
    public void Find(AppDb db, string id) {
        db.Users.FromSqlRaw("SELECT * FROM Users WHERE Id = " + id);
    }
    public void Run(string name) { System.Diagnostics.Process.Start("report " + name); }
    public string CardNumber { get; set; }
    public string Cvv { get; set; }
}
