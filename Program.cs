using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;

const string password = "password";

// Using PasswordHasher class
string hashedPassword = new PasswordHasher<object?>().HashPassword(null, password);
var result = new PasswordHasher<object?>().VerifyHashedPassword(null, hashedPassword, "passwordd");
Console.WriteLine(hashedPassword);

// Using KeyDerivation.Pbkdf2
byte[] salt = RandomNumberGenerator.GetBytes(128/8);
byte[] hashed = KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, 100000, 256 / 8);
hashedPassword = Convert.ToBase64String(hashed);
Console.WriteLine(hashedPassword);