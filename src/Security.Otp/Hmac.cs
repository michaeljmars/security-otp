using System.Security.Cryptography;

namespace Security.Otp
{
    public class Hmac
    {
        public static HMAC Sha1 => new HMACSHA1();

        public static HMAC Sha256 => new HMACSHA256();

        public static HMAC Sha512 => new HMACSHA512();
    }
}
