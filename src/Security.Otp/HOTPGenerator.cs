using System;
using System.Security.Cryptography;

namespace Security.Otp
{
    public class HotpGenerator : IHotpGenerator
    {
        private static readonly int[] digits = new int[]
        {
            1,        // 0
            10,       // 1
            100,      // 2
            1000,     // 3
            10000,    // 4
            100000,   // 5
            1000000,  // 6
            10000000, // 7
            100000000 // 8
        };

        /// <inheritdoc/>
        public string GeneratePassword(byte[] key, long counter, IPasswordLength length)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (counter < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(counter),
                    "A positive value must be supplied for the counter.");
            }

            if (length.Digits < 0 || length.Digits > 8)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(length.Digits),
                    "Only passwords of between 1 and 8 digits in length can be generated.");
            }

            using (var hmac = new HMACSHA1(key))
            {
                return GeneratePassword(key, counter, length, hmac);
            }
        }

        internal string GeneratePassword(byte[] key, long counter, IPasswordLength length, HMAC hmac)
        {
            var text = BitConverter.GetBytes(counter);
            Array.Reverse(text);

            var hash = hmac.ComputeHash(text);
            int offset = hash[19] & 0xf;

            int binary = (hash[offset] & 0x7f) << 24
                | (hash[offset + 1] & 0xff) << 16
                | (hash[offset + 2] & 0xff) << 8
                | (hash[offset + 3] & 0xff);

            int password = binary % digits[length.Digits];

            return password.ToString(length.Format);
        }
    }
}
