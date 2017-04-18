using System;
using System.Security.Cryptography;

namespace Security.Otp
{
    public class TotpGenerator
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public string GeneratePassword(byte[] key, IPasswordLength length, HMAC hmac)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (length.Digits < 0 || length.Digits > 8)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(length.Digits),
                    "Only passwords of between 1 and 8 digits in length can be generated.");
            }

            if (hmac == null)
            {
                throw new ArgumentNullException(nameof(hmac));
            }

            TimeSpan span = (DateTime.Now.ToUniversalTime() - Epoch);

            return this.GeneratePassword(key, DateTime.UtcNow, 60, length, hmac);
        }

        public string GeneratePassword(byte[] key, int step, IPasswordLength length, HMAC hmac)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (step < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(step), "A positive value must be supplied for step.");
            }

            if (length.Digits < 0 || length.Digits > 8)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(length.Digits),
                    "Only passwords of between 1 and 8 digits in length can be generated.");
            }

            if (hmac == null)
            {
                throw new ArgumentNullException(nameof(hmac));
            }

            return this.GeneratePassword(key, DateTime.UtcNow, step, length, hmac);
        }

        internal string GeneratePassword(byte[] key, DateTime date, int step, IPasswordLength length, HMAC hmac)
        {
            TimeSpan span = (date.ToUniversalTime() - Epoch);
            return Otp.Hotp.GeneratePassword(key, (long)span.TotalSeconds / step, length, hmac);
        }
    }
}
