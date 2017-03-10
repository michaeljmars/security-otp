using System;

namespace Security.Otp
{
    public class TotpGenerator
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public string GeneratePassword(byte[] key, IPasswordLength length)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            TimeSpan span = (DateTime.Now.ToUniversalTime() - Epoch);

            return this.GeneratePassword(key, DateTime.UtcNow, 60, length);
        }

        public string GeneratePassword(byte[] key, int step, IPasswordLength length)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (step < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(step), "A positive value must be supplied for step.");
            }

            return this.GeneratePassword(key, DateTime.UtcNow, step, length);
        }

        internal string GeneratePassword(byte[] key, DateTime date, int step, IPasswordLength length)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (step < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(step), "A positive value must be supplied for step.");
            }

            TimeSpan span = (date - Epoch);
            return Otp.Hotp.GeneratePassword(key, (int)span.TotalSeconds / step, length);
        }
    }
}
