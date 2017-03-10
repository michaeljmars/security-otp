
namespace Security.Otp
{
    /// <summary>
    /// Represents a One-Time Password algorithm.
    /// </summary>
    public abstract class Otp
    {
        private static volatile HotpGenerator hotpGenerator;

        private static volatile TotpGenerator totpGenerator;

        /// <summary>
        /// Gets an instance for generating HMAC-Based One-Time Passwords.
        /// </summary>
        public static HotpGenerator Hotp => hotpGenerator ?? (hotpGenerator = new HotpGenerator());

        /// <summary>
        /// Gets an instance for generating Time-Based One-Time Passwords.
        /// </summary>
        public static TotpGenerator Totp => totpGenerator ?? (totpGenerator = new TotpGenerator());
    }
}
