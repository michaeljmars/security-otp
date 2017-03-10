
namespace Security.Otp
{
    /// <summary>
    /// Defines a method of generating HMAC-based One Time Passwords.
    /// </summary>
    public interface IHotpGenerator
    {
        /// <summary>
        /// Generates a HMAC-based One Time Password of the defined length using the specified key and moving factory
        /// (<paramref name="counter"/>).
        /// </summary>
        /// <param name="key">The secret key against which a password will be generated.</param>
        /// <param name="counter">The moving factor that denotes which password will be generated.</param>
        /// <param name="length">The length of the password in digits.</param>
        /// <returns>The generated password.</returns>
        string GeneratePassword(byte[] key, long counter, IPasswordLength length);
    }
}
