
using System;

namespace Security.Otp
{
    /// <summary>
    /// Represents the length of a One-Time Password.
    /// </summary>
    public abstract class PasswordLengths
    {
        private static readonly IPasswordLength sixDigitPassword = new PasswordLength(6);
        private static readonly IPasswordLength eightDigitPassword = new PasswordLength(8);

        /// <summary>
        /// Gets an instance representing an 8 digit One-Time Password.
        /// </summary>
        public static IPasswordLength EightDigitPassword => eightDigitPassword;

        /// <summary>
        /// Gets an instance representing a 6 digit One-Time Password.
        /// </summary>
        public static IPasswordLength SixDigitPassword => sixDigitPassword;
    }

    /// <summary>
    /// Defines the length of a One-Time Password.
    /// </summary>
    public interface IPasswordLength
    {
        int Digits { get; }

        int Power { get; }

        string Format { get; }
    }

    /// <summary>
    /// The length of a One-Time Password.
    /// </summary>
    public class PasswordLength : IPasswordLength
    {
        private static readonly int[] powers = new int[]
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

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordLength"/> class that represents the specified length.
        /// </summary>
        /// <param name="digits">The desired password length.</param>
        internal PasswordLength(int digits)
        {
            this.Digits = digits;
            this.Power = powers[digits];
            this.Format = $"D{digits}";
        }

        public int Digits { get; }

        public int Power { get; }

        public string Format { get; }

        /// <summary>
        /// Generates a new <see cref="IPasswordLength"/> instance for the specified length.
        /// </summary>
        /// <param name="digits">The desired password length.</param>
        /// <returns>An instance representing the length of password specified by <paramref name="digits"/>.</returns>
        public static IPasswordLength Of(int digits)
        {
            if (digits == 8) return PasswordLengths.EightDigitPassword;
            if (digits == 6) return PasswordLengths.SixDigitPassword;

            if (digits < 0 || digits > 8) throw new ArgumentOutOfRangeException(nameof(digits), $"A password of {digits} in length cannot be created. Only passwords with a length between 0 and 8 (inclusive) are supported.");

            return new PasswordLength(digits);
        }
    }
}
