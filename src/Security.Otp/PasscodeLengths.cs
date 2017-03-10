﻿
namespace Security.Otp
{
    /// <summary>
    /// Represents the length of a One-Time Password.
    /// </summary>
    public abstract class PasscodeLengths
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

        string Format { get; }
    }

    /// <summary>
    /// The length of a One-Time Password.
    /// </summary>
    internal class PasswordLength : IPasswordLength
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

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordLength"/> class that represents the specified length.
        /// </summary>
        /// <param name="length">The desired password length.</param>
        public PasswordLength(int length)
        {
            this.Digits = digits[length];
            this.Format = $"D{length}";
        }

        public int Digits { get; }

        public string Format { get; }
    }
}
