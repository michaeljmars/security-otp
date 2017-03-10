using System.Text;
using Xunit;

namespace Security.Otp.Test
{
    public class HotpGeneratorTest
    {
        private static readonly byte[] rfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

        private static readonly byte[] googleSecret = new byte[]
        {
            0xDE, 0xAD, 0xBE, 0xEF, 0x48,
            0x65, 0x6C, 0x6C, 0x6F, 0x21
        };

        [Theory]
        [InlineData(0, "755224")]
        [InlineData(1, "287082")]
        [InlineData(2, "359152")]
        [InlineData(3, "969429")]
        [InlineData(4, "338314")]
        [InlineData(5, "254676")]
        [InlineData(6, "287922")]
        [InlineData(7, "162583")]
        [InlineData(8, "399871")]
        [InlineData(9, "520489")]
        public void OneTimePassword_IsGeneratedCorrectlyForRfcTests(long counter, string expectedPassword)
        {
            // Arrange
            var otpGenerator = new HotpGenerator();

            // Act
            var password = otpGenerator.GeneratePassword(rfcSecret, counter, PasscodeLengths.SixDigitPassword);

            // Assert
            Assert.Equal(expectedPassword, password);
        }

        [Theory]
        [InlineData(1, "092093")]
        [InlineData(11, "266262")]
        public void OneTimePassword_IsGeneratedCorrectlyForGoogleTests(long counter, string expectedPassword)
        {
            // Arrange
            var otpGenerator = new HotpGenerator();

            // Act
            var password = otpGenerator.GeneratePassword(googleSecret, counter, PasscodeLengths.SixDigitPassword);

            // Assert
            Assert.Equal(expectedPassword, password);
        }

        [Theory]
        [InlineData(4)]
        [InlineData(6)]
        [InlineData(8)]
        public void OneTimePassword_OfTheCorrectLength_IsGenerated(int expectedLength)
        {
            // Arrange
            var secret = Encoding.ASCII.GetBytes("0000000000");
            var otpGenerator = new HotpGenerator();

            // Act
            var password = otpGenerator.GeneratePassword(secret, 0, new PasswordLength(expectedLength));

            // Assert
            Assert.Equal(password.Length, expectedLength);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(8)]
        public void OneTimePassword_IsNumeric(long counter)
        {
            // Arrange
            var secret = Encoding.ASCII.GetBytes("0000000000");
            var otpGenerator = new HotpGenerator();

            // Act
            var password = otpGenerator.GeneratePassword(secret, counter, PasscodeLengths.SixDigitPassword);

            // Assert
            Assert.True(int.TryParse(password, out int temp));
        }

        public void APassword_OfTheCorrectNumberOfDigits_IsGenerated(long counter, IPasswordLength length, int expectedLength)
        {
            // Arrange
            var secret = Encoding.UTF8.GetBytes("000000000000");

            var otpGenerator = new HotpGenerator();

            // Act
            var password = otpGenerator.GeneratePassword(secret, counter, length);

            // Assert
            Assert.Equal(password.Length, expectedLength);
        }
    }
}
