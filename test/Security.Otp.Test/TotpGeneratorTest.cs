using System;
using System.Globalization;
using System.Text;
using Xunit;

namespace Security.Otp.Test
{
    public class TotpGeneratorTest
    {
        private static readonly byte[] rfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

        [Theory]
        [InlineData("1970-01-01 00:00:59", "94287082")]
        public void OneTimePassword_UsingSHA1_IsGeneratedCorrectlyForRfcTests(string dateTimeString, string expectedPassword)
        {
            // Arrange
            var dateTime = DateTime.ParseExact(dateTimeString, "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

            var otpGenerator = new TotpGenerator();

            // Act
            var password = otpGenerator.GeneratePassword(rfcSecret, dateTime, 30, PasscodeLengths.EightDigitPassword);

            // Assert
            Assert.Equal(expectedPassword, password);
        }
    }
}
