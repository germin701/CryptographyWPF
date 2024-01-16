using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyWPF
{
    public partial class MainWindow : Window
    {
        private static readonly byte[] AesKey = Encoding.UTF8.GetBytes("1234567890123456");  // 128 bits (16 bytes)
        private static readonly byte[] AesIV = Encoding.UTF8.GetBytes("9876543210987654");  // 128 bits (16 bytes)

        private static readonly byte[] DesKey = Encoding.UTF8.GetBytes("87654321");  // 64 bits (8 bytes)
        private static readonly byte[] DesIV = Encoding.UTF8.GetBytes("12345678");  // 64 bits (8 bytes)

        private static readonly byte[] TripleDesKey = Encoding.UTF8.GetBytes("ABCDEF1234567890VWXYZ123");  // 192 bits (24 bytes)
        private static readonly byte[] TripleDesIV = Encoding.UTF8.GetBytes("87654321");  // 64 bits (8 bytes)

        public MainWindow()
        {
            InitializeComponent();
        }

        private void EncryptAesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;

            // Convert the user input to hexadecimal
            string hexPlainText = ConvertStringToHex(plainText);

            // Encrypt the hexadecimal representation
            byte[] encryptedData = EncryptAes(hexPlainText, AesKey, AesIV);

            // Display the encrypted data in hexadecimal without hyphens
            OutputTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            OutputTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void DecryptAesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;

            // Convert the hexadecimal input to byte array and decrypt
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            string decryptedText = DecryptAes(encryptedData, AesKey, AesIV);

            // Convert ASCII codes to characters
            string plainText = ConvertHexToAscii(decryptedText);

            // Display the decrypted text
            OutputTextBox.Text = plainText;
        }

        private void EncryptDesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;

            // Convert the user input to hexadecimal
            string hexPlainText = ConvertStringToHex(plainText);

            byte[] encryptedData = EncryptDes(hexPlainText, DesKey, DesIV);

            // Display the encrypted data in hexadecimal without hyphens
            OutputTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            OutputTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void DecryptDesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;

            // Convert the hexadecimal input to byte array and decrypt
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            byte[] decryptedData = DecryptDes(encryptedData, DesKey, DesIV);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);

            // Convert ASCII codes to characters
            string plainText = ConvertHexToAscii(decryptedText);

            // Display the decrypted text
            OutputTextBox.Text = plainText;
        }

        private void EncryptTripleDesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;

            // Convert the user input to hexadecimal
            string hexPlainText = ConvertStringToHex(plainText);

            // Encrypt the hexadecimal representation
            //byte[] encryptedData = EncryptTripleDes(hexPlainText, TripleDesKey, TripleDesIV);
            byte[] encryptedData = EncryptTripleDesManually(hexPlainText, DesKey, DesIV);

            // Display the encrypted data in hexadecimal without hyphens
            OutputTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            OutputTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void DecryptTripleDesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;

            // Convert the hexadecimal input to byte array and decrypt
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            //string decryptedText = DecryptTripleDes(encryptedData, TripleDesKey, TripleDesIV);
            string decryptedText = DecryptTripleDesManually(encryptedData, DesKey, DesIV);

            // Convert ASCII codes to characters
            string plainText = ConvertHexToAscii(decryptedText);

            // Display the decrypted text
            OutputTextBox.Text = plainText;
        }

        // To convert a string to its hexadecimal representation
        private string ConvertStringToHex(string input)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        // To convert a hexadecimal string to a byte array
        private byte[] ConvertHexStringToByteArray(string hexString)
        {
            // Determine the number of characters in the hex string
            int numberChars = hexString.Length;

            // Create a byte array to store the result (half the length of the hex string)
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return bytes;
        }
            /*Enumerable.Range(0, hexString.Length / 2)
                .Select(i => Convert.ToByte(hexString.Substring(i * 2, 2), 16))
                .ToArray();*/

        // To convert ASCII codes to characters
        private string ConvertHexToAscii(string hexString) =>
            string.Concat(Enumerable.Range(0, hexString.Length / 2)
                .Select(i => Convert.ToChar(Convert.ToInt32(hexString.Substring(i * 2, 2), 16))));

        private byte[] EncryptAes(string plainText, byte[] key, byte[] iv)
        {
            // Create an AES algorithm
            using (Aes aesAlg = Aes.Create())
            {
                // Set key and IV for the AES algorithm
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create a memory stream to store the encrypted data
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Create a CryptoStream to write the encrypted data to the memory stream
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        // Create a StreamWriter to write the plaintext to the CryptoStream
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        private string DecryptAes(byte[] cipherText, byte[] key, byte[] iv)
        {
            // Create an AES algorithm
            using (Aes aesAlg = Aes.Create())
            {
                // Set key and IV for the AES algorithm
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Create an decryptor using the key and IV
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create a memory stream from the input ciphertext byte array
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    // Create a CryptoStream to read the decrypted data from the memory stream
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Create a StreamReader to read the decrypted data from the CryptoStream
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        private byte[] EncryptDes(string plainText, byte[] key, byte[] iv)
        {
            // Create an DES algorithm
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                // Set key and IV for the DES algorithm
                desAlg.Key = key;
                desAlg.IV = iv;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

                // Convert plainText to bytes
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] encryptedBytes;

                // Create a memory stream to store the encrypted data
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Create a CryptoStream to write the encrypted data to the memory stream
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }

                return encryptedBytes;
            }
        }

        private byte[] DecryptDes(byte[] cipherText, byte[] key, byte[] iv)
        {
            // Create an DES algorithm
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                // Set key and IV for the DES algorithm
                desAlg.Key = key;
                desAlg.IV = iv;

                // Create an decryptor using the key and IV
                ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV);

                byte[] decryptedBytes;

                // Create a memory stream from the input ciphertext byte array
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    // Create a CryptoStream to read the decrypted data from the memory stream
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        // Create a memory stream to store the decrypted result
                        using (MemoryStream msResult = new MemoryStream())
                        {
                            csDecrypt.CopyTo(msResult);
                            decryptedBytes = msResult.ToArray();
                        }
                    }
                }
                return decryptedBytes;
            }
        }

        private byte[] EncryptTripleDes(string plainText, byte[] key, byte[] iv)
        {
            // Create a TDES algorithm
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                // Set key and IV for the TDES algorithm
                tdesAlg.Key = key;
                tdesAlg.IV = iv;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = tdesAlg.CreateEncryptor(tdesAlg.Key, tdesAlg.IV);

                // Create a memory stream to store the encrypted data
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // Create a CryptoStream to write the encrypted data to the memory stream
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        // Create a StreamWriter to write the plaintext to the CryptoStream
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        private string DecryptTripleDes(byte[] cipherText, byte[] key, byte[] iv)
        {
            // Create a TDES algorithm
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                // Set key and IV for the TDES algorithm
                tdesAlg.Key = key;
                tdesAlg.IV = iv;

                //Create an decryptor using the key and IV
                ICryptoTransform decryptor = tdesAlg.CreateDecryptor(tdesAlg.Key, tdesAlg.IV);

                //Create a memory stream from the input ciphertext byte array
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    //Create a CryptoStream to read the decrypted data from the memory stream
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        //Create a StreamReader to read the decrypted data from the CryptoStream
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        private byte[] EncryptTripleDesManually(string plainText, byte[] key, byte[] iv)
        {
            byte[] encryptedBytes, encryptedBytes2, encryptedBytes3;
            // First encrypt using DES
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.IV = iv;

                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }
            }
            // Second encrypt using DES
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.IV = iv;

                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(encryptedBytes, 0, encryptedBytes.Length);
                    }
                    encryptedBytes2 = msEncrypt.ToArray();
                }
            }
            // Third encrypt using DES
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.IV = iv;

                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(encryptedBytes2, 0, encryptedBytes2.Length);
                    }
                    encryptedBytes3 = msEncrypt.ToArray();
                }
            }
            return encryptedBytes3;
        }

        private string DecryptTripleDesManually(byte[] cipherText, byte[] key, byte[] iv)
        {
            // First decrypt by DES
            byte[] decryptedData3 = DecryptDes(cipherText, key, iv);

            // Second decrypt by DES
            byte[] decryptedData2 = DecryptDes(decryptedData3, key, iv);

            // Third decrypt by DES
            byte[] decryptedData1 = DecryptDes(decryptedData2, key, iv);

            // Convert the final result from byte array to UTF-8 string
            return Encoding.UTF8.GetString(decryptedData1);
        }

        private void FirstEncryptButton_Click(object sender, RoutedEventArgs e)
        {
            
        }

        private void FirstDecryptButton_Click(object sender, RoutedEventArgs e)
        {

        }
        private void SecondEncryptButton_Click(object sender, RoutedEventArgs e)
        {

        }
        private void SecondDecryptButton_Click(object sender, RoutedEventArgs e)
        {

        }
        private void ThirdEncryptButton_Click(object sender, RoutedEventArgs e)
        {

        }
        private void ThirdDecryptButton_Click(object sender, RoutedEventArgs e)
        {

        }

        private void InputTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(InputTextBox.Text))
            {
                InputTextBox.Visibility = System.Windows.Visibility.Collapsed;
                WatermarkInputTB.Visibility = System.Windows.Visibility.Visible;
            }
        }

        private void WatermarkInputTB_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkInputTB.Visibility = System.Windows.Visibility.Collapsed;
            InputTextBox.Visibility = System.Windows.Visibility.Visible;
            InputTextBox.Focus();
        }

        private void KeyTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(WatermarkKeyTB.Text))
            {
                KeyTextBox.Visibility = System.Windows.Visibility.Collapsed;
                WatermarkKeyTB.Visibility = System.Windows.Visibility.Visible;
            }
        }

        private void WatermarkKeyTB_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkKeyTB.Visibility = System.Windows.Visibility.Collapsed;
            KeyTextBox.Visibility = System.Windows.Visibility.Visible;
            KeyTextBox.Focus();
        }
    }
}
