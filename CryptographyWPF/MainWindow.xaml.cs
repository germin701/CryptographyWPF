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
        private static readonly byte[] AesIV = Encoding.UTF8.GetBytes("9876543210987654");  // 128 bits (16 bytes)
        private static readonly byte[] DesIV = Encoding.UTF8.GetBytes("12345678");  // 64 bits (8 bytes)
        private static readonly byte[] TripleDesIV = Encoding.UTF8.GetBytes("87654321");  // 64 bits (8 bytes)

        private byte[] Key, Key1, Key2, Key3;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void EncryptAesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;
            Key = Encoding.UTF8.GetBytes(KeyTextBox.Text);
            byte[] encryptedData = EncryptAes(plainText, Key, AesIV);

            // Display the encrypted data in hexadecimal without hyphens
            OutputTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            OutputTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void DecryptAesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;
            Key = Encoding.UTF8.GetBytes(KeyTextBox.Text);
            string decryptedText = AES(cipherText, Key, AesIV);

            // Display the decrypted text
            OutputTextBox.Text = decryptedText;
        }

        private string AES(string cipherText, byte[] Key, byte[] IV)
        {
            // Convert the hexadecimal input to byte array and decrypt it
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            byte[] decryptedData = DecryptAes(encryptedData, Key, IV);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            return decryptedText;
        }

        private void EncryptDesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;
            Key = Encoding.UTF8.GetBytes(KeyTextBox.Text);
            byte[] encryptedData = EncryptDes(plainText, Key, DesIV);

            // Display the encrypted data in hexadecimal without hyphens
            OutputTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            OutputTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void DecryptDesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;
            Key = Encoding.UTF8.GetBytes(KeyTextBox.Text);
            string decryptedText = DES(cipherText, Key, DesIV);

            // Display the decrypted text
            OutputTextBox.Text = decryptedText;
        }

        private string DES(string cipherText, byte[] Key, byte[] IV)
        {
            // Convert the hexadecimal input to byte array and decrypt it
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            byte[] decryptedData = DecryptDes(encryptedData, Key, IV);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            return decryptedText;
        }

        private void EncryptTripleDesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;
            Key = Encoding.UTF8.GetBytes(KeyTextBox.Text);
            byte[] encryptedData = EncryptTripleDes(plainText, Key, TripleDesIV);

            // Display the encrypted data in hexadecimal without hyphens
            OutputTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            OutputTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void DecryptTripleDesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;
            Key = Encoding.UTF8.GetBytes(KeyTextBox.Text);
            string decryptedText = TDES(cipherText, Key, TripleDesIV);

            // Display the decrypted text
            OutputTextBox.Text = decryptedText;
        }

        private string TDES(string cipherText, byte[] Key, byte[] IV)
        {
            // Convert the hexadecimal input to byte array and decrypt it
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            byte[] decryptedData = DecryptTripleDes(encryptedData, Key, IV);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            return decryptedText;
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

            //Another way to convert a hexadecimal string to a byte array
            /*Enumerable.Range(0, hexString.Length / 2)
                .Select(i => Convert.ToByte(hexString.Substring(i * 2, 2), 16))
                .ToArray();*/

        private byte[] EncryptAes(string plainText, byte[] key, byte[] iv)
        {
            // Create an AES algorithm
            using (Aes aesAlg = Aes.Create())
            {
                // Set key, IV, padding mode, and cipher mode for the AES algorithm
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Mode = CipherMode.ECB;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

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

        private byte[] DecryptAes(byte[] cipherText, byte[] key, byte[] iv)
        {
            // Create an AES algorithm
            using (Aes aesAlg = Aes.Create())
            {
                // Set key, IV, padding mode, and cipher mode for the AES algorithm
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Mode = CipherMode.ECB;

                // Create an decryptor using the key and IV
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

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

        private byte[] EncryptDes(string plainText, byte[] key, byte[] iv)
        {
            // Create an DES algorithm
             using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
             {
                 // Set key, IV, padding mode, and cipher mode for the DES algorithm
                 desAlg.Key = key;
                 desAlg.IV = iv;
                 desAlg.Padding = PaddingMode.Zeros;
                 desAlg.Mode = CipherMode.ECB;

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
                // Set key, IV, padding mode, and cipher mode for the DES algorithm
                desAlg.Key = key;
                desAlg.IV = iv;
                desAlg.Padding = PaddingMode.Zeros;
                desAlg.Mode = CipherMode.ECB;

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
                // Set key, IV, padding mode, and cipher mode for the TDES algorithm
                tdesAlg.Key = key;
                tdesAlg.IV = iv;
                tdesAlg.Padding = PaddingMode.Zeros;
                tdesAlg.Mode = CipherMode.ECB;

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

        private byte[] DecryptTripleDes(byte[] cipherText, byte[] key, byte[] iv)
        {
            // Create a TDES algorithm
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                // Set key, IV, padding mode, and cipher mode for the TDES algorithm
                tdesAlg.Key = key;
                tdesAlg.IV = iv;
                tdesAlg.Padding = PaddingMode.Zeros;
                tdesAlg.Mode = CipherMode.ECB;

                //Create an decryptor using the key and IV
                ICryptoTransform decryptor = tdesAlg.CreateDecryptor(tdesAlg.Key, tdesAlg.IV);

                byte[] decryptedBytes;

                //Create a memory stream from the input ciphertext byte array
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    //Create a CryptoStream to read the decrypted data from the memory stream
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

        private byte[] cipher;

        private void FirstEncryptButton_Click(object sender, RoutedEventArgs e)
        {
            // Split the full key into three parts
            Key1 = Encoding.UTF8.GetBytes(KeyTextBoxTDES.Text.Substring(0, 8));
            Key2 = Encoding.UTF8.GetBytes(KeyTextBoxTDES.Text.Substring(8, 8));
            Key3 = Encoding.UTF8.GetBytes(KeyTextBoxTDES.Text.Substring(16, 8));
            string plainText = InputTextBoxTDES.Text;
            byte[] encryptedData = EncryptDes(plainText, Key1, DesIV);

            // Display the encrypted data in hexadecimal without hyphens
            FirstCipherTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            FirstCipherTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void FirstDecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = FirstCipherTextBox.Text;

            // Convert the hexadecimal input to byte array and decrypt
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            byte[] decryptedData = DecryptDes(encryptedData, Key2, DesIV);
            cipher = decryptedData;

            // Display the decrypted data in hexadecimal without hyphens
            SecondCipherTextBox.Text = BitConverter.ToString(decryptedData).Replace("-", ""); ;
            SecondCipherTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void SecondEncryptButton_Click(object sender, RoutedEventArgs e)
        {
            byte[] encryptedData = EncryptDes(cipher, Key3, DesIV);

            // Display the encrypted data in hexadecimal without hyphens
            ThirdCipherTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            ThirdCipherTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void SecondDecryptButton_Click(object sender, RoutedEventArgs e)
        {
            // Split the full key into three parts
            Key1 = Encoding.UTF8.GetBytes(KeyTextBoxTDES2.Text.Substring(0, 8));
            Key2 = Encoding.UTF8.GetBytes(KeyTextBoxTDES2.Text.Substring(8, 8));
            Key3 = Encoding.UTF8.GetBytes(KeyTextBoxTDES2.Text.Substring(16, 8));
            string cipherText = CipherTextBoxTDES.Text;

            // Convert the hexadecimal input to byte array and decrypt
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            byte[] decryptedData = DecryptDes(encryptedData, Key3, DesIV);
            cipher = decryptedData;

            // Display the decrypted data in hexadecimal without hyphens
            FirstResultTextBox.Text = BitConverter.ToString(decryptedData).Replace("-", "");
            FirstResultTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void ThirdEncryptButton_Click(object sender, RoutedEventArgs e)
        {
            byte[] encryptedData = EncryptDes(cipher, Key2, DesIV);

            // Display the encrypted data in hexadecimal without hyphens
            SecondResultTextBox.Text = BitConverter.ToString(encryptedData).Replace("-", "");
            SecondResultTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private void ThirdDecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = SecondResultTextBox.Text;

            // Convert the hexadecimal input to byte array and decrypt
            byte[] encryptedData = ConvertHexStringToByteArray(cipherText);
            byte[] decryptedData = DecryptDes(encryptedData, Key1, DesIV);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);

            // Display the decrypted text
            ThirdResultTextBox.Text = decryptedText;
            ThirdResultTextBox.Foreground = new SolidColorBrush(Colors.Black);
        }

        private byte[] EncryptDes(byte[] plainBytes, byte[] key, byte[] iv)
        {
            // Create an DES algorithm
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                // Set key, IV, padding mode, and cipher mode for the DES algorithm
                desAlg.Key = key;
                desAlg.IV = iv;
                desAlg.Padding = PaddingMode.Zeros;
                desAlg.Mode = CipherMode.ECB;

                // Create an encryptor using the key and IV
                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

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

        private void InputTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(InputTextBox.Text))
            {
                InputTextBox.Visibility = Visibility.Collapsed;
                WatermarkInputTB.Visibility = Visibility.Visible;
            }
        }

        private void WatermarkInputTB_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkInputTB.Visibility = Visibility.Collapsed;
            InputTextBox.Visibility = Visibility.Visible;
            InputTextBox.Focus();
        }

        private void KeyTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(KeyTextBox.Text))
            {
                KeyTextBox.Visibility = Visibility.Collapsed;
                WatermarkKeyTB.Visibility = Visibility.Visible;
            }
        }

        private void WatermarkKeyTB_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkKeyTB.Visibility = Visibility.Collapsed;
            KeyTextBox.Visibility = Visibility.Visible;
            KeyTextBox.Focus();
        }

        private void InputTextBoxTDES_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(InputTextBoxTDES.Text))
            {
                InputTextBoxTDES.Visibility = Visibility.Collapsed;
                WatermarkInputTBTDES.Visibility = Visibility.Visible;
            }
        }

        private void WatermarkInputTBTDES_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkInputTBTDES.Visibility = Visibility.Collapsed;
            InputTextBoxTDES.Visibility = Visibility.Visible;
            InputTextBoxTDES.Focus();
        }

        private void KeyTextBoxTDES_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(KeyTextBoxTDES.Text))
            {
                KeyTextBoxTDES.Visibility = Visibility.Collapsed;
                WatermarkKeyTBTDES.Visibility = Visibility.Visible;
            }
        }

        private void WatermarkKeyTBTDES_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkKeyTBTDES.Visibility = Visibility.Collapsed;
            KeyTextBoxTDES.Visibility = Visibility.Visible;
            KeyTextBoxTDES.Focus();
        }

        private void CipherTextBoxTDES_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(CipherTextBoxTDES.Text))
            {
                CipherTextBoxTDES.Visibility = Visibility.Collapsed;
                WatermarkCipherTBTDES.Visibility = Visibility.Visible;
            }
        }

        private void WatermarkCipherTBTDES_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkCipherTBTDES.Visibility = Visibility.Collapsed;
            CipherTextBoxTDES.Visibility = Visibility.Visible;
            CipherTextBoxTDES.Focus();
        }

        private void KeyTextBoxTDES2_LostFocus(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(KeyTextBoxTDES2.Text))
            {
                KeyTextBoxTDES2.Visibility = Visibility.Collapsed;
                WatermarkKeyTBTDES2.Visibility = Visibility.Visible;
            }
        }

        private void WatermarkKeyTBTDES2_GotFocus(object sender, RoutedEventArgs e)
        {
            WatermarkKeyTBTDES2.Visibility = Visibility.Collapsed;
            KeyTextBoxTDES2.Visibility = Visibility.Visible;
            KeyTextBoxTDES2.Focus();
        }

    }
}
