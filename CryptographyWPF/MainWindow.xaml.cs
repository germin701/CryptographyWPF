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

        /*private static readonly byte[] TripleDesKey = Encoding.UTF8.GetBytes("ABCDEF1234567890UVWXYZXY");  // 192 bits (24 bytes)
        private static readonly byte[] TripleDesIV = Encoding.UTF8.GetBytes("ZYXWVUT0987654321");  // 64 bits (8 bytes)*/

        public MainWindow()
        {
            InitializeComponent();
        }

        private void EncryptAesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;
            byte[] encryptedData = EncryptAes(plainText, AesKey, AesIV);
            OutputTextBox.Text = Convert.ToBase64String(encryptedData);
        }

        private void DecryptAesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;
            byte[] encryptedData = Convert.FromBase64String(cipherText);
            string decryptedText = DecryptAes(encryptedData, AesKey, AesIV);
            OutputTextBox.Text = decryptedText;
        }

        private void EncryptDesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;
            byte[] encryptedData = EncryptDes(plainText, DesKey, DesIV);
            OutputTextBox.Text = Convert.ToBase64String(encryptedData);
        }

        private void DecryptDesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;
            byte[] encryptedData = Convert.FromBase64String(cipherText);
            string decryptedText = DecryptDes(encryptedData, DesKey, DesIV);
            OutputTextBox.Text = decryptedText;
        }

        private void EncryptTripleDesButton_Click(object sender, RoutedEventArgs e)
        {
            string plainText = InputTextBox.Text;
            /*byte[] encryptedData = EncryptTripleDes(plainText, TripleDesKey, TripleDesIV);
            OutputTextBox.Text = Convert.ToBase64String(encryptedData);*/
        }

        private void DecryptTripleDesButton_Click(object sender, RoutedEventArgs e)
        {
            string cipherText = OutputTextBox.Text;
            /*byte[] encryptedData = Convert.FromBase64String(cipherText);
            string decryptedText = DecryptTripleDes(encryptedData, TripleDesKey, TripleDesIV);
            OutputTextBox.Text = decryptedText;*/
        }

        private byte[] EncryptAes(string plainText, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
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
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
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
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.IV = iv;

                ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, desAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        private string DecryptDes(byte[] cipherText, byte[] key, byte[] iv)
        {
            using (DESCryptoServiceProvider desAlg = new DESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.IV = iv;

                ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        /*private byte[] EncryptTripleDes(string plainText, byte[] key, byte[] iv)
        {
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                tdesAlg.Key = key;
                tdesAlg.IV = iv;

                ICryptoTransform encryptor = tdesAlg.CreateEncryptor(tdesAlg.Key, tdesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
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
            using (TripleDESCryptoServiceProvider tdesAlg = new TripleDESCryptoServiceProvider())
            {
                tdesAlg.Key = key;
                tdesAlg.IV = iv;

                ICryptoTransform decryptor = tdesAlg.CreateDecryptor(tdesAlg.Key, tdesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }*/
    }
}
