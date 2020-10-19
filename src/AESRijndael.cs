using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Atomus.Security
{
    /// <summary>
    /// 라인델 AES 암호화
    /// </summary>
    public class AESRijndael : IEncryptor, IDecryptor
    {
        //private string password;
        //private string salt;

        string IEncryptor.Encrypt(string value, string password, string salt, int iterations)
        {
            return Encoding.ASCII.GetString(((IEncryptor)this).Encrypt(Encoding.ASCII.GetBytes(value), Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(salt), iterations));
        }
        string IEncryptor.EncryptToBase64String(string value, string password, string salt, int iterations)
        {
            return Convert.ToBase64String(((IEncryptor)this).Encrypt(Encoding.ASCII.GetBytes(value), Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(salt), iterations));
        }
        byte[] IEncryptor.Encrypt(byte[] value, byte[] password, byte[] salt, int iterations)
        {
            byte[] result;

            try
            {
                using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
                {
                    using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                    {
                        using (MemoryStream memoryStream = new MemoryStream())
                        {
                            using (ICryptoTransform cryptoTransform = rijndaelManaged.CreateEncryptor(rfc2898DeriveBytes.GetBytes(32), rfc2898DeriveBytes.GetBytes(16)))
                            {
                                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                                {
                                    cryptoStream.Write(value, 0, value.Length);
                                    cryptoStream.FlushFinalBlock();

                                    result = memoryStream.ToArray();

                                    cryptoStream.Close();
                                }
                            }
                            memoryStream.Close();
                        }

                        rijndaelManaged.Clear();
                    }
                }

                return result;
            }
            catch (AtomusException exception)
            {
                throw exception;
            }
            catch (Exception exception)
            {
                throw new AtomusException(exception);
            }
        }

        string IDecryptor.Decrypt(string value, string password, string salt, int iterations)
        {
            return Encoding.ASCII.GetString(((IDecryptor)this).Decrypt(Encoding.ASCII.GetBytes(value), Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(salt), iterations));
        }
        string IDecryptor.DecryptFromBase64String(string value, string password, string salt, int iterations)
        {
            return Encoding.ASCII.GetString(((IDecryptor)this).Decrypt(Convert.FromBase64String(value), Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(salt), iterations));
        }
        byte[] IDecryptor.Decrypt(byte[] value, byte[] password, byte[] salt, int iterations)
        {
            Byte[] tmpBytes;
            int cnt;
            byte[] result;

            try
            {
                using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
                {
                    using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                    {
                        using (ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor(rfc2898DeriveBytes.GetBytes(32), rfc2898DeriveBytes.GetBytes(16)))
                        {
                            using (MemoryStream memoryStream = new MemoryStream(value))
                            {
                                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                                {
                                    //cryptoStream.Write(value, 0, value.Length);
                                    //cryptoStream.FlushFinalBlock();

                                    //result = memoryStream.ToArray();

                                    //cryptoStream.Close();

                                    tmpBytes = new Byte[value.Length + 100];
                                    cnt = cryptoStream.Read(tmpBytes, 0, tmpBytes.Length);
                                    cryptoStream.Close();

                                    result = new byte[cnt];

                                    Array.Copy(tmpBytes, result, cnt);
                                }

                                memoryStream.Close();
                            }
                        }

                        rijndaelManaged.Clear();
                    }
                }

                return result;
            }
            catch (AtomusException _Exception)
            {
                throw _Exception;
            }
            catch (Exception _Exception)
            {
                throw new AtomusException(_Exception);
            }
        }
    }
}