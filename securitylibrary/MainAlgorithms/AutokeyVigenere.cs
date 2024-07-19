using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            //throw new NotImplementedException();

            char[] alphabets = { 'A', 'B', 'C', 'D',
            'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L',
            'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X',
            'Y', 'Z' };


            char[,] matrix = new char[26, 26];

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = alphabets[(j + i) % 26];
                }
            }
            string key = "";
            for (int i = 0; i <= 26; i++)
            {
                int plainIndex = Array.IndexOf(alphabets, Char.ToUpper(plainText[i]));
                for (int j = 0; j < 26; j++)
                {
                    if (matrix[plainIndex, j] == cipherText[i])
                    {
                        key += alphabets[j];
                        break;
                    }
                }
            }

            string shortKey = "";
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == Char.ToUpper(plainText[0]) && key[i + 1] == Char.ToUpper(plainText[1]))
                {
                    for (int j = 0; j < i; j++)
                    {
                        shortKey += key[j];
                    }
                    break;
                }

            }

            return shortKey.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {

            //throw new NotImplementedException();
            

            string plain = "";
            char[] alphabets = {
            'A', 'B', 'C', 'D',
            'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L',
            'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X',
            'Y', 'Z'
        };

            char[,] matrix = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = alphabets[(j + i) % 26];
                }
            }

            string newKey = key;

            do
            {
                plain = ""; 

                for (int i = 0; i < newKey.Length; i++)
                {
                    int keyIndex = Array.IndexOf(alphabets, Char.ToUpper(newKey[i]));
                    for (int j = 0; j < 26; j++)
                    {
                        if (matrix[j, keyIndex] == cipherText[i])
                        {
                            plain += alphabets[j];
                            break;
                        }
                    }
                }

                int n = cipherText.Length - key.Length;

            
                newKey += plain[newKey.Length - key.Length];

            } while (cipherText.Length != newKey.Length);

            plain = "";
            for (int i = 0; i < newKey.Length; i++)
            {
                int keyIndex = Array.IndexOf(alphabets, Char.ToUpper(newKey[i]));
                for (int j = 0; j < 26; j++)
                {
                    if (matrix[j, keyIndex] == cipherText[i])
                    {
                        plain += alphabets[j];
                        break;
                    }
                }
            }
            
        

           return plain.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {

            //throw new NotImplementedException();
            char[] alphabets = { 'A', 'B', 'C', 'D',
            'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L',
            'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T',
            'U', 'V', 'W', 'X',
            'Y', 'Z' };


            char[,] matrix = new char[26, 26];

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = alphabets[(j + i) % 26];
                }
            }

            

            string newKey = key;
            int n = plainText.Length - key.Length;

            for (int j = 0; j < n; j++)
            {
                newKey += plainText[j];
            }
            

            string result = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = char.ToUpper(plainText[i]);
                char keyChar = char.ToUpper(newKey[i]);

                int plainIndex = Array.IndexOf(alphabets, plainChar);
                int keyIndex = Array.IndexOf(alphabets, keyChar);

                

                char encryptedChar = matrix[plainIndex, keyIndex];

                result += encryptedChar;
            }
            return result.ToUpper();

        }
    }
}
