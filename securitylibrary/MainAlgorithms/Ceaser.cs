using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();

            char[] arr = new char[26];
            for (char i = 'a'; i <= 'z'; i++)
            {
                int index = i - 'a';
                arr[index] = i;
            }

            char[] encryptedWord = new char[plainText.Length];
            for (int j = 0; j < plainText.Length; j++)
            {
                int letterIndex = Array.IndexOf(arr, plainText[j]);
                if (letterIndex != -1)
                {
                    int enceyptedIndex = (letterIndex + key) % 26;
                    encryptedWord[j] = arr[enceyptedIndex];

                }
                else
                {
                    encryptedWord[j] = plainText[j];
                }

            }
            return new string(encryptedWord);
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();

            char[] arr = new char[26];
            for (char i = 'a'; i <= 'z'; i++)
            {
                int index = i - 'a';
                arr[index] = i;
            }

            char[] decryptedWord = new char[cipherText.Length];
            for (int j = 0; j < cipherText.Length; j++)
            {
                char currentChar = char.ToLower(cipherText[j]);
                int letterIndex = Array.IndexOf(arr, currentChar);
                if (letterIndex != -1)
                {
                    int decryptedIndex = (letterIndex - key + 26) % 26;
                    char decryptedChar = arr[decryptedIndex];
                    decryptedWord[j] = char.IsUpper(cipherText[j]) ? char.ToUpper(decryptedChar) : decryptedChar;
                }
                else
                {
                    decryptedWord[j] = cipherText[j];
                }
            }
            return new string(decryptedWord);
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            for (int key = 0; key < 26; key++)
            {

                string decryptedWord = Decrypt(cipherText, key);
                if (decryptedWord.Equals(plainText)) { return key; }

            }

            return -1;
        }
    }
}