using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int theMaxLength = Math.Min(plainText.Length, cipherText.Length);

            for (int key = 1; key <= theMaxLength; key++)
            {
                string decryptedText = Decrypt(cipherText, key);


                if (decryptedText.Length > plainText.Length)
                {
                    decryptedText = decryptedText.Substring(0, plainText.Length);
                }

                if (decryptedText.Equals(plainText, StringComparison.InvariantCultureIgnoreCase))
                {
                    return key;
                }
            }

            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToUpper();

            int cols = (int)Math.Ceiling((double)cipherText.Length / key);
            char[,] array = new char[key, cols];

            // row-wise
            int index = 0;
            for (int i = 0; i < key; ++i)
            {
                for (int j = 0; j < cols; ++j)
                {
                    array[i, j] = index < cipherText.Length ? cipherText[index++] : ' ';
                }
            }

            // column-wise 
            string plaintext = "";
            for (int j = 0; j < cols; ++j)
            {
                for (int i = 0; i < key; ++i)
                {
                    plaintext += array[i, j];
                }
            }

            return plaintext.Trim();
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToUpper();

            int columns = (int)Math.Ceiling((double)plainText.Length / key);
            char[,] arr = new char[key, columns];

            int index = 0;
            for (int j = 0; j < columns; j++)
            {
                for (int i = 0; i < key; i++)
                {
                    if (index < plainText.Length)
                    {
                        if (true)
                        {
                            arr[i, j] = plainText[index++];
                        }
                    }
                    else
                    {
                        arr[i, j] = ' ';
                    }
                }
            }


            string cipherText = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (arr[i, j] != ' ')
                    {
                        cipherText += arr[i, j];
                    }
                }
            }

            return cipherText.Trim();
        }
    }
}
