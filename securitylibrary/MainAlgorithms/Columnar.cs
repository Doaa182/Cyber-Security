using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            int theRows = 0;
            int theColumns = 0;
            int indexer = 0;

            cipherText = cipherText.ToLower();

            for (int i = 2; i < 8; i++)
            {
                if (plainText.Length % i == 0)
                {
                    theColumns = i;
                }
            }

            theRows = plainText.Length / theColumns;

            char[,] plainMatrix = new char[theRows, theColumns];
            char[,] cipherMatrix = new char[theRows, theColumns];


            List<int> key = new List<int>(theColumns);

            for (int i = 0; i < theRows; i++)
            {
                for (int j = 0; j < theColumns; j++)
                {
                    if (indexer < plainText.Length)
                    {
                        plainMatrix[i, j] = plainText[indexer++];
                    }

                }
            }

            indexer = 0;
            for (int i = 0; i < theColumns; i++)
            {
                for (int j = 0; j < theRows; j++)
                {
                    if (indexer < plainText.Length)
                    {
                        cipherMatrix[j, i] = cipherText[indexer];
                        indexer++;
                    }
                }
            }

            int check = 0;
            for (int i = 0; i < theColumns; i++)
            {
                for (int k = 0; k < theColumns; k++)
                {
                    for (int j = 0; j < theRows; j++)
                    {
                        if (plainMatrix[j, i] == cipherMatrix[j, k])
                        {
                            check++;
                        }
                        if (check == theRows)
                            key.Add(k + 1);
                    }
                    check = 0;
                }
            }

            if (key.Count == 0)
            {
                for (int i = 0; i < theColumns + 2; i++)
                {
                    key.Add(0);
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            int numColumns = key.Count;


            int[] rowsPerColumn = new int[numColumns];


            int rowIndex = 0;
            foreach (char c in cipherText)
            {
                int colIndex = key[rowIndex % numColumns];
                rowsPerColumn[colIndex - 1]++;
                rowIndex++;
            }


            char[,] arr = new char[numColumns, rowsPerColumn.Max()];
            int textIndex = 0;


            foreach (int colIndex in key.OrderBy(k => k))
            {
                int rowCount = rowsPerColumn[colIndex - 1];

                for (int i = 0; i < rowCount; i++)
                {
                    if (textIndex < cipherText.Length)
                    {
                        arr[colIndex - 1, i] = cipherText[textIndex++];
                    }
                    else
                    {
                        arr[colIndex - 1, i] = ' ';
                    }
                }
            }


            string decryptedText = "";
            for (int i = 0; i < arr.GetLength(1); i++)
            {
                foreach (int colIndex in key)
                {

                    if (arr[colIndex - 1, i] != ' ')
                    {
                        decryptedText += arr[colIndex - 1, i];
                    }
                }
            }


            return decryptedText;

        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToUpper();
            int columns = key.Max();
            int row = (int)Math.Ceiling((double)plainText.Length / columns);

            char[,] arr = new char[row, columns];
            int indexer = 0;


            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (indexer < plainText.Length)
                    {
                        arr[i, j] = plainText[indexer++];
                    }
                    else
                    {
                        arr[i, j] = ' ';
                    }
                }
            }


            string[] columnsText = new string[columns];
            for (int colIndex = 1; colIndex <= columns; colIndex++)
            {
                string columnText = "";
                foreach (int rowIndex in Enumerable.Range(0, row))
                {
                    char c = arr[rowIndex, key.IndexOf(colIndex)];
                    if (c != ' ')
                    {
                        columnText += c;
                    }
                }
                columnsText[colIndex - 1] = columnText;
            }


            string encryptedText = string.Join("", columnsText);

            encryptedText = encryptedText.ToUpper();
            return encryptedText;
        }
    }
}
