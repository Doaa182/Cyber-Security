using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            string newKey = key.Replace("J", "I");

            char[,] matrix = new char[5, 5];
            string alphabet = newKey + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            char[] withoutRepeat = new char[26];
            int index = 0;
            bool flag;

            for (int i = 0; i < alphabet.Length; i++)
            {
                if (i == 0) { withoutRepeat[index++] = alphabet[i]; }

                else
                {
                    flag = false;
                    for (int j = 0; j < index; j++)
                    {
                        if (alphabet[i] == withoutRepeat[j]) { flag = true; break; }
                    }
                    if (flag == false) { withoutRepeat[index++] = alphabet[i]; }
                }
            }

            index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = withoutRepeat[index++];
                }
            }


            string plainText = "";

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char v1 = cipherText[i];
                char v2 = cipherText[i + 1];

                Tuple<int, int> firstPos = findPos(ref matrix, ref v1);
                Tuple<int, int> secondPos = findPos(ref matrix, ref v2);
                if (firstPos.Item1 == secondPos.Item1)
                {
                    plainText += matrix[firstPos.Item1, (((firstPos.Item2 - 1) + 5) % 5)] + "" + matrix[secondPos.Item1, (((secondPos.Item2 - 1) + 5) % 5)];
                }
                else if (firstPos.Item2 == secondPos.Item2)
                {
                    plainText += matrix[(((firstPos.Item1 - 1) + 5) % 5), firstPos.Item2] + "" + matrix[(((secondPos.Item1 - 1) + 5) % 5), secondPos.Item2];
                }
                else if (firstPos.Item1 != secondPos.Item1 && firstPos.Item2 != secondPos.Item2)
                {
                    plainText += matrix[firstPos.Item1, secondPos.Item2] + "" + matrix[secondPos.Item1, firstPos.Item2];
                }
            }

            if (plainText.EndsWith("X")) { plainText = plainText.Substring(0, plainText.Length - 1); }
          
            for (int i = 0; i < plainText.Length; i += 1)
            {
                if ((i + 2) < plainText.Length && (i + 1) < plainText.Length && plainText[i + 1] == 'X' && (i + 1) % 2 != 0)//32
                {
                    if (plainText[i] == plainText[i + 2]) { plainText = plainText.Substring(0, i + 1) + '$' + plainText.Substring(i + 2); }
                    
                }
            }
            plainText = plainText.Replace("$", "");

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
           
            plainText = plainText.ToUpper();
            key = key.ToUpper();

            string newKey = key.Replace("J", "I");
            string alphabet = newKey + "ABCDEFGHIKLMNOPQRSTUVWXYZ";

            char[,] matrix = new char[5, 5];
            char[] withoutRepeat = new char[26];
            int index = 0;
            bool flag;

            for (int i = 0; i < alphabet.Length; i++)
            {
                if (i == 0) { withoutRepeat[index++] = alphabet[i]; }
               
                else
                {
                    flag = false;
                    for (int j = 0; j < index; j++)
                    {
                        if (alphabet[i] == withoutRepeat[j]) { flag = true; break; }
                       

                    }
                    if (flag == false) { withoutRepeat[index++] = alphabet[i]; }
                   

                }
            }

            index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++) { matrix[i, j] = withoutRepeat[index++]; }
               
            }

            string cipherText = "";
            for (int i = 0; i < plainText.Length; i += 2)
            {
                char v1 = plainText[i];
                char v2;

                if ((i + 1) < plainText.Length)
                {
                    v2 = plainText[i + 1];

                    if (v1 == v2) { v2 = 'X'; i = i - 1; }
                   
                }
                else { v2 = 'X'; }

                Tuple<int, int> firstPos = findPos(ref matrix, ref v1);
                Tuple<int, int> secondPos = findPos(ref matrix, ref v2);

                if (firstPos.Item1 == secondPos.Item1)
                {
                    cipherText += matrix[firstPos.Item1, ((firstPos.Item2 + 1) % 5)] + "" + matrix[secondPos.Item1, ((secondPos.Item2 + 1) % 5)];
                }
                else if (firstPos.Item2 == secondPos.Item2)
                {
                    cipherText += matrix[((firstPos.Item1 + 1) % 5), firstPos.Item2] + "" + matrix[((secondPos.Item1 + 1) % 5), secondPos.Item2];
                }
                else if (firstPos.Item1 != secondPos.Item1 && firstPos.Item2 != secondPos.Item2)
                {
                    cipherText += matrix[firstPos.Item1, secondPos.Item2] + "" + matrix[secondPos.Item1, firstPos.Item2];
                }
            }

            return cipherText;
        }

        public Tuple<int, int> findPos(ref char[,] matrix, ref char c)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == c)
                    {
                        return Tuple.Create(i, j);
                    }

                }
            }
            return null;
        }
    }
}