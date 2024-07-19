using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            //throw new NotImplementedException();
            List<int> key = generateKey(ref plainText, ref cipherText);
            if (key != null)
            {
                return key;
               
            }
            
            else
            {
                throw new InvalidAnlysisException(); 
            }
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            //throw new NotImplementedException();
            List<int> plain = new List<int>() { };

            int keyLen = key.Count;
            int size = GetSquareMatrixSize(ref keyLen);
            //Console.WriteLine("size: " + size);

            int[,] keyMatrix = dCreateMatrixFromList(ref size, ref size, ref key);


            int[,] newKeyMatrix = new int[size, size];
            int[,] matrixOfCofactors = new int[size, size];
            int[,] transposedMatrix = new int[size, size];
            int[,] newTransposedMatrix = new int[size, size];

            if (size == 2)
            {
                newKeyMatrix = Inverse2by2Matrix(ref keyMatrix);

                for (int i = 0; i < cipherText.Count / size; i++)
                {
                    int index = i * size;
                    int[,] colVector = OneColumn(ref size, ref cipherText, ref index);


                    List<int> result = MatrixMultiplication(ref newKeyMatrix, ref colVector);

                    for (int j = 0; j < result.Count; j++)
                    {
                        if (result[j] % 26 >= 0)
                        {
                            plain.Add(result[j] % 26);
                        }
                        else if (result[j] % 26 < 0)
                        {
                            plain.Add((result[j] % 26) + 26);
                        }

                    }

                }

                return plain;
            }
            else if (size == 3)
            {
                for (int i = 0; i < size; i++)
                {
                    for (int j = 0; j < size; j++)
                    {
                        int[,] minor = minorMatrix(keyMatrix, i, j);

                        if ((i + j) % 2 == 0)
                        {
                            matrixOfCofactors[i, j] = calculateCofactors(minor);
                        }
                        else
                        {
                            matrixOfCofactors[i, j] = -1 * calculateCofactors(minor);
                        }

                    }
                }

                transposedMatrix = transpose(matrixOfCofactors);

                newTransposedMatrix = Inverse3by3Matrix(ref keyMatrix, ref transposedMatrix);

                for (int i = 0; i < cipherText.Count / size; i++)
                {
                    int index = i * size;
                    int[,] colVector = OneColumn(ref size, ref cipherText, ref index);

                    List<int> result = MatrixMultiplication(ref newTransposedMatrix, ref colVector);
                    for (int j = 0; j < result.Count; j++)
                    {
                        if (result[j] % 26 >= 0)
                        {
                            plain.Add(result[j] % 26);
                        }
                        else if (result[j] % 26 < 0)
                        {
                            plain.Add((result[j] % 26) + 26);
                        }

                    }

                }

                return plain;

            }
            return plain;
        }
        int GetSquareMatrixSize(ref int count)
        {
            int size = 0;
            while (size * size < count)
            {
                size++;
            }
            return size;
        }
       
        int[,] Inverse2by2Matrix(ref int[,] keyMatrix)
        {
            int mFraction = 1 / ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[0, 1] * keyMatrix[1, 0]));
            
            int a = keyMatrix[0, 0];
            int d = keyMatrix[1, 1];
            keyMatrix[0, 0] = d;
            keyMatrix[1, 1] = a;
            keyMatrix[0, 1] = keyMatrix[0, 1] * -1;
            keyMatrix[1, 0] = keyMatrix[1, 0] * -1;

            int rows = keyMatrix.GetLength(0);
            int cols = keyMatrix.GetLength(1);

            if (mFraction == 0)
            {
                throw new DivideByZeroException("Divide by 0 is not allowed!!");
            }

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    keyMatrix[i, j] = keyMatrix[i, j] * mFraction;
                  
                }
            }

            return keyMatrix;
        }
        int[,] OneColumn(ref int no_of_rows, ref List<int> list, ref int startingIndex)
        {
            int[,] SingleCol = new int[no_of_rows, 1];
            for (int i = 0, j = startingIndex; i < no_of_rows; i++, j++)
            {
                SingleCol[i, 0] = list[j];
            }
            return SingleCol;
        }
        List<int> MatrixMultiplication(ref int[,] matrix1, ref int[,] matrix2)
        {
            int rows1 = matrix1.GetLength(0);
            int cols1 = matrix1.GetLength(1);
            int rows2 = matrix2.GetLength(0);
            int cols2 = matrix2.GetLength(1);

            List<int> result = new List<int> { };

            for (int i = 0; i < rows1; i++)
            {
                for (int j = 0; j < cols2; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < cols1; k++)
                    {
                        sum += matrix1[i, k] * matrix2[k, j];
                    }
                    result.Add(sum);
                }
            }

            return result;
        }

        int[,] transpose(int[,] matrix)
        {
            int[,] transposedMatrix = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    transposedMatrix[j, i] = matrix[i, j];
                }
            }
            return transposedMatrix;
        }
        int calculateCofactors(int[,] matrix)
        {
            int result;
            int x = matrix[0, 0] * matrix[1, 1];
            int y = matrix[0, 1] * matrix[1, 0];
            result = x - y;

            return result;
        }
        int[,] minorMatrix(int[,] matrix, int rowIndex, int colIndex)
        {
            int[,] minor = new int[2, 2];
            int row = 0;
            for (int i = 0; i < 3; i++)
            {
                int col = 0;
                if (i == rowIndex)
                {
                    continue;
                }
                for (int j = 0; j < 3; j++)
                {
                    if (j == colIndex)
                    {
                        continue;
                    }
                    minor[row, col] = matrix[i, j];
                    col++;
                }
                row++;
            }
            return minor;
        }

        int[,] Inverse3by3Matrix(ref int[,] matrix, ref int[,] transMatrix)
        {
            int determinant = matrix[0, 0] * ((matrix[1, 1] * matrix[2, 2]) - (matrix[2, 1] * matrix[1, 2]))
                - matrix[0, 1] * ((matrix[1, 0] * matrix[2, 2]) - (matrix[2, 0] * matrix[1, 2]))
                + matrix[0, 2] * ((matrix[1, 0] * matrix[2, 1]) - (matrix[2, 0] * matrix[1, 1]));

            while (determinant < 0)
            {
                determinant = (determinant % 26 + 26) % 26;
            }

            int modularInverse = FindModularInverse(determinant);

            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);

            int[,] newMatrix = new int[rows, cols];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {

                    newMatrix[i, j] = transMatrix[i, j] * modularInverse;
                }
            }

            Console.WriteLine(determinant);
            Console.WriteLine(1 / determinant);
            return newMatrix;
        }

        int FindModularInverse(int determinant)
        {

            int inverse = 0;


            for (int i = 1; i < 26; i++)
            {

                if ((determinant * i) % 26 == 1)
                {
                    inverse = i;
                    break;
                }
            }

            return inverse;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> cipher = new List<int>() { };
            int keyLen = key.Count;
            int size = GetSquareMatrixSize(ref keyLen);
            int[,] keyMatrix = dCreateMatrixFromList(ref size, ref size, ref key);

            for (int i = 0; i < plainText.Count / size; i++)
            {
                int index = i * size;
                int[,] colVector = OneColumn(ref size, ref plainText, ref index);

                List<int> result = MatrixMultiplication(ref keyMatrix, ref colVector);
                for (int j = 0; j < result.Count; j++)
                {
                    cipher.Add(result[j] % 26);
                }

            }
            return cipher;
        }

        int[,] dCreateMatrixFromList(ref int no_of_rows, ref int no_of_cols, ref List<int> given_list)
        {
            int[,] matrix = new int[no_of_rows, no_of_cols];

            for (int i = 0; i < no_of_rows; i++)
            {
                for (int j = 0; j < no_of_cols; j++)
                {
                    matrix[i, j] = given_list[(i * no_of_cols) + j];
                }
            }

            return matrix;
        }
        int[,] aCreateMatrixFromList(ref int no_of_rows, ref int no_of_cols, ref List<int> given_list)
        {
            int[,] matrix = new int[no_of_rows, no_of_cols];

            for (int i = 0; i < no_of_rows; i++)
            {
                for (int j = 0; j < no_of_cols; j++)
                {
                    matrix[i, j] = given_list[(j * no_of_cols) + i];
                }
            }

            return matrix;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            List<int> plain = convertToNum(ref plainText);
            List<int> keyInt = convertToNum(ref key);
            List<int> cipher = new List<int>() { };
            int n = keyInt.Count;
            int size = GetSquareMatrixSize(ref n);
            int[,] keyMatrix = dCreateMatrixFromList(ref size, ref size, ref keyInt);

            for (int i = 0; i < plain.Count / size; i++)
            {
                int x = i * size;
                int[,] colVector = OneColumn(ref size, ref plain, ref x);

                List<int> result = MatrixMultiplication(ref keyMatrix, ref colVector);
                for (int j = 0; j < result.Count; j++)
                {
                    cipher.Add(result[j] % 26);
                }

            }
            return convertToString(ref cipher);
        }

        List<int> convertToNum(ref string input)
        {
            List<int> num = new List<int> { };
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < input.Length; i++)
            {
                for (int j = 0; j < alphabets.Length; j++)
                {
                    if (input[i] == alphabets[j])
                    {
                        num.Add(j);
                    }
                }
            }
            return num;
        }
        string convertToString(ref List<int> input)
        {
            string cipher = "";
            string alphabets = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < input.Count; i++)
            {
                cipher += alphabets[input[i]];
            }
            return cipher;
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            // throw new NotImplementedException();
            List<int> key = new List<int>() { };

            int size = 3;
            

            int[,] keyMatrix = aCreateMatrixFromList(ref size, ref size, ref plain3);
       

            int[,] cipherMatrix = aCreateMatrixFromList(ref size, ref size, ref cipher3);
           


            int[,] newKeyMatrix = new int[size, size];
            int[,] matrixOfCofactors = new int[size, size];
            int[,] transposedMatrix = new int[size, size];
            int[,] newTransposedMatrix = new int[size, size];


            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    int[,] minor = minorMatrix(keyMatrix, i, j);

                    if ((i + j) % 2 == 0)
                    {
                        matrixOfCofactors[i, j] = calculateCofactors(minor);
                    }
                    else
                    {
                        matrixOfCofactors[i, j] = -1 * calculateCofactors(minor);
                    }

                }
            }

            transposedMatrix = transpose(matrixOfCofactors);
    

            newTransposedMatrix = Inverse3by3Matrix(ref keyMatrix, ref transposedMatrix);
          

            List<int> newTransposedList = MatrixToList(newTransposedMatrix);
            

            for (int i = 0; i < cipher3.Count / size; i++)
            {
                int index = i * size;
            
                int[,] colVector = OneColumn(ref size, ref newTransposedList, ref index);
                int s = 1;
               

                List<int> result = MatrixMultiplication(ref cipherMatrix, ref colVector);
              

                for (int j = 0; j < result.Count; j++)
                {
                    if (result[j] % 26 >= 0)
                    {
                        key.Add(result[j] % 26);
                    }
                    else if (result[j] % 26 < 0)
                    {
                        key.Add((result[j] % 26) + 26);
                    }

                }

            }
      
            int[,] matrix = ListToMatrix(key);

            
            List<int> rowBasedList = MatrixToList(matrix);

            return rowBasedList;
            
        }
         int[,] ListToMatrix(List<int> list)
        {
            int[,] matrix = new int[3, 3];
            int index = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    matrix[i, j] = list[index++];
                }
            }
            return matrix;
        }
        static List<int> MatrixToList(int[,] matrix)
        {
            List<int> list = new List<int>();

            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    list.Add(matrix[j, i]);
                    //list.Add(matrix[i, j]);
                }
            }

            return list;

        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        List<int> generateKey(ref List<int> plainText, ref List<int> cipherText)
        {
            int alphaLen = 26;
            for (int zeroZero = 0; zeroZero < alphaLen; zeroZero = zeroZero + 1)
            {
                for (int zeroOne = 0; zeroOne < alphaLen; zeroOne = zeroOne + 1)
                {
                    for (int oneZero = 0; oneZero < alphaLen; oneZero = oneZero + 1)
                    {
                        for (int oneOne = 0; oneOne < alphaLen; oneOne = oneOne + 1)
                        {
                            List<int> generatedKey = new List<int>(new[] { zeroZero, zeroOne, oneZero, oneOne });

                            List<int> generatedCipher = Encrypt(plainText, generatedKey);

                            bool areSimilar = true;

                            if (generatedCipher.Count == cipherText.Count)
                            {
                                for (int i = 0; i < generatedCipher.Count; i++)
                                {
                                    if (generatedCipher[i] != cipherText[i])
                                    {
                                        areSimilar = false;
                                        break;
                                    }

                                }
                            }
                            else
                            {
                                areSimilar = false;
                            }

                            if (areSimilar == true)
                            {
                                return generatedKey;
                            }

                        }

                    }

                }

            }
            return null;


        }


    }
}

