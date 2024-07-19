using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            int[,] PC_1 = new int[8, 7] {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };

            int[,] IP = new int[8, 8] {
            { 58, 50, 42, 34, 26, 18, 10, 2 },
            { 60, 52, 44, 36, 28, 20, 12, 4 },
            { 62, 54, 46, 38, 30, 22, 14, 6 },
            { 64, 56, 48, 40, 32, 24, 16, 8 },
            { 57, 49, 41, 33, 25, 17, 9, 1 },
            { 59, 51, 43, 35, 27, 19, 11, 3 },
            { 61, 53, 45, 37, 29, 21, 13, 5 },
            { 63, 55, 47, 39, 31, 23, 15, 7 } };

            Dictionary<int, string> binary1 = new Dictionary<int, string>()
        {
            {0,"0000" },
            {1,"0001" },
            {2,"0010" },
            {3,"0011" },
            {4,"0100" },
            {5,"0101" },
            {6,"0110" },
            {7,"0111" },
            {8,"1000" },
            {9,"1001" },
            {10,"1010" },
            {11,"1011" },
            {12,"1100" },
            {13,"1101" },
            {14,"1110" },
            {15,"1111" }
        };

            int[,] PermutationAfterXOR = new int[,]
            {
       { 16,  7, 20, 21 },
       { 29, 12, 28, 17 },
       {  1, 15, 23, 26 },
       { 5, 18, 31, 10 },
       { 2,  8, 24, 14 },
       { 32, 27,  3,  9 },
       { 19, 13, 30,  6 },
       { 22, 11,  4, 25 }};

            int[,] inv_IP = new int[8, 8] {
    { 40, 8, 48, 16, 56, 24, 64, 32 },
    { 39, 7, 47, 15, 55, 23, 63, 31 },
    { 38, 6, 46, 14, 54, 22, 62, 30 },
    { 37, 5, 45, 13, 53, 21, 61, 29 },
    { 36, 4, 44, 12, 52, 20, 60, 28 },
    { 35, 3, 43, 11, 51, 19, 59, 27 },
    { 34, 2, 42, 10, 50, 18, 58, 26 },
    { 33, 1, 41,  9, 49, 17, 57, 25 }
};
            string keyhexa = key;
            string cipherhexa = cipherText;

            string key_64bit = HexaToBin(keyhexa);
            string cipher_64bit = HexaToBin(cipherhexa);

            string key_56bit = Permutaion(PC_1, key_64bit, 8, 7);
            string new_cipher_64bit = Permutaion(IP, cipher_64bit, 8, 8);
            string keyLeftPart = splitLeft(key_56bit);


            string keyRightPart = splitRight(key_56bit);

            string cipherLeftPart = splitLeft(new_cipher_64bit);

            string cipherRightPart = splitRight(new_cipher_64bit);

            int[] shiftAmountArr = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            string[] keysArr_48bit = new string[shiftAmountArr.Length + 1];

            string shiftedLeftBin = keyLeftPart;
            string shiftedRightBin = keyRightPart;
            keysArr_48bit[0] = shiftedLeftBin + shiftedRightBin;

            string[] R = new string[shiftAmountArr.Length + 1];
            string[] L = new string[shiftAmountArr.Length + 1];


            R[0] = cipherRightPart;
            L[0] = cipherLeftPart;

            string cipherAfterXOR;
            int rndNum, key1;
            char[,] RMatrix;
            string Expanded;
            int shiftAmount;
            string s;
            string XORresult;
            string subsResult;
            char[,] XORresultMtrx;

            for (int i = 0; i < 16; i++)
            {
                //key
                shiftAmount = shiftAmountArr[i];
                shiftedLeftBin = BinShiftLeft(shiftedLeftBin, shiftAmount);
                shiftedRightBin = BinShiftLeft(shiftedRightBin, shiftAmount);
                s = shiftedLeftBin + shiftedRightBin;
                keysArr_48bit[i] = Permutaion(PC_2, s, 8, 6);
            }

            for (rndNum = 1, key1 = 15; rndNum < shiftAmountArr.Length; rndNum++, key1--)
            {
                L[rndNum] = R[rndNum - 1];

                RMatrix = StrToMtrx(R[rndNum - 1], 8, 4);
                Expanded = expansionPermutation(RMatrix);

                XORresult = XOR(keysArr_48bit[key1], Expanded);
                XORresultMtrx = StrToMtrx(XORresult, 8, 6);
                subsResult = substitution(XORresultMtrx, binary1);
                cipherAfterXOR = Permutaion(PermutationAfterXOR, subsResult, 8, 4);
                R[rndNum] = XOR(L[rndNum - 1], cipherAfterXOR);
            }

            rndNum = 16;
            L[rndNum] = R[rndNum - 1];

            RMatrix = StrToMtrx(R[rndNum - 1], 8, 4);
            Expanded = expansionPermutation(RMatrix);
            XORresult = XOR(keysArr_48bit[0], Expanded);
            XORresultMtrx = StrToMtrx(XORresult, 8, 6);
            subsResult = substitution(XORresultMtrx, binary1);
            cipherAfterXOR = Permutaion(PermutationAfterXOR, subsResult, 8, 4);

            R[rndNum] = XOR(L[rndNum - 1], cipherAfterXOR);
            R[16] = XOR(L[15], cipherAfterXOR);

            string finalPlain = R[16] + L[16];
            finalPlain = Permutaion(inv_IP, finalPlain, 8, 8);
            finalPlain = BinToHexa(finalPlain);
            return finalPlain;
        }

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            

            int[,] PC_1 = new int[8, 7] {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };

            int[,] IP = new int[8, 8] {
            { 58, 50, 42, 34, 26, 18, 10, 2 },
            { 60, 52, 44, 36, 28, 20, 12, 4 },
            { 62, 54, 46, 38, 30, 22, 14, 6 },
            { 64, 56, 48, 40, 32, 24, 16, 8 },
            { 57, 49, 41, 33, 25, 17, 9, 1 },
            { 59, 51, 43, 35, 27, 19, 11, 3 },
            { 61, 53, 45, 37, 29, 21, 13, 5 },
            { 63, 55, 47, 39, 31, 23, 15, 7 } };

            Dictionary<int, string> binary1 = new Dictionary<int, string>()
        {
            {0,"0000" },
            {1,"0001" },
            {2,"0010" },
            {3,"0011" },
            {4,"0100" },
            {5,"0101" },
            {6,"0110" },
            {7,"0111" },
            {8,"1000" },
            {9,"1001" },
            {10,"1010" },
            {11,"1011" },
            {12,"1100" },
            {13,"1101" },
            {14,"1110" },
            {15,"1111" }
        };

            int[,] PermutationAfterXOR = new int[,]
        {
       { 16,  7, 20, 21 },
       { 29, 12, 28, 17 },
       {  1, 15, 23, 26 },
       { 5, 18, 31, 10 },
       { 2,  8, 24, 14 },
       { 32, 27,  3,  9 },
       { 19, 13, 30,  6 },
       { 22, 11,  4, 25 }};

            int[,] inv_IP = new int[8, 8] {
    { 40, 8, 48, 16, 56, 24, 64, 32 },
    { 39, 7, 47, 15, 55, 23, 63, 31 },
    { 38, 6, 46, 14, 54, 22, 62, 30 },
    { 37, 5, 45, 13, 53, 21, 61, 29 },
    { 36, 4, 44, 12, 52, 20, 60, 28 },
    { 35, 3, 43, 11, 51, 19, 59, 27 },
    { 34, 2, 42, 10, 50, 18, 58, 26 },
    { 33, 1, 41,  9, 49, 17, 57, 25 }
};

            string keyhexa = key;
            string plainhexa = plainText;

            string key_64bit = HexaToBin(keyhexa);
            string plain_64bit = HexaToBin(plainhexa);

            string key_56bit = Permutaion(PC_1, key_64bit, 8, 7);
            string new_plain_64bit = Permutaion(IP, plain_64bit, 8, 8);

            
            string keyLeftPart = splitLeft(key_56bit);
            //Console.WriteLine("Left: " + keyLeftPart);

            string keyRightPart = splitRight(key_56bit);
            //Console.WriteLine("Right: " + keyRightPart);

            //Console.WriteLine("===============================================================================================================");

            string plainLeftPart = splitLeft(new_plain_64bit);
            //Console.WriteLine("Left: " + plainLeftPart);

            string plainRightPart = splitRight(new_plain_64bit);
            //Console.WriteLine("Right: " + plainRightPart);

            //Console.WriteLine("===============================================================================================================");
            int[] shiftAmountArr = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            string[] keysArr_48bit = new string[shiftAmountArr.Length + 1];

            string shiftedLeftBin = keyLeftPart;
            string shiftedRightBin = keyRightPart;
            keysArr_48bit[0] = shiftedLeftBin + shiftedRightBin;

            string[] R = new string[shiftAmountArr.Length + 1];
            string[] L = new string[shiftAmountArr.Length + 1];


            R[0] = plainRightPart;
            L[0] = plainLeftPart;

            string plainAfterXOR = "";
            int rndNum;
            char[,] RMatrix;
            string Expanded;
            int shiftAmount;
            string s;
            string XORresult;
            string subsResult;
            char[,] XORresultMtrx;


            for (rndNum = 1; rndNum < shiftAmountArr.Length; rndNum++)
            {
                L[rndNum] = R[rndNum - 1];

                RMatrix = StrToMtrx(R[rndNum - 1], 8, 4);
                Expanded = expansionPermutation(RMatrix);
                /*string output = "011110100001010101010101011110100001010101010101";
                Console.WriteLine(Expanded == output);*/

                //Console.WriteLine("===============================================================================================================");

             
                shiftAmount = shiftAmountArr[rndNum - 1];
                shiftedLeftBin = BinShiftLeft(shiftedLeftBin, shiftAmount);
                shiftedRightBin = BinShiftLeft(shiftedRightBin, shiftAmount);
                s = shiftedLeftBin + shiftedRightBin;
                keysArr_48bit[rndNum] = Permutaion(PC_2, s, 8, 6);

                /*Console.WriteLine("round: " + rndNum + " after the left part is shifted by " + shiftAmount + ": " + shiftedLeftBin);
                Console.WriteLine("round: " + rndNum + " after the right part is shifted by " + shiftAmount + ": " + shiftedRightBin);
                Console.WriteLine("key of round " + rndNum + ": " + keysArr_48bit[rndNum]);*/
                // Console.WriteLine("===============================================================================================================");

                XORresult = XOR(keysArr_48bit[rndNum], Expanded);
                //Console.WriteLine("key of round " + rndNum + " XOR Expanded(R" + (rndNum - 1) + "): " + XORresult);

                XORresultMtrx = StrToMtrx(XORresult, 8, 6);

                subsResult = substitution(XORresultMtrx, binary1);
                /*string actual = "01011100100000101011010110010111";
                Console.WriteLine(result == actual);*/

                plainAfterXOR = Permutaion(PermutationAfterXOR, subsResult, 8, 4);
                //Console.WriteLine("Permutation after XOR of round " + rndNum + ": " + plainAfterXOR);

                R[rndNum] = XOR(L[rndNum - 1], plainAfterXOR);
                //Console.WriteLine("R"+ rndNum+": " + R[rndNum]);


            }

            rndNum = 16;
            L[rndNum] = R[rndNum - 1];

            RMatrix = StrToMtrx(R[rndNum - 1], 8, 4);
            Expanded = expansionPermutation(RMatrix);
            
            shiftAmount = shiftAmountArr[rndNum - 1];
            shiftedLeftBin = BinShiftLeft(shiftedLeftBin, shiftAmount);
            shiftedRightBin = BinShiftLeft(shiftedRightBin, shiftAmount);
            s = shiftedLeftBin + shiftedRightBin;
            keysArr_48bit[rndNum] = Permutaion(PC_2, s, 8, 6);

            XORresult = XOR(keysArr_48bit[rndNum], Expanded);
            XORresultMtrx = StrToMtrx(XORresult, 8, 6);
            subsResult = substitution(XORresultMtrx, binary1);
            plainAfterXOR = Permutaion(PermutationAfterXOR, subsResult, 8, 4);
     
            R[rndNum] = XOR(L[rndNum - 1], plainAfterXOR);
            R[16] = XOR(L[15], plainAfterXOR);
           
            string finalPlain = R[16] + L[16];
            finalPlain = Permutaion(inv_IP, finalPlain, 8, 8);
            finalPlain = BinToHexa(finalPlain);
          
            return finalPlain;
        }


        static string HexaToBin(string hexaNum)
        {
            string binNum = "";
            hexaNum = hexaNum.Substring(2);

            foreach (char d in hexaNum)
            {
                int hexa = Convert.ToInt32(d.ToString(), 16);
                string binaryDigit = Convert.ToString(hexa, 2).PadLeft(4, '0');
                binNum += binaryDigit;
            }

            return binNum;
        }

        static string Permutaion(int[,] permutaion_table, string key, int row, int column)
        {
            string result = "";
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    result += key[permutaion_table[i, j] - 1];
                }
            }
            return result;
        }

        static string splitLeft(string binNum)
        {
            string left = binNum.Substring(0, binNum.Length / 2);

            return left;
        }

        static string splitRight(string binNum)
        {
            string right = binNum.Substring((binNum.Length / 2));

            return right;
        }

        static string BinShiftLeft(string binNum, int shiftAmount)
        {

            char[] binaryArray = binNum.ToCharArray();

            for (int i = 0; i < shiftAmount; i++)
            {
                char firstChar = binaryArray[0];

                for (int j = 0; j < binaryArray.Length - 1; j++)
                {
                    binaryArray[j] = binaryArray[j + 1];
                }

                binaryArray[binaryArray.Length - 1] = firstChar;
            }

            string shiftedBinary = new string(binaryArray);

            return shiftedBinary;
        }

        static string expansionPermutation(char[,] input)
        {
            char[,] Expanded = new char[8, 6];

            Expanded[0, 0] = input[7, 3];
            for (int i = 1, j = 0; i < 8; i++, j++)
            {
                Expanded[i, 0] = input[j, 3];
            }

            Expanded[7, 5] = input[0, 0];
            for (int i = 0, j = 1; i < 7; i++, j++)
            {
                Expanded[i, 5] = input[j, 0];
            }
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Expanded[i, j + 1] = input[i, j];
                }
            }
            string expandedStr = "";

            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    expandedStr += Expanded[i, j];
                }
            }
            return expandedStr;
        }

        static char[,] StrToMtrx(string input, int row, int col)
        {
            char[,] R0Matrix = new char[row, col];
            int n = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    R0Matrix[i, j] = input[n];
                    n++;
                }
            }
            return R0Matrix;
        }

        static string XOR(string binary1, string binary2)
        {
            char[] result = new char[binary1.Length];

            for (int i = 0; i < binary1.Length; i++)
            {
                if (binary1[i] == binary2[i])
                    result[i] = '0';
                else
                    result[i] = '1';
            }

            return new string(result);
        }

        static string substitution(char[,] input, Dictionary<int, string> binary1)
        {
            int[,] sBox1 = {
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
            {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
            {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
            {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        };

            int[,] sBox2 = {
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
            {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
            {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
            {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        };

            int[,] sBox3 = {
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
            {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
            {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
            {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        };

            int[,] sBox4 = {
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
            {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
            {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
            {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        };

            int[,] sBox5 = {
            {2,12,4,1,7, 10, 11,6,8,5,3,15,13,0,14,9},
            {14,11,2,12,4, 7, 13,1,5,0,15,10,3,9,8, 6},
            {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
            {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
        };

            int[,] sBox6 = {
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
            {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
            {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
            {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        };

            int[,] sBox7 = {
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
            {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
            {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
            {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        };

            int[,] sBox8 = {
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
            {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
            {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
            {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        };

            string row;
            string col;
            int[] rowInd = new int[8];
            int[] colInd = new int[8];
            for (int i = 0; i < 8; i++)
            {
                row = "00";
                col = "";
                for (int j = 0; j < 6; j++)
                {
                    if (j == 0 || j == 5)
                    {
                        row += input[i, j];
                    }
                    else
                    {
                        col += input[i, j];
                    }
                }

                rowInd[i] = hex(binary1, row);
                colInd[i] = hex(binary1, col);

            }

            int val1 = sBox1[rowInd[0], colInd[0]];
            int val2 = sBox2[rowInd[1], colInd[1]];
            int val3 = sBox3[rowInd[2], colInd[2]];
            int val4 = sBox4[rowInd[3], colInd[3]];
            int val5 = sBox5[rowInd[4], colInd[4]];
            int val6 = sBox6[rowInd[5], colInd[5]];
            int val7 = sBox7[rowInd[6], colInd[6]];
            int val8 = sBox8[rowInd[7], colInd[7]];
            string result = "";
            result += binary1[val1];

            result += binary1[val2];
            result += binary1[val3];
            result += binary1[val4];

            result += binary1[val5];
            result += binary1[val6];
            result += binary1[val7];
            result += binary1[val8];

            return result;

        }

        static int hex(Dictionary<int, string> binary, string x)
        {
            foreach (var y in binary)
            {
                if (y.Value == x)
                {
                    return y.Key;
                }
            }
            return 0;


        }

         static string BinToHexa(string binNum)
        {
            
            string hexString = "";

            for (int i = 0; i < binNum.Length; i += 4)
            {
                string binaryDigit = binNum.Substring(i, 4);
                int hexValue = Convert.ToInt32(binaryDigit, 2);
                hexString += hexValue.ToString("X");

            }

            return "0x" + hexString;
        }



    }
}
