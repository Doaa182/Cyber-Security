using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();


            string[,] sBox = new string[17, 17] {
        {"","0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"},
        { "0","63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
        { "1","ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
        { "2","b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
        { "3","04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
        {"4", "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
        { "5","53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
        {"6", "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
        { "7","51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
        {"8", "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
        { "9","60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
        { "a","e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
        { "b","e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
        { "c","ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
        { "d","70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
        { "e","e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
        { "f","8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
        };

            string[,] sBoxInv = new string[17, 17] {
    { "", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f" },
    { "0", "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
    { "1", "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" },
    { "2", "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" },
    { "3", "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" },
    { "4", "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" },
    { "5", "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" },
    { "6", "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" },
    { "7", "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" },
    { "8", "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" },
    { "9", "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" },
    { "a", "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" },
    { "b", "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" },
    { "c", "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" },
    { "d", "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" },
    { "e", "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" },
    { "f", "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" }
};

            Dictionary<char, string> binary = new Dictionary<char, string>()
        {
            {'0',"0000" },
            {'1',"0001" },
            {'2',"0010" },
            {'3',"0011" },
            {'4',"0100" },
            {'5',"0101" },
            {'6',"0110" },
            {'7',"0111" },
            {'8',"1000" },
            {'9',"1001" },
            {'a',"1010" },
            {'b',"1011" },
            {'c',"1100" },
            {'d',"1101" },
            {'e',"1110" },
            {'f',"1111" }
        };

            string[,] Rcon = new string[,]
            {
            {"01","02","04", "08", "10", "20", "40", "80", "1b", "36"},
            {"00","00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00","00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00","00", "00", "00", "00", "00", "00", "00", "00", "00"},
            };



            

            string[,] Inverse_MixColumnFactor = new string[,]{
            {"0e","0b", "0d", "09"},
            {"09","0e", "0b", "0d"},
            {"0d","09", "0e", "0b"},
            {"0b","0d", "09", "0e"}
            };


           

            string[,] cipher = HexaToMatrix(cipherText.ToLower());
         

            string[,] keystr = HexaToMatrix(key.ToLower());
           

            string[,] subResult;
            string[,] shift;
            string[,] mixed;


            string[,] newKey = keystr;
            string[,] newKey1 = keystr;
            string[,] newKey2 = keystr;
            string[,] newKey3 = keystr;
            string[,] newKey4 = keystr;
            string[,] newKey5 = keystr;
            string[,] newKey6 = keystr;
            string[,] newKey7 = keystr;
            string[,] newKey8 = keystr;
            string[,] newKey9 = keystr;

            for (int i = 0; i < 9; i++)
            {

                newKey = calcNewKey(newKey, sBox, binary, Rcon, i);
                if (i == 0) { newKey1 = newKey; }
                else if (i == 1) { newKey2 = newKey; }
                else if (i == 2) { newKey3 = newKey; }
                else if (i == 3) { newKey4 = newKey; }
                else if (i == 4) { newKey5 = newKey; }
                else if (i == 5) { newKey6 = newKey; }
                else if (i == 6) { newKey7 = newKey; }
                else if (i == 7) { newKey8 = newKey; }
                else if (i == 8) { newKey9 = newKey; }

            }
            
            newKey = calcNewKey(newKey, sBox, binary, Rcon, 9);
            


            string[,] output = AddRoundKey(binary, cipher, newKey);
         

            shift = ShiftRightRows(output);
            

            subResult = subByte(sBoxInv, shift);
            


            string[,] round = newKey;

            for (int i = 8; i >= 0; i--)
            {
                if (i == 8) { round = AddRoundKey(binary, subResult, newKey9); }
                else if (i == 7) { Console.Write("here     "); round = AddRoundKey(binary, subResult, newKey8); Console.Write("here 2    "); }
                else if (i == 6) { round = AddRoundKey(binary, subResult, newKey7); }
                else if (i == 5) { round = AddRoundKey(binary, subResult, newKey6); }
                else if (i == 4) { round = AddRoundKey(binary, subResult, newKey5); }
                else if (i == 3) { round = AddRoundKey(binary, subResult, newKey4); }
                else if (i == 2) { round = AddRoundKey(binary, subResult, newKey3); }
                else if (i == 1) { round = AddRoundKey(binary, subResult, newKey2); }
                else if (i == 0) { round = AddRoundKey(binary, subResult, newKey1); }


                mixed = InverseMixColumns(round, Inverse_MixColumnFactor);
             

                shift = ShiftRightRows(mixed);
                

                for (int x = 0; x < 4; x++)
                {
                    for (int z = 0; z < 4; z++)
                    {
                        shift[x, z] = shift[x, z].ToLower();
                    }

                }

                subResult = subByte(sBoxInv, shift);
               
            }

            round = AddRoundKey(binary, subResult, keystr);
          

            string plain = "0X";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = i; k < i + 1; k++)
                    {
                        plain += round[j, k].ToUpper();
                    }
                }
            }
            //Console.WriteLine(plain == plainText.ToUpper());


            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            string[,] sBox = new string[17, 17] {
        {"","0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"},
        { "0","63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
        { "1","ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
        { "2","b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
        { "3","04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
        {"4", "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
        { "5","53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
        {"6", "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
        { "7","51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
        {"8", "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
        { "9","60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
        { "a","e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
        { "b","e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
        { "c","ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
        { "d","70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
        { "e","e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
        { "f","8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
        };
            Dictionary<char, string> binary = new Dictionary<char, string>()
        {
            {'0',"0000" },
            {'1',"0001" },
            {'2',"0010" },
            {'3',"0011" },
            {'4',"0100" },
            {'5',"0101" },
            {'6',"0110" },
            {'7',"0111" },
            {'8',"1000" },
            {'9',"1001" },
            {'a',"1010" },
            {'b',"1011" },
            {'c',"1100" },
            {'d',"1101" },
            {'e',"1110" },
            {'f',"1111" }
        };
            string[,] Rcon = new string[,]
            {
            {"01","02","04", "08", "10", "20", "40", "80", "1b", "36"},
            {"00","00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00","00", "00", "00", "00", "00", "00", "00", "00", "00"},
            {"00","00", "00", "00", "00", "00", "00", "00", "00", "00"},
            };
            
            string[,] MixColumnFactor = new string[,]{
            {"02","03", "01", "01"},
            {"01","02", "03", "01"},
            {"01","01", "02", "03"},
            {"03","01", "01", "02"}
        };
            

            string[,] plain = HexaToMatrix(plainText.ToLower());
            string[,] keystr = HexaToMatrix(key.ToLower());

            string[,] output = AddRoundKey(binary, plain, keystr);
            string[,] round = output;
            string[,] newKey = keystr;
            string[,] subResult;
            string[,] shift;
            string[,] mixed;
            for (int i = 0; i < 9; i++)
            {
                subResult = subByte(sBox, round);
                shift = ShiftLeftRows(subResult);
                mixed = MixColumns(shift, MixColumnFactor, binary);
                newKey = calcNewKey(newKey, sBox, binary, Rcon, i);
                round = AddRoundKey(binary, mixed, newKey);
            }
            subResult = subByte(sBox, round);
            shift = ShiftLeftRows(subResult);
            newKey = calcNewKey(newKey, sBox, binary, Rcon, 9);
            round = AddRoundKey(binary, shift, newKey);

            string cipher = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = i; k < i + 1; k++)
                    {
                        cipher += round[j, k].ToUpper();
                    }
                }
            }
            //Console.WriteLine(cipher == cipherText);
            return cipher;
        }


        static string[,] HexaToMatrix(string hexaStr)
        {
            // remove 0x 
            hexaStr = hexaStr.Substring(2);

            string[,] matrix = new string[4, 4];
            int index = 0;

            // convert each 2 chars of hex  to 1 byte
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    string hexElem = hexaStr.Substring(index, 2);
                    matrix[row, col] = hexElem;
                    index = index + 2;
                }
            }

            return matrix;
        }
        static string ShiftLeft(string binary)
        {
            char[] binaryArray = binary.ToCharArray();
            for (int i = 0; i < binaryArray.Length - 1; i++)
            {
                binaryArray[i] = binaryArray[i + 1];
            }
            binaryArray[binaryArray.Length - 1] = '0';

            return new string(binaryArray);
        }
        static string BinXOR(string binary_1, string binary_2)
        {
            int maxLength = Math.Max(binary_1.Length, binary_2.Length);
            binary_1 = binary_1.PadLeft(maxLength, '0');
            binary_2 = binary_2.PadLeft(maxLength, '0');

            StringBuilder result = new StringBuilder(maxLength);

            for (int i = 0; i < maxLength; i++)
            {
                result.Append(binary_1[i] == binary_2[i] ? '0' : '1');
            }

            return result.ToString();
        }
        static string HexToBin(string x)
        {
            StringBuilder binBuilder = new StringBuilder();

            foreach (char c in x)
            {
                int value = Convert.ToInt32(c.ToString(), 16);
                for (int i = 3; i >= 0; i--)
                {
                    int bit = (value >> i) & 1;
                    binBuilder.Append(bit);
                }
            }

            return binBuilder.ToString();
        }
        static string BinToHex(string x)
        {
            StringBuilder hexBuilder = new StringBuilder();

            int padLength = (4 - x.Length % 4) % 4;
            x = x.PadLeft(x.Length + padLength, '0');

            for (int i = 0; i < x.Length; i += 4)
            {
                string nibble = x.Substring(i, 4);
                int decimalValue = Convert.ToInt32(nibble, 2);
                hexBuilder.Append(decimalValue.ToString("X"));
            }

            return hexBuilder.ToString();
        }
        public static string[,] MixColumns(string[,] matrix, string[,] MixColumnFactor, Dictionary<char, string> binary)
        {
            string[,] mixed_matrix = new string[4, 4];
            string temp;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string result = "";
                    for (int k = 0; k < 4; k++)
                    {
                        temp = matrix[k, j];
                        string binary1 = HexToBin(matrix[k, j]);
                        string res = "";
                        string _1B = HexToBin("1B");

                        if (MixColumnFactor[i, k].Equals("02"))
                        {
                            if (binary1[0] == '1')
                            {
                                binary1 = ShiftLeft(binary1);
                                res = BinXOR(binary1, _1B);
                            }
                            else
                                res = ShiftLeft(binary1);
                        }
                        else if (MixColumnFactor[i, k].Equals("01"))
                        {
                            res = binary1;
                        }
                        else if (MixColumnFactor[i, k].Equals("03"))
                        {
                            res = binary1;
                            if (binary1[0] == '1')
                            {
                                binary1 = ShiftLeft(binary1);
                                res = BinXOR(BinXOR(binary1, _1B), res);
                            }
                            else
                            {
                                binary1 = ShiftLeft(binary1);
                                res = BinXOR(binary1, res);
                            }
                        }

                        result = BinXOR(result.PadLeft(8, '0'), res);
                    }

                    mixed_matrix[i, j] = BinToHex(result).PadLeft(2, '0').ToLower();
                }
            }

            return mixed_matrix;
        }

        public static string[,] ShiftLeftRows(string[,] input)
        {
            for (var i = 1; i < 4; i++)
            {
                for (var j = 0; j < i; j++)
                {
                    string temp_swap = input[i, 0];
                    input[i, 0] = input[i, 1];
                    input[i, 1] = input[i, 2];
                    input[i, 2] = input[i, 3];
                    input[i, 3] = temp_swap;
                }
            }
            return input;
        }
        static string[,] subByte(string[,] sBox, string[,] matrix)
        {
            string[,] result = new string[4, 4];
            string[] vec1;
            string[] vec2;
            for (int i = 0; i < 4; i++)
            {
                vec1 = getCol(i, matrix);
                vec2 = sBytes(sBox, vec1);
                for (int k = 0; k < 4; k++)
                {
                    result[k, i] = vec2[k];
                }
            }
            return result;
        }
        static string[,] calcNewKey(string[,] key, string[,] sBox, Dictionary<char, string> binary, string[,] Rcon, int index)
        {
            string[] keyFirstCol;
            string[] keyCol;
            string[,] newKey = new string[4, 4];
            string[] temp = new string[4];
            for (int i = 0; i < 4; i++)
            {
                if (i == 0)
                {
                    keyFirstCol = calcKeyFirstCol(key, sBox, binary, Rcon, index);
                    for (int k = 0; k < 4; k++)
                    {
                        newKey[k, i] = keyFirstCol[k];
                        temp[k] = keyFirstCol[k];

                    }
                }
                else
                {
                    keyCol = calcKeyCols(key, temp, binary, i);

                    for (int k = 0; k < 4; k++)
                    {
                        newKey[k, i] = keyCol[k];
                        temp[k] = keyCol[k];
                    }
                }
            }
            return newKey;
        }
        static string[] calcKeyCols(string[,] key, string[] col1, Dictionary<char, string> binary, int index)
        {
            string[] col2 = getCol(index, key);
            string[] keyCol = new string[4];
            string temp0;
            string temp1;
            for (int i = 0; i < 4; i++)
            {
                temp0 = col1[i];
                temp1 = col2[i];
                keyCol[i] = "" + hex(binary, Xor(binary[temp0[0]], binary[temp1[0]])) + hex(binary, Xor(binary[temp0[1]], binary[temp1[1]]));
               // Console.WriteLine(temp0[1] + " " + temp1[1]);
            }
            return keyCol;

        }
        static string[] calcKeyFirstCol(string[,] key, string[,] sBox, Dictionary<char, string> binary, string[,] Rcon, int index)
        {
            string[] col = getFirstCol(key);
            string[] col2 = getCol(0, key);
            string[] result = sBytes(sBox, col);
            string temp0;
            string temp1;
            string temp2;
            string[] keyCol = new string[4];
            for (int i = 0; i < 4; i++)
            {
                temp0 = col2[i];
                temp1 = result[i];
                temp2 = Rcon[i, index];
                //Console.WriteLine(temp2[0]);
                keyCol[i] = "" + hex(binary, Xor3(binary[temp0[0]], binary[temp1[0]], binary[temp2[0]])) + hex(binary, Xor3(binary[temp0[1]], binary[temp1[1]], binary[temp2[1]]));
            }
            return keyCol;
        }
        static string[] getFirstCol(string[,] matrix)
        {
            string[] col = new string[4];

            for (int k = 0; k < 3; k++)
            {
                col[k] = matrix[k + 1, 3];
            }
            col[3] = matrix[0, 3];
            return col;
        }
        static string[] getCol(int index, string[,] matrix)
        {
            string[] col = new string[4];
            for (int k = 0; k < 4; k++)
            {
                col[k] = matrix[k, index];
            }
            return col;
        }
        static string[] sBytes(string[,] Smatrix, string[] vector)
        {
            string[] result = new string[4];
            string val;
            int col = 0;
            int row = 0;
            for (int i = 0; i < 4; i++)
            {
                val = vector[i];
                for (int j = 0; j < 17; j++)
                {
                    if (Smatrix[j, 0] == "" + val[0])
                    {
                        row = j;
                    }
                    if (Smatrix[0, j] == "" + val[1])
                    {
                        col = j;
                    }

                }
                result[i] = Smatrix[row, col];

            }
            return result;
        }
        static string[,] AddRoundKey(Dictionary<char, string> binary, string[,] plain, string[,] key)
        {
            string[,] output = new string[4, 4];
            string tempP;
            string tempK;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tempP = plain[i, j];
                    tempK = key[i, j];
                    output[i, j] = "" + hex(binary, Xor(binary[tempP[0]], binary[tempK[0]])) + hex(binary, Xor(binary[tempP[1]], binary[tempK[1]]));
                }
            }
            return output;
        }

        static char hex(Dictionary<char, string> binary, string x)
        {
            foreach (var y in binary)
            {
                if (y.Value == x)
                {
                    return y.Key;
                }
            }
            return ' ';

        }
        static string Xor(string x, string y)
        {
            string output = "";
            for (int i = 0; i < 4; i++)
            {
                if (x[i] == '1' && y[i] == '1')
                {
                    output += "0";
                }
                else if (x[i] == '1' && y[i] == '0')
                {
                    output += "1";
                }
                else if (x[i] == '0' && y[i] == '1')
                {
                    output += "1";
                }
                else if (x[i] == '0' && y[i] == '0')
                {
                    output += "0";
                }
            }
            return output;
        }

        static string Xor3(string x, string y, string z)
        {
            string output = "";
            for (int i = 0; i < 4; i++)
            {
                if (x[i] == '1' && y[i] == '1' && z[i] == '1')
                {
                    output += "1";
                }
                else if (x[i] == '1' && y[i] == '0' && z[i] == '0')
                {
                    output += "1";
                }
                else if (x[i] == '0' && y[i] == '1' && z[i] == '0')
                {
                    output += "1";
                }
                else if (x[i] == '0' && y[i] == '0' && z[i] == '1')
                {
                    output += "1";
                }
                else
                {
                    output += "0";
                }
            }
            return output;
        }

        public static string[,] ShiftRightRows(string[,] cipher)
        {
            for (var i = 1; i < 4; i++)
            {
                for (var j = 0; j < i; j++)
                {
                    string temp_swap = cipher[i, 3];
                    cipher[i, 3] = cipher[i, 2];
                    cipher[i, 2] = cipher[i, 1];
                    cipher[i, 1] = cipher[i, 0];
                    cipher[i, 0] = temp_swap;
                }
            }
            //cipher = PadMatrixElements(cipher);
            return cipher;
        }

        static String Shift_1B(string binary)
        {
            if (binary[0] == '0')
            {
                return binary.Remove(0, 1) + "0";
            }
            else
            {
                return BinXOR((binary.Remove(0, 1) + "0"), HexToBin("1B"));
            }
        }
        static string _09(string binary)
        {
            string res = BinXOR(Shift_1B(Shift_1B(Shift_1B(binary))), binary);
            return res;
        }
        static string _0B(string binary)
        {
            string res = BinXOR(Shift_1B(BinXOR(Shift_1B(Shift_1B(binary)), binary)), binary);
            return res;
        }
        static string _0D(string binary)
        {
            string res = BinXOR(Shift_1B(Shift_1B(BinXOR(Shift_1B(binary), binary))), binary);
            return res;

        }
        static string _0E(string binary)
        {
            string res = Shift_1B(BinXOR(Shift_1B(BinXOR(Shift_1B(binary), binary)), binary));
            return res;

        }

        public static string[,] InverseMixColumns(string[,] matrix, string[,] Inverse_MixColumnFactor)
        {

            string[,] mixed_matrix = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mixed_matrix[i, j] = "";
                    for (int k = 0; k < 4; k++)
                    {
                        StringBuilder binary = new StringBuilder(HexToBin(matrix[k, j]));
                        string res = "";
                        if (Inverse_MixColumnFactor[i, k].Equals("09", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _09(binary.ToString());
                        }
                        else if (Inverse_MixColumnFactor[i, k].Equals("0B", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0B(binary.ToString());
                        }
                        else if (Inverse_MixColumnFactor[i, k].Equals("0D", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0D(binary.ToString());
                        }
                        else if (Inverse_MixColumnFactor[i, k].Equals("0E", StringComparison.OrdinalIgnoreCase))
                        {
                            res = _0E(binary.ToString());
                        }
                        mixed_matrix[i, j] = BinXOR(mixed_matrix[i, j].PadLeft(8, '0'), res);

                        if (k == 3)
                        {
                            mixed_matrix[i, j] = BinToHex(mixed_matrix[i, j]).PadLeft(2, '0').ToUpper();
                        }
                    }
                }
            }
            //mixed_matrix = PadMatrixElements(mixed_matrix);
            return mixed_matrix;
        }


    }
}

