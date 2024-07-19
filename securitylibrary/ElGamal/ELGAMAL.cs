using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();

            long C1 = LargePower(alpha, k, q);
            long K = LargePower(y, k, q);
            long C2 = LargePower(K * m, 1, q);

            List<long> cipher = new List<long>() { C1, C2 };

            return cipher;

        }
     
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();

            long K = LargePower(c1, x, q);
            int kInv = GetMultiplicativeInverse((int)K, q);

            long M = LargePower(c2 * kInv, 1, q);

            return (int)M;

        }

        long LargePower(long baseN, long power, long num)
        {
            baseN = baseN % num;
            long res = 1;

            while (power >= 1)
            {
                if (power % 2 == 1) { res = (baseN * res) % num; }
                baseN = (baseN * baseN) % num;
                power = power / 2;
            }

            return res;
        }

        int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();

            int myResult;

            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;
            int Q = 0;

            int New_A1 = 0, New_A2 = 0, New_A3 = 0;
            int New_B1 = 0, New_B2 = 0, New_B3 = 0;

            while (B3 != 1)
            {

                /*Console.Write(Q + "   " + A1 + " " + A2 + " " + A3);
                Console.WriteLine("     " + B1 + " " + B2 + " " + B3);*/

                Q = A3 / B3;

                New_A1 = B1;
                New_A2 = B2;
                New_A3 = B3;

                New_B1 = A1 - Q * B1;
                New_B2 = A2 - Q * B2;
                New_B3 = A3 - Q * B3;

                /*Console.Write(Q + "   " + New_A1 + " " + New_A2 + " " + New_A3);
                Console.WriteLine("     " + New_B1 + " " + New_B2 + " " + New_B3);*/

                A1 = New_A1; A2 = New_A2; A3 = New_A3;
                B1 = New_B1; B2 = New_B2; B3 = New_B3;

                if (New_B3 == 0) { myResult = -1; break; }
                else
                {
                    Q = New_A3 / New_B3;
                }

            }

            //Console.WriteLine(B2);

            if (New_B3 != 0)
            {
                while (B2 < 0)
                {
                    //B2 = B2 + 26;
                    B2 = B2 + baseN;

                }

                myResult = B2;
                return myResult;
            }
            else { myResult = -1; return myResult; }

            /*
            Console.WriteLine(myResult);
            Console.WriteLine(myResult == result);*/



        }
    }
}
