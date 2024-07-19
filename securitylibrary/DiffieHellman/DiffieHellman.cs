using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{


    public class DiffieHellman
    {

      public  int power(int f, int s, int sf)
        {
            //throw new NotImplementedException();

            int res = 1;
            for (int i = 0; i < s; i++)
            {
                res = (res * f) % sf;
            }
            return res;
        }

       public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            // throw new NotImplementedException();

            List<int> keys = new List<int>();
            int ya, yb;
            int shared_keya, shared_keyb;

            //public keys
            ya = power(alpha, xa, q);
            yb = power(alpha, xb, q);

            // shared keys
            shared_keya = power(yb, xa, q);
            shared_keyb = power(ya, xb, q);

            keys.Add(shared_keya);
            keys.Add(shared_keyb);

            return keys;
        }
    }
}