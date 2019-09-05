using System;

namespace Sample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            string line;

            if (args.Length < 1)
            {
                Console.WriteLine("Sample.exe [Listening Port]");
                return;
            }

            
            Console.WriteLine("Starting Sample of WebSocket Library on Port: [" + args[0] + "]");

            Server server = new Server(int.Parse(args[0]));
            server.Start();

            do
            {

                line = System.Console.ReadLine();
                line = line.ToUpper();


            } while (!line.Equals("QUIT"));

            server.OnStop();

        }
    }


}
