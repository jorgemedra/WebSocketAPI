using System;
using System.Net;
using System.Collections;
using jomt.websocket;

namespace Sample
{
    public class Server
    {
        private string CERT_PATH = "/Users/jorgemedra/Projects/WebSocket/cert/certificate.pfx";

        private WebSocketServer wsserver;

        private Queue clients;

        public Server(int port)
        {

            wsserver = new WebSocketServer(IPAddress.Any, port,CERT_PATH,"w0rk1ng",System.Security.Authentication.SslProtocols.Tls12);

            clients = new Queue();

            wsserver.OnSartedEvent += OnStated;
            wsserver.OnStopEvent += OnStop;
            wsserver.OnNewConnectionEvent += OnNewConnection;
            wsserver.OnErrorEvent += OnError;
        }

        public void Start()
        {
            if (wsserver.IsRunning) return;
            wsserver.start();
        }

        public void OnStated()
        {
            System.Console.WriteLine("Server::OnStated.");
        }

        public void OnStop()
        {
            System.Console.WriteLine("Server::OnStop.");
            foreach (Client c in clients)
                c.Stop();

        }

        public void OnNewConnection(WebSocketClient cnx)
        {
            System.Console.WriteLine("Server::OnNewConnection: New Connectionwas accepted.");

            Client clt = new Client(cnx);
            clients.Enqueue(clt);
            clt.OnLine();
        }

        public void OnError(int code, string desc)
        {
            System.Console.WriteLine(string.Format("Server::OnError: Code: {0}; Desc: {1}", code, desc));
        }
    }
}
