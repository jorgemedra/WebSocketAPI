using System;
using System.Text;
using System.Net.Sockets;
using jomt.websocket.events;
using System.Security.Authentication;

namespace jomt.websocket
{

    /// <summary>
    /// WebSocketServer implement a socket server to wait for any WebSocket connection request. This class
    /// provide the events to know when the service has been started, stoped or a new connection has been arrived.
    ///
    /// This class allows to use a SSL certfed to stablish a WSS connection.
    /// </summary>
    public class WebSocketServer
    {
#region Events
        public event OnStart OnSartedEvent;
        public event OnStop OnStopEvent;
        public event OnError OnErrorEvent;
        public event OnNewConnection OnNewConnectionEvent;
#endregion

        public string SSLCetified{get;set;}
        public bool UseSSL{
            get{return SSLCetified== null? false:true;}
        }

        public bool IsRunning { get; private set; }
        private TcpListener server;

        private string _pwd;
        private SslProtocols _protocol;

        /// <summary>
        /// Create an Instance of WebSocket Server
        /// </summary>
        /// <param name="address">Address from wich the Server will be wating for requests.</param>
        /// <param name="port">The port from wich will be listenning.</param>
        public WebSocketServer(System.Net.IPAddress address, int port)
        {
            server = new TcpListener(address, port);
            IsRunning = false;
            SSLCetified = null;
        }

        /// <summary>
        /// Create an Instance of WebSocket Server
        /// </summary>
        /// <param name="address">Address from wich the Server will be wating for requests.</param>
        /// <param name="port">The port from wich shall be listenning.</param>
        /// <param name="certified">The path of the file PFX wich will be used to set the SSL comunicaction. (WSS://)</param>
        /// <param name="password">The password of PFX file wich will be used to set the SSL comunicaction. (WSS://)</param>
        /// <param name="protocol">The SSLProtocol that will be used.</param>
        public WebSocketServer(System.Net.IPAddress address, int port, string certified, string password, SslProtocols protocol) :
            this(address, port)
        {
            SSLCetified = certified;
            _pwd = password;
            _protocol = protocol;
        }

        /// <summary>
        /// Start to wait forconnections
        /// </summary>
        public void start()
        {
            try
            {
                if(IsRunning)
                {
                    OnErrorEvent((int)WSError.ALREADY_STARTED, "Server is already started.");
                    return;
                }
                IsRunning = true;
                server.Start();
                server.BeginAcceptTcpClient(AcceptNewConnection, server);
                OnSartedEvent();
            }catch(Exception e){
                OnErrorEvent((int)WSError.ON_START_WAITING, "There is a problem at the moment of starting server:" + e);
            }
        }

        public void stop()
        {
            if (!IsRunning)
            {
                OnErrorEvent((int)WSError.NOT_RUNNING, "The Server is already stoped.");
                return;
            }

            IsRunning = true;
            server.Stop();
            OnStopEvent(); 
        }

        private void AcceptNewConnection(IAsyncResult ar)
        {
            try
            {
                TcpClient client =  server.EndAcceptTcpClient(ar);
                WebSocketClient wsc = null;
                if (UseSSL)
                    wsc = new WebSocketClient(client, SSLCetified, _pwd, _protocol);
                else
                    wsc = new WebSocketClient(client);
                OnNewConnectionEvent(wsc);

                if (IsRunning)
                    server.BeginAcceptTcpClient(AcceptNewConnection, server);
            }
            catch(Exception e)
            {
                if(IsRunning)
                {
                    StringBuilder sb = new StringBuilder("On Waiting conection: " + e);
                    OnErrorEvent((int)WSError.ON_WAIT_CNX, "Server is already started.");
                }
            }
        }


    } //Class
} //Namespace
 