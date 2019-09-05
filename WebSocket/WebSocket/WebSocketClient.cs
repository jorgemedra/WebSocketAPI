using System;
using System.Text;
using jomt.websocket.events;
using System.Net.Sockets;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using jomt.websocket.utils;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace jomt.websocket
{


    public class WebSocketClient
    {

        #region Events

        public event OnTextMessage OnTextMessageEvent;
        public event OnBinaryMessage OnBinaryMessageEvent;
        public event OnStart OnStartEvent;
        public event OnStop OnStopEvent;
        public event OnError OnErrorEvent;
        public event OnDebug OnDebugEvent;

        #endregion

        public int ID { get; private set; }
        public bool DebugOn { get; set; }

        private bool _started;

        private bool _sslActive;
        private string certpath;

        private TcpClient socket;
        private SslStream sslstrm;
        private NetworkStream nstrm;
        private X509Certificate cert;
        private string _pwd;
        private SslProtocols _protocol;

        private byte[] InitByte;
        List<byte> MainBuffer;

        private const string    WEBSOCK_HDR = "Sec-WebSocket-Key";
        private const string    MAGIC_WORD = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        private const int       MAX_PAYLOAD_LEN = 2 ^ 24;



        /// <summary>
        /// Create a WeSocketClient linking a TCPClient socket to handle the communicaton between the client and server.
        /// </summary>
        /// <param name="socket">A TCPClient wich owns the communication between reqest side and server side.</param>
        public WebSocketClient(TcpClient socket)
        {
            ID = ((IPEndPoint)socket.Client.RemoteEndPoint).Port;
            _sslActive = false;
            DebugOn = false;
            this.socket = socket;
            MainBuffer = new List<byte>();
        }

        /// <summary>
        /// Create a WeSocketClient linking a TCPClient socket to handle the communicaton between the client and server.
        /// </summary>
        /// <param name="socket">A TCPClient wich owns the communication between reqest side and server side.</param>
        /// <param  name="certified">The path of the certified fiel tostablished a wss connection.</param>
        public WebSocketClient(TcpClient socket, string certified, string password, SslProtocols protocol):this(socket)
        {
            _sslActive = true;
            certpath = certified;
            _pwd = password;
            _protocol = protocol;
            _started = false;
        }

        /// <summary>
        /// Method to start the comunicaction between the client and the server. If there is a problem
        /// at the moment of statin the communication or getting the SSL Stream  this method shall raise
        /// the Error Event, and the Stop Event otherwise the Start Evet sall be raised.
        /// </summary>
        public void Start()
        {
            bool result = true;
            StringBuilder debug = new StringBuilder();

            if (DebugOn)
                OnDebugEvent("[" + ID + "] - Starting WebSocketClient");

            if (_started)
            {
                OnErrorEvent((int)WSError.ALREADY_STARTED, "The cliens is already started.");
                return;
            }

            try
            {
                _started = true;

                if (DebugOn)
                    debug.AppendLine("[" + ID + "]: Starting client");

                if (_sslActive)
                {
                    if(!InitSSLStream(ref debug))
                    {
                        string errInfo = string.Format("{0}{1}{2}",
                            "ERROR: There was an error at the momento of getting SSL stream.",
                                DebugOn ? Environment.NewLine : "",
                                DebugOn ? debug.ToString():""
                        );

                        OnErrorEvent((int)WSError.SSL_ERROR, errInfo);
                        result = false;
                    }
                }
                else
                {
                    sslstrm = null;
                    nstrm = socket.GetStream();
                }

                if (HandShaking(ref debug))
                {
                    if (DebugOn)
                        OnDebugEvent("[" + ID + "] - HandShaking aproved.");
                    Task.Run(new Action(this.PingHadler)); //Start the PingHandler.

                    //Start To read the next Frame
                    InitByte = new byte[1];
                    if (_sslActive) this.sslstrm.BeginRead(InitByte, 0, 1, this.RxFrame, this.sslstrm);
                    else            this.nstrm.BeginRead(InitByte, 0, 1, this.RxFrame, this.nstrm);
                }
                else
                {
                    string errInfo = string.Format("{0}{1}{2}",
                                                "There was an error in HandShaking process.",
                                                DebugOn ? Environment.NewLine : "",
                                                DebugOn ? debug.ToString() : ""
                                               );

                    OnErrorEvent((int)WSError.HANDSHACKING_ERROR, errInfo);
                }

            }catch(Exception e){
                string errInfo = string.Format("{0}{1}{2}{3}{4}",
                            "ERROR: There was an error at the momento of starting the comunication.",
                                DebugOn ? Environment.NewLine : "",
                                DebugOn ? debug.ToString() : "",
                                DebugOn ? Environment.NewLine : "",
                                DebugOn ? e.ToString() : ""
                        );
                OnErrorEvent((int)WSError.STARTING_ERROR, errInfo);
                result = false;
            }

            if (result)
                OnStartEvent();
            else
                Stop(); //Close the connection;
        }

        /// <summary>
        /// Method to stop the communication beween the remote point and the server.
        /// </summary>
        public void Stop()
        {
            if (DebugOn)
                OnDebugEvent("[" + ID + "] - Closing connection...");

            try
            {
                if (socket.Connected)
                {
                    _started = false;

                    if (_sslActive) sslstrm.Close();
                    else nstrm.Close();

                    socket.Close();
                    OnStopEvent();

                }
            }catch(Exception e)
            {
                string errInfo = string.Format("{0}{1}{2}",
                            "ERROR: There was an error at the momento of closing the socket.",
                                DebugOn ? Environment.NewLine : "",
                                DebugOn ? e.ToString() : ""
                        );
                OnErrorEvent((int)WSError.CLOSING_ERROR, errInfo);
            }

        }

        #region HAND SHACKING

        /// <summary>
        /// Method to get the SSLStream.
        ///
        /// More Information On: https://docs.microsoft.com/en-us/dotnet/api/system.net.security.sslstream?view=netframework-4.8
        /// </summary>
        /// <param name="debug">String Builder to</param>
        /// <returns></returns>
        bool InitSSLStream(ref StringBuilder debug)
        {
            bool result = false;

            if (DebugOn)
                OnDebugEvent("[" + ID + "] - Getting SSL Strema from Certified [" + certpath + "]");

            try
            {
                if (DebugOn)
                    debug.AppendLine("[" + ID + "]: loading certificated: [" + certpath + "]");


                cert = new X509Certificate(certpath, _pwd, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
                sslstrm = new SslStream(socket.GetStream(), false);
                sslstrm.AuthenticateAsServer(cert, false, _protocol, true);

                if (DebugOn)
                {
                    debug.AppendLine("------- CERT INFO ---------");
                    debug.AppendLine(string.Format("\tCipher: {0} strength {1}", sslstrm.CipherAlgorithm, sslstrm.CipherStrength));
                    debug.AppendLine(string.Format("\tHash: {0} strength {1}", sslstrm.HashAlgorithm, sslstrm.HashStrength));
                    debug.AppendLine(string.Format("\tKey exchange: {0} strength {1}", sslstrm.KeyExchangeAlgorithm, sslstrm.KeyExchangeStrength));
                    debug.AppendLine(string.Format("\tProtocol: {0}", sslstrm.SslProtocol));

                    debug.AppendLine(string.Format("\tIs authenticated: {0} as server? {1}", sslstrm.IsAuthenticated, sslstrm.IsServer));
                    debug.AppendLine(string.Format("\tIsSigned: {0}", sslstrm.IsSigned));
                    debug.AppendLine(string.Format("\tIs Encrypted: {0}", sslstrm.IsEncrypted));

                    debug.AppendLine(string.Format("\tCan read: {0}, write {1}", sslstrm.CanRead, sslstrm.CanWrite));
                    debug.AppendLine(string.Format("\tCan timeout: {0}", sslstrm.CanTimeout));

                    if (sslstrm.LocalCertificate != null)
                    {
                        debug.AppendLine(string.Format("\tLocal cert was issued to {0} and is valid from {1} until {2}.",
                            sslstrm.LocalCertificate.Subject,
                            sslstrm.LocalCertificate.GetEffectiveDateString(),
                            sslstrm.LocalCertificate.GetExpirationDateString()));
                    }

                    if (sslstrm.RemoteCertificate != null)
                    {
                        debug.AppendLine(string.Format("\tRemote cert was issued to {0} and is valid from {1} until {2}.",
                            sslstrm.RemoteCertificate.Subject,
                            sslstrm.RemoteCertificate.GetEffectiveDateString(),
                            sslstrm.RemoteCertificate.GetExpirationDateString()));
                    }

                }

                result = true;

            }
            catch (AuthenticationException e)
            {
                if (DebugOn)
                {
                    debug.AppendLine("ERROR: Authentication failed.");
                    debug.AppendLine(e.Message);
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                    }
                }
            }
            catch (Exception e)
            {
                if (DebugOn)
                {
                    debug.AppendLine("There was an exception at the moment of fetching for SSL Sream:");
                    debug.AppendLine(e.ToString());
                }
            }
            finally
            {
                if (DebugOn)
                    OnDebugEvent(debug.ToString());
            }

            if(!result)
                sslstrm = null;

            return result;
        }


        /// <summary>
        /// Method to handle the handshacking connection.
        /// </summary>
        /// <param name="debug">A String Builder to store the information about the handshacking</param>
        /// <returns>Return True if the HandShaking was successful, otherwise false</returns>
        private bool HandShaking(ref StringBuilder debug)
        {
            bool result = false;

            if (DebugOn)
            {
                OnDebugEvent("[" + ID + "] - Performing HandShaking.");
                debug.AppendLine("Performing HandShaking.");
            }

            //StringBuilder sb = new StringBuilder();


            string header = null;
            string token = null;
            byte[] response = null;

            StreamReader reader = _sslActive ? new StreamReader(sslstrm) : new StreamReader(nstrm);

            header = ReadLine(reader);

            if (header == null) return result;

            if(DebugOn)
            {
                debug.AppendLine("Request info");
                debug.AppendLine(string.Format("\t{0}", header));
            }


            if (header.StartsWith("GET", StringComparison.Ordinal))
            {
                //Getting the token
                while (!header.Contains(WEBSOCK_HDR))
                {
                    header = ReadLine(reader);
                    if (DebugOn)
                        debug.AppendLine(string.Format("\t{0}", header));
                }

                token = new Regex("Sec-WebSocket-Key: (.*)").Match(header).Groups[1].Value.Trim() + MAGIC_WORD;

                //Read the remainding header.
                while (!header.Equals(""))
                {
                    header = ReadLine(reader);
                    if (DebugOn)
                        debug.AppendLine(string.Format("\t{0}", header));
                }

                if (DebugOn)
                    debug.AppendLine(string.Format("TOKEN: [{0}]", token));


                //Send Response
                response = Encoding.UTF8.GetBytes(
                        "HTTP/1.1 101 Switching Protocols" + Environment.NewLine +
                        "Connection: Upgrade" + Environment.NewLine +
                        "Upgrade: websocket" + Environment.NewLine +
                        "Sec-WebSocket-Accept: " + Convert.ToBase64String(SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(token.ToCharArray()))) +
                        Environment.NewLine +
                        Environment.NewLine
                    );

                //Send Response
                if (DebugOn)
                {
                    debug.AppendLine("Sending response: ");
                    debug.AppendLine(Encoding.UTF8.GetString(response));
                }

                SendData(response);
                result = true;
            }
            else
            {
                if (DebugOn)
                    debug.AppendLine("ERROR : The request is invalid, it was expected a GET request.");
            }

            return result;
        }

        #endregion


        #region Methods of the interface

        public void SendTextMessage(string message) // interface
        {
            try
            {
                if (socket.Connected)
                {
                    Frame frame = new Frame();
                    frame.IsRX = false;
                    frame.OpCode = (byte)OpCodes.TEXT;
                    frame.PayLoad = Encoding.UTF8.GetBytes(message);
                    SendFrame(frame);
                }
            }
            catch (Exception ex)
            {
                OnErrorEvent((int)WSError.TX_TEXT_ERROR, "There was an error at the moment of Tx a Text Message: " + ex);
            }
        }

        public void SendBinaryMessage(byte[] buffer) // interface
        {
            try
            {
                if (socket.Connected)
                {
                    Frame frame = new Frame();
                    frame.IsRX = false;
                    frame.OpCode = (byte)OpCodes.BINARY;
                    frame.PayLoad = buffer;
                    SendFrame(frame);
                }
            }
            catch (Exception ex)
            {
                OnErrorEvent((int)WSError.TX_TEXT_ERROR, "There was an error at the moment of Tx a Binary Message: " + ex);
            }
        }

        #endregion

        #region TX

        private void SendData(byte[] data)
        {
            try
            {
                if (socket.Connected)
                {
                    if (_sslActive)
                        sslstrm.BeginWrite(data, 0, data.Length, SendFinished, sslstrm);
                    else
                        nstrm.BeginWrite(data, 0, data.Length, SendFinished, nstrm);
                }
                else
                    OnErrorEvent((int)WSError.TX_ERROR, "Was not possible to send the message, the socket has been closed.");
            }
            catch (Exception ex)
            {
                OnErrorEvent((int)WSError.TX_ERROR, "SendData: " + ex.ToString());
                Stop();
            }
        }

        private void SendFinished(IAsyncResult ar)
        {
            try
            {
                NetworkStream ns = (NetworkStream)ar.AsyncState;
            }
            catch(System.InvalidCastException ice)
            {
                //System.Console.WriteLine("Internal exception on SendFinished to Ignore: " + ice.ToString());
                string data = ice.ToString();
            }
            catch (Exception ex)
            {
                OnErrorEvent((int)WSError.TX_ERROR, "SendFinished: " + ex.ToString());
            }
        }

        private byte[] GenMask()
        {
            byte[] mask = new byte[4];

            Random rnd = new Random(325255);
            rnd.NextBytes(mask);
            return mask;
        }

        private void SendFrame(Frame frame)
        {
            try
            {
                if (!socket.Connected)
                {
                    OnDebugEvent("[" + ID + "] - Tx Frame: The socket has been closed.");
                    return;
                }

                if (DebugOn && frame.OpCode != (short)OpCodes.PING && frame.OpCode != (short)OpCodes.PONG)
                    OnDebugEvent("[" + ID + "] - " + frame.ToString());

                StringBuilder sb = new StringBuilder();

                List<byte> response = new List<byte>();
                bool useMask = false;

                byte[] mask = null;

                if (useMask)
                    mask = GenMask();

                // FIN=1
                // see RFC6455 at 6.1.3 and 6.1.4 for text frame
                byte aux = 128; // 0x80 10000000
                aux |= (byte)(0x00ff & frame.OpCode);
                response.Add(aux);

                aux = 0x00;
                if (useMask)
                    aux |= 0x80; // MASK=1 and PayLoadLen=0's // 10000000

                // 126 0x7E 01111110
                // 127 0x7F 01111111

                byte[] auxArr;

                if (frame.PayLoad.Length < 126)
                {
                    sb.AppendLine("data.Length (A) [" + frame.PayLoad.Length + "]");
                    aux |= (byte)frame.PayLoad.Length;
                    response.Add(aux);
                }
                else if (frame.PayLoad.Length < UInt16.MaxValue) // so the range is [126 - 65,535].
                {
                    sb.AppendLine("data.Length (B) [" + frame.PayLoad.Length + "]");
                    aux |= (byte)126;
                    response.Add(aux);

                    auxArr = BitConverter.GetBytes((UInt16)frame.PayLoad.Length);
                    sb.AppendLine("lenAux.Length[" + auxArr.Length + "] (must be 2)");
                    if (BitConverter.IsLittleEndian)
                        auxArr = auxArr.Reverse().ToArray();

                    response.AddRange(auxArr);
                }
                else
                {
                    string message = Encoding.UTF8.GetString(frame.PayLoad);

                    if (message.Length > MAX_PAYLOAD_LEN) // so the range is [65,536 - 16,777,216].
                        throw new ArgumentOutOfRangeException(string.Format("Payload length of {0} bytes is too long in the sent message (max allowed is {1}).", message.Length, MAX_PAYLOAD_LEN));

                    sb.AppendLine("data.Length (C) [" + frame.PayLoad.Length + "]");
                    aux |= (byte)127;
                    response.Add(aux);

                    auxArr = BitConverter.GetBytes((UInt64)frame.PayLoad.Length);
                    sb.AppendLine("lenAux.Length[" + auxArr.Length + "] (must be 8)");

                    if (BitConverter.IsLittleEndian) // quitar ?
                        auxArr = auxArr.Reverse().ToArray();

                    response.AddRange(auxArr);

                }

                if (useMask)
                    response.AddRange(mask);

                response.AddRange(frame.PayLoad);

                auxArr = response.ToArray<byte>();
                SendData(auxArr);

                if (DebugOn && frame.OpCode != (short)OpCodes.PING && frame.OpCode != (short)OpCodes.PONG)
                    OnDebugEvent("[" + ID + "] - " + sb.ToString());
            }
            catch (Exception ex)
            {
                if (_started)
                    OnErrorEvent((int)WSError.TX_FRAME_ERROR, "On Sending Frame: " + ex);
            }
        }


        #endregion

        #region RX

        /// <summary>
        /// Read Line from the socket.
        /// </summary>
        /// <returns></returns>
        private string ReadLine(StreamReader reader)
        {
            return reader.ReadLine();
        }


        /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-------+-+-------------+-------------------------------+
        |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
        |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
        |N|V|V|V|       |S|             |   (if payload len==126/127)   |
        | |1|2|3|       |K|             |                               |
        +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
        |     Extended payload length continued, if payload len == 127  |
        + - - - - - - - - - - - - - - - +-------------------------------+
        |                               |Masking-key, if MASK set to 1  |
        +-------------------------------+-------------------------------+
        | Masking-key (continued)       |          Payload Data         |
        +-------------------------------- - - - - - - - - - - - - - - - +
        :                     Payload Data continued ...                :
        + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
        |                     Payload Data continued ...                |
        +---------------------------------------------------------------+
        */
        private void RxFrame(IAsyncResult ar)
        {
            byte byteAux;
            Frame frame = new Frame();
            frame.IsRX = true;
            int total = 0;
            StringBuilder debug = new StringBuilder("RxFrame:");

            try
            {
                byteAux = InitByte[0];

                //logger.Debug(string.Format("Byte1: [{0:X}]", byteAux));

                //Read FIN, RSVs and OPCODE (1 Byte)
                byte finBitFlag = 0x80;
                byte opCodeFlag = 0x0F;
                frame.FIN = (byteAux & finBitFlag) == finBitFlag;
                frame.OpCode = (byte)(byteAux & opCodeFlag);

                byteAux = _sslActive ? (byte)this.sslstrm.ReadByte() : (byte)this.nstrm.ReadByte();

                byte MASK_FLAG = 0x80;
                frame.IsMASKING = (byteAux & MASK_FLAG) == MASK_FLAG;

                //Reading the PayLoad, according the last Byte.
                ReadPayLoadLen(byteAux, ref frame); // Read from 0, 2 or 8 bytes

                //Reading MASK
                if (frame.IsMASKING)
                {
                    frame.MaskingKey = new byte[4];

                    //reading 0 to N bytes of PayLoad
                    total = _sslActive ?
                            this.sslstrm.Read(frame.MaskingKey, 0, frame.MaskingKey.Length) :
                            this.nstrm.Read(frame.MaskingKey, 0, frame.MaskingKey.Length);
                }

                //Reading PAYLOAD
                frame.PayLoad = new byte[frame.PayLoadLen];
                //nwstrm.Read(frame.PayLoad, 0, (int)frame.PayLoadLen); //reading 4 bytes of Mask

                total = _sslActive ?
                            this.sslstrm.Read(frame.PayLoad, 0, (int)frame.PayLoadLen) :
                            this.nstrm.Read(frame.PayLoad, 0, (int)frame.PayLoadLen);

                if (frame.IsMASKING)
                    DecodePayLoad(ref frame);

                ProccessFrame(ref frame);

                //nwstrm.BeginRead(InitByte, 0, 1, this.RxFrame, nwstrm); //Start To read the next Frme

                //Start To read the next Frme
                if (_sslActive) this.sslstrm.BeginRead(InitByte, 0, 1, this.RxFrame, this.sslstrm);
                else            this.nstrm.BeginRead(InitByte, 0, 1, this.RxFrame, this.nstrm);
            }
            catch (Exception ex)
            {
                if (_started)
                {
                    OnErrorEvent((int)WSError.RX_FRAME_ERROR, "There was an error at the moment of Read a Frame: " + ex);
                    Stop();
                }
            }
        }

        /// <summary>
        /// x = bPaydLoad & 0x7. If x < 126 (This is the Size); if x == 126 (Read 2 Bytes), if x == 127 (Read 8 Bytes),
        /// </summary>
        /// <param name="bPaydLoad"></param>
        /// <param name="frame"></param>
        private void ReadPayLoadLen(Byte bPaydLoad, ref Frame frame)
        {
            byte aux = (byte)(0x7F & bPaydLoad); //remove the MaskBit

            int BytesPL = aux < 126 ? 0 : (aux == 126 ? 2 : 8);

            if (BytesPL == 0) //The size has been read
            {
                frame.PayLoadLen = (int)aux;
                return;
            }

            byte[] bufPL = new byte[BytesPL];

            if (_sslActive) this.sslstrm.Read(bufPL, 0, bufPL.Length);
            else            this.nstrm.Read(bufPL, 0, bufPL.Length);

            if (BitConverter.IsLittleEndian)
                bufPL = bufPL.Reverse().ToArray();

            if (bufPL.Length == 2)   // 16 bits
                frame.PayLoadLen = (int)BitConverter.ToUInt16(bufPL, 0);
            else // 64 bits
                frame.PayLoadLen = (int)BitConverter.ToUInt64(bufPL, 0);
        }

        private void DecodePayLoad(ref Frame frame)
        {
            if (frame.IsMASKING)
            {
                byte[] dataDec = new byte[frame.PayLoadLen];
                for (int i = 0; i < frame.PayLoadLen; i++)
                {
                    dataDec[i] = (byte)(frame.PayLoad[i] ^ frame.MaskingKey[i % frame.MaskingKey.Length]);
                }
                frame.PayLoad = dataDec;
            }
        }

        private void ProccessFrame(ref Frame frame)
        {
            StringBuilder debug = new StringBuilder();

            if (frame.OpCode != (short)OpCodes.PING && frame.OpCode != (short)OpCodes.PONG && frame.OpCode != (short)OpCodes.CONTINUE)
                debug.AppendLine(frame.ToString());

            if (frame.FIN)
            {
                if (MainBuffer.Count > 0)
                {
                    MainBuffer.AddRange(frame.PayLoad);
                    frame.PayLoad = MainBuffer.ToArray();
                    frame.PayLoadLen = frame.PayLoad.Length;
                }

                if (frame.OpCode == (short)OpCodes.TEXT)
                {
                    frame.TextData = Encoding.ASCII.GetString(frame.PayLoad, 0, frame.PayLoadLen);

                    if (DebugOn) OnDebugEvent(debug.ToString());
                    OnTextMessageEvent(frame.TextData);
                }
                else if (frame.OpCode == (short)OpCodes.BINARY)
                {
                    if (DebugOn) OnDebugEvent(debug.ToString());
                    OnBinaryMessageEvent(frame.PayLoad);
                }
                else if (frame.OpCode == (short)OpCodes.CLOSE)
                {
                    if (DebugOn){
                        debug.AppendLine("RX:[CLOSE] The connection will be close");
                        OnDebugEvent(debug.ToString());
                    }
                    Stop();
                }
                else if (frame.OpCode == (short)OpCodes.PING || frame.OpCode == (short)OpCodes.PONG)
                {
                    if (frame.OpCode == (short)OpCodes.PING)
                        SendPong(ref frame);
                }
                else
                {
                    debug.AppendLine("ERROR - Bad OPCODE (" + frame.OpCode + "). The connection will be closed.");
                    OnErrorEvent((int)WSError.BAD_OPCODE_ERROR, debug.ToString());
                    Stop();
                }

                MainBuffer.Clear();

            }
            else //If this frame is not the end of the package, it will be stored
                MainBuffer.AddRange(frame.PayLoad);
        }


        #endregion

        #region PIN HANDLER

        private void PingHadler()
        {
            long DLY_TM = 5000;
            long counter = 0;

            if(DebugOn)
                OnDebugEvent("[" + ID + "] - PingHadler has started.");

            while (socket.Connected)
            {
                while (socket.Connected)
                {
                    counter++;
                    if (counter > DLY_TM)
                    {
                        counter=0;
                        if (socket.Connected)
                            SendPing();
                    }
                    else
                        System.Threading.Thread.Sleep(1);
                }
            }

            if (DebugOn)
                OnDebugEvent("[" + ID + "] - PingHandler has finished.");
        }

        private void SendPing()
        {
            string message = "heartbeat";
            Frame pframe = new Frame();
            pframe.IsRX = false;
            pframe.OpCode = (byte)OpCodes.PING;
            pframe.PayLoad = Encoding.UTF8.GetBytes(message);
            SendFrame(pframe);
        }

        private void SendPong(ref Frame frame)
        {
            frame.OpCode = (byte)OpCodes.PONG;
            SendFrame(frame);
        }
        #endregion

    } //Class
}//namespace
