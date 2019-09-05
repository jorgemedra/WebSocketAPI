using System;
using jomt.websocket;

namespace Sample
{
    public class Client
    {
        WebSocketClient ws;

        public Client(WebSocketClient socket)
        {
            ws = socket;
            ws.DebugOn = true;

            ws.OnDebugEvent += Debugger;
            ws.OnErrorEvent += WSErrors;
            ws.OnStartEvent += WSStarted;
            ws.OnStopEvent += WSStopped;
            ws.OnTextMessageEvent += WSOnTextMessage;
            ws.OnBinaryMessageEvent += WSOnBynaryMessage;
        }


        public void Stop()
        {
            ws.Stop();
        }

        #region EVENTS
        private void Debugger(string logMessage)
        {
            System.Console.WriteLine("DEBUG:" + logMessage);
        }

        private void WSErrors(int errCode, string errdesc)
        {
            System.Console.WriteLine("ERROR [" + errCode +"]: " + errdesc);
        }

        private void WSStarted()
        {
            System.Console.WriteLine("WS Client was started.");
        }

        private void WSStopped()
        {
            System.Console.WriteLine("WS Client was stopped.");
        }


        private void WSOnTextMessage(string data)
        {
            System.Console.WriteLine("TXT In: [" + data + "].");
            ws.SendTextMessage("ECHO: " + data);
        }

        private void WSOnBynaryMessage(byte[] data)
        {
            System.Console.WriteLine("BNR In: [" + data + "].");
        }

        public void OnLine()
        {
            ws.Start();
            ws.SendTextMessage("Here i am!");
        }

        #endregion
    }



}
