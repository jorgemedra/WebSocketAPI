using System;

namespace jomt.websocket.events
{
    public delegate void OnStart();
    public delegate void OnStop();
    public delegate void OnError(int err_code, string err_desc);
    public delegate void OnTextMessage(string data);
    public delegate void OnBinaryMessage(byte[] data);
    public delegate void OnDebug(string message);
    public delegate void OnNewConnection(WebSocketClient client);
}