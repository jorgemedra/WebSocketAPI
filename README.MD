# WebScocket Sever Lib For .NET 4.5

# Introduction

This library provides a Websocket Server, coded with **TCPListener** and **TPCClient** classes to implement a server wich can works in any OS wich support *Microsoft .Net Framework 4.5* or *Microsoft.Net.Core 2.1*.

# Requirementes

+ Visual Studio 2017 Communitiy (For Windows).
+ Microsoft .Net 4.5 (For Windows)
+ Visual Studio 8.2.5 or higer (For Mac)
+ Microsoft Net Core 2.1 (For MAC)

# Basic concepts

The repository has two projects:

+ **WebSocket**: Projet wich has the code for WebSocket library.
+ **Sample**: Project wich shows how to use the library.

## Main Classes

+ `WebSocketServer` sets the socket listener to wait for new connections and raise an event with the new connection accepted.
+ `WebSocketClient` handles the communication pear to pear, allowing send and receive messages, get debug message and error messages, as well.

## Server events

```csharp
public void OnStartEvent();
public void OnStopEvent();
public void OnErrorEvent(int err_code, string err_desc);
public void OnNewConnectionEvent(WebSocketClient client);
```

## Client events


```csharp
public void OnStartEvent();
public void OnStopEvent();
public void OnErrorEvent(int err_code, string err_desc);
public void OnTextMessageEvent(string data);
public void OnBinaryMessageEvent(byte[] data);
public void OnDebugEvent(string message);
```

## Using WebSocket Server

**Creating a single** `WebSocketServer`**:**

```csharp
WebSocketServer wsserver = new WebSocketServer(IPAddress.Any, port);
```

**Creating a** `WebSocketServer` **with SSL:**

```csharp
WebSocketServer wsserver = new WebSocketServer(IPAddress.Any, port,CERT_PATH,"w0rk1ng",System.Security.Authentication.SslProtocols.Tls12);
```

**Link its events:**

```csharp
wsserver.OnSartedEvent += OnStated;
wsserver.OnStopEvent += OnStop;
wsserver.OnNewConnectionEvent += OnNewConnection;
wsserver.OnErrorEvent += OnError;
```

**Handle a new connection:**

```csharp
public void OnNewConnection(WebSocketClient cnx)
{
    System.Console.WriteLine("Server::OnNewConnection: New Connectionwas accepted.");

    Client clt = new Client(cnx);
    clients.Enqueue(clt);
    clt.OnLine();
}
```
The new connection (`WebSocketClient`) si delegate into a new   class wich will be handled the communication between pears.

In case that there would be and error, the `OnErrorEvent` will report this event and  its information:

```csharp
public void OnError(int code, string desc)
{
    System.Console.WriteLine(string.Format("Server::OnError: Code: {0}; Desc: {1}", code, desc));
}
```

## Using WebSocket Client

> In case of Debug information is requiered, use the property `DebugOn`, from `WebSocketClient` to activate all the debug messages through the event `OnDebugEvent`.

Before start communication, link events and, if you need it, turn on the debug messages, as it shows in the example below:

```csharp
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
```

Detect the start of communication through the method linked to `OnStartEvent`:

```csharp
private void WSStarted()
{
    System.Console.WriteLine("WS Client was started.");
}
```

Detect the end of communication,through the method linked to `OnStopEvent`:

```csharp
private void WSStopped()
{
    System.Console.WriteLine("WS Client was stopped.");
}
```

Detect an error with the WebSocketClient through the method linked to `OnErrorEvent`:

```csharp
private void WSErrors(int errCode, string errdesc)
{
    System.Console.WriteLine("ERROR [" + errCode +"]: " + errdesc);
}
```

Get the Debug message if the debug property is turn on, through the method linked to `OnDebugEvent`:

```csharp
private void Debugger(string logMessage)
{
    System.Console.WriteLine("DEBUG:" + logMessage);
}
```

To get a Text Message through the method linked to `OnTextMessageEvent`::

```csharp
private void WSOnTextMessage(string data)
{
    System.Console.WriteLine("TXT In: [" + data + "].");
    ws.SendTextMessage("ECHO: " + data);
}
```

To get a Binary Message through the method linked to `OnBinaryMessageEvent`::

```csharp
private void WSOnBynaryMessage(byte[] data)
{
    System.Console.WriteLine("BNR In: [" + data + "].");
}
```

To send mesage use the methods:

+ `SendTextMessage(string message)` To send a Text message.
+ `SendBinaryMessage(byte[] buffer)` To send a Binary message.

# Creating a Cerified for SSL

Firts of all, keep at hand all the information which is required to create a new certified, i.e.:

+ **Password for PFX**: w0rk1ng
+ **Key Length**: 512
+ **Algorithm**: RSA
+ **Country Name**: MX
+ **State or Province Name**: CDMX
+ **Locality Name**: CDMX
+ **Organization Name**: My Company
+ **Organizational Unit Name**: Desarrollo
+ **Common Name**: DEV
+ **Email Address**: myuser@mydomain.com.mx
+ **Amoutn of valid days**: 5000

> **Important**: The Password for PFX will be used get the certifies.


**1.** Creating a SelfSigned Certified

`
openssl req -new -x509 -days 5000 -key isat_key.pem -out isat_cert.pem
`

For example:

```cmd
$ openssl req -new -x509 -days 5000 -key isat_key.pem -out isat_cert.pem
  You are about to be asked to enter information that will be incorporated
  into your certificate request.
  What you are about to enter is what is called a Distinguished Name or a DN.
  There are quite a few fields but you can leave some blank
  For some fields there will be a default value,
  If you enter '.', the field will be left blank.
  -----
  Country Name (2 letter code) [AU]:MX
  State or Province Name (full name) [Some-State]:CDMX
  Locality Name (eg, city) []:CDMX
  Organization Name (eg, company) [Internet Widgits Pty Ltd]:My Company
  Organizational Unit Name (eg, section) []:Desarrollo
  Common Name (e.g. server FQDN or YOUR name) []:DEV
  Email Address []:myuser@mydomain.com.mx
```

**2.** Generating a PFX file

`openssl pkcs12 -export -out certificate.pfx -inkey isat_key.pem -in isat_cert.pem`

For example:

```cmd
$ openssl pkcs12 -export -out certificate.pfx -inkey isat_key.pem -in isat_cert.pem
  Enter Export Password:
  Verifying - Enter Export Password:
  $ ls
  certificate.pfx    isat.pem    isat_cert.pem    isat_key.pem
```


Now, you have a PXF file.

> **Important**: Do not forget add an exception on the browser in the case the webSocket is set to work with SSL.
