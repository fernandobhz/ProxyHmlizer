Imports System.Net.Sockets
Imports System.Threading
Imports System.IO
Imports System.Net.Security
Imports System.Text
Imports System.Security.Cryptography.X509Certificates

Module Main

    Friend PlainTcpListener As TcpListener
    Friend SecureTcpListener As TcpListener

    Sub Log(Identifier As String, S As String, Optional IsError As Boolean = False)
        'Exit Sub

        Dim IdSize As Integer = 256 - Application.StartupPath.Length - Len("Log..txt")

        If Identifier.Length > IdSize Then
            Identifier = Identifier.Substring(0, IdSize)
        End If

        Dim Message As String = String.Format("{0} {1}{2}", Date.Now, S, vbCrLf)

        Dim LogPath As String = IO.Path.Combine(Application.StartupPath, String.Format("Log.{0}.txt", Identifier))
        My.Computer.FileSystem.WriteAllText(LogPath, Message, True)

        If IsError Then
            Dim ErrorPath As String = IO.Path.Combine(Application.StartupPath, String.Format("Log.{0}.txt", Identifier))
            My.Computer.FileSystem.WriteAllText(ErrorPath, Message, True)
        End If

    End Sub

    Sub Main()
        PlainTcpListener = New TcpListener(Net.IPAddress.Any, 80)
        PlainTcpListener.Start()

        'Do
        '    Dim TcpClient As TcpClient = PlainTcpListener.AcceptTcpClient
        '    HandleClient(TcpClient)
        'Loop


        Dim TPlain As New Thread(
            Sub()
                Do
                    Dim TcpClient As TcpClient = PlainTcpListener.AcceptTcpClient
                    HandleClient(TcpClient, TcpClient.GetStream)
                Loop
            End Sub)
        TPlain.Name = "Wait Plain TCP Connections"
        TPlain.IsBackground = True
        TPlain.Start()


        Dim CertBytes() As Byte = My.Computer.FileSystem.ReadAllBytes("c:\cert.cer")
        Dim Cert As New System.Security.Cryptography.X509Certificates.X509Certificate(CertBytes)

        SecureTcpListener = New TcpListener(Net.IPAddress.Any, 443)
        SecureTcpListener.Start()



        Dim TSecure As New Thread(
            Sub()
                Do
                    Dim TcpClient As TcpClient = SecureTcpListener.AcceptTcpClient
                    Dim Stream As Stream = TcpClient.GetStream

                    Dim Id As String = String.Empty

                    Try
                        Dim X = ParseHttpTalk(Stream, Sub(S As String) Debug.Print(S))
                        Id = X.Header.URLID(TcpClient, Stream)

                        Log(Id, X.Header.ToString & System.Text.Encoding.ASCII.GetString(X.Body))

                        Dim ConnectionEstablishedText As String = "HTTP/1.1 200 Connection established" & vbCrLf & "Proxy-agent: matt-dot-net" & vbCrLf & vbCrLf
                        Dim ConnectionEstablishedBytes() As Byte = System.Text.Encoding.ASCII.GetBytes(ConnectionEstablishedText)
                        Stream.Write(ConnectionEstablishedBytes, 0, ConnectionEstablishedBytes.Length)

                        Log(Id, "Connection established sent to browser")
                        Log(Id, "Will try auth as server")

                        Dim SSLStream As New SslStream(Stream)
                        SSLStream.AuthenticateAsServer(Cert, False, Security.Authentication.SslProtocols.Tls Or Security.Authentication.SslProtocols.Ssl2 Or Security.Authentication.SslProtocols.Ssl3, True)
                        'makecert.exe cert.cer -a sha1 -n "CN=matt-dot-net" -sr LocalMachine -ss My -sky signature -pe -len 2048
                        'http://www.codeproject.com/Articles/93301/Implementing-a-Multithreaded-HTTP-HTTPS-Debugging

                        Log(Id, "Auth as server worked")
                        Log(Id, "Handling client")

                        HandleClient(TcpClient, SSLStream)
                    Catch ex As Exception
                        If Not String.IsNullOrEmpty(Id) Then
                            Log(Id, ex.Message & vbCrLf & ex.StackTrace)
                        End If
                    End Try
                Loop
            End Sub)
        TSecure.Name = "Wait Secure TCP Connections"
        TSecure.IsBackground = True
        TSecure.Start()

        Do
            Thread.Sleep(100)
            Application.DoEvents()
        Loop

    End Sub

    Private Sp As String = ""

    Sub HandleClient(AClient As TcpClient, AStream As Stream)

        Dim T As New Thread(
            Sub()
                Dim BClient As New TcpClient
                Dim BStream As Stream = New MemoryStream 'Hack to solve visual studio warnings of null reference exception could be result on run-time
                Dim Id As String = String.Empty

                Try
                    Do
                        'Receiving request from browser
                        AStream.ReadTimeout = 30 * 1000 * 10
                        Dim A = ParseHttpTalk(AStream, Sub(S) Debug.Print(S))

                        Dim FullURL As String = A.Header.FullURL(AStream)
                        Dim URI As New Uri(FullURL)
                        Dim IpHost As String = Resolve(URI)
                        Dim IpPort As Integer = URI.Port
                        Id = A.Header.URLID(AClient, AStream)
                        Log(Id, Sp & "Received request to: " & FullURL & " on " & IpHost & ":" & IpPort & vbCrLf & A.Header.ToString)


                        'Check if server is the same that already connect
                        'Browser can reutilize an tcp connection with proxy to make request to anothers servers
                        If BClient.Connected Then
                            Dim Ip As String = BClient.Client.RemoteEndPoint.ToString
                            Dim Port As Integer = CType(BClient.Client.RemoteEndPoint, Net.IPEndPoint).Port

                            If Ip <> IpHost Or Port <> IpPort Then
                                Log(Id, "Browser reutilized connection to make request to a different domain, we will disconect the actual bclient and bstream and make a new one")
                                BStream.Dispose()
                                BClient.Close()
                                BClient = New TcpClient
                            End If
                        End If


                        'Connection to remote host
                        If Not BClient.Connected Then
                            Log(Id, "Will make a tcp connect to " & IpHost & ":" & IpPort)
                            BClient.Connect(IpHost, IpPort)
                            BStream = BClient.GetStream
                            BStream.ReadTimeout = 30 * 1000 * 10

                            If IpPort = 443 Then
                                Dim SSLStream As New SslStream(BClient.GetStream, False, New RemoteCertificateValidationCallback(AddressOf ValidateServerCertificate), Nothing)
                                SSLStream.AuthenticateAsClient(URI.Host)

                                BStream = SSLStream
                            End If
                        End If



                        'Requesting data to remote host
                        PrepareRequestHeaderFromBrowser(A)
                        Log(Id, "Requesting" & vbCrLf & A.Header.ToString)
                        A.WriteToStream(BStream)
                        Log(Id, "Requested")



                        'Sending content back to browser
                        Log(Id, "Will read response from server")
                        Dim B As HttpTalk = ParseHttpTalk(BStream, Sub(S As String) Log(Id, S)) ', Sub(S As String) Log(Id, S))
                        Log(Id, "Response arrived")

                        Log(Id, Sp & "Sending content back to browser" & vbCrLf & B.Header.ToString & System.Text.Encoding.ASCII.GetString(B.Body))
                        B.WriteToStream(AStream)
                        Log(Id, "Content sent to browser")

                        'Kill connection if not Keep-Alive
                        If A.Header.IsKeepAlive = False Or B.Header.IsKeepAlive = False Then
                            KillConnection(AClient, AStream)
                            KillConnection(BClient, BStream)
                            Exit Do
                        End If
                    Loop
                Catch ex As Exception
                    If Not String.IsNullOrEmpty(Id) Then
                        Log(Id, ex.Message & vbCrLf & ex.StackTrace, True)
                    End If

                    KillConnection(AClient, AStream)
                    KillConnection(BClient, BStream)
                End Try
            End Sub)

        T.Name = "Processing request"
        T.IsBackground = True
        T.Start()

        'T.Join()
    End Sub

    Public Function ValidateServerCertificate(ByVal sender As Object, ByVal certificate As X509Certificate, ByVal chain As X509Chain, ByVal sslPolicyErrors As SslPolicyErrors) As Boolean
        Return True

        If sslPolicyErrors = Net.Security.SslPolicyErrors.None Then
            Return True
        End If

        Console.WriteLine("Certificate error: {0}", sslPolicyErrors)

        ' Do not allow this client to communicate with unauthenticated servers.
        Return False
    End Function

    Sub KillConnection(TcpClient As TcpClient, Stream As Stream)
        Stream.Dispose()
        TcpClient.Close()
    End Sub

    Sub PrepareRequestHeadersToSendFromProxy(Ht As HttpTalk)

        If Ht.Header.Type = HttpTalkType.Response Then
            Throw New Exception("HttpTalk is a response not a request")
        End If

        Dim S As String = Ht.Header.FirstLine

        Dim Parts() = S.Split(" ")

        Dim Resource As String = Parts(1)

        If Resource.StartsWith("http://" & Ht.Header.Host) Then
            Resource = Resource.Substring(Len("http://" & Ht.Header.Host))
        ElseIf Resource.StartsWith("https://" & Ht.Header.Host) Then
            Resource = Resource.Substring(Len("https://" & Ht.Header.Host))
        End If

        Parts(1) = Resource

        Dim NewS As String = String.Join(" ", Parts)

        Ht.Header.Items(0) = NewS
    End Sub

    Function ParseHttpTalk(Stream As Stream, Log As Action(Of String)) As HttpTalk
        Dim Ht As New HttpTalk
        Ht.Header = ReadHttpHeader(Stream)

        Log("Header received: " & vbCrLf & Ht.Header.ToString)

        If Ht.Header.IsEmpty Then
            Throw New HttpTalkHeaderIsEmpty
        End If

        If Ht.Header.Type = HttpTalkType.Response Then

            If Ht.Header.IsChunkedResponse Then
                Log("Response is chunked")

                Ht.Body = ParseChunkedResponse(Stream, Log)

                Log("Response parsed")

                TransformHttpRequestHeader_ChunkedToContentLength(Ht)

                Log("Headers transformed" & vbCrLf & Ht.Header.ToString)
            Else
                Log("Response is content-length")

                Ht.Body = ParseContentLengthResponse(Stream, Ht.Header.ContentLength)

                Log("Response parsed")
            End If
        Else
            If Not String.IsNullOrEmpty(Ht.Header.ContentLength) Then
                Ht.Body = ParseContentLengthResponse(Stream, Ht.Header.ContentLength)
            End If
        End If

        Return Ht
    End Function

    Function ParseContentLengthResponse(Stream As Stream, Length As Integer) As Byte()
        Return ReadXBytes(Stream, Length)
    End Function


    Sub PrepareRequestHeaderFromBrowser(Ht As HttpTalk)
        StripAcceptEncoding(Ht)
        StripHSTS(Ht)
        TransformHttpRequestHeader_ChunkedToContentLength(Ht)
    End Sub

    Sub StripHSTS(Ht As HttpTalk)
        Dim NewH As New List(Of String)

        For Each S In Ht.Header.Items
            If Not S.ToLower.StartsWith("Strict-Transport-Security:".ToLower) Then
                NewH.Add(S)
            End If
        Next

        Ht.Header = NewH
    End Sub

    Sub StripAcceptEncoding(Ht As HttpTalk)
        Dim NewH As New List(Of String)

        For Each S In Ht.Header.Items
            If Not S.ToLower.StartsWith("Accept-Encoding:".ToLower) Then
                NewH.Add(S)
            End If
        Next

        Ht.Header = NewH
    End Sub

    Sub TransformHttpRequestHeader_ChunkedToContentLength(Ht As HttpTalk)
        Dim NewH As New List(Of String)

        For Each S In Ht.Header.Items
            If S.ToLower <> "Transfer-Encoding: chunked".ToLower Then
                NewH.Add(S)
            Else
                NewH.Add("Content-Length: " & Ht.Body.Length)
            End If
        Next

        Ht.Header = NewH
    End Sub

    Function ReadHttpHeader(Stream As Stream) As Byte()
        Using MS As New MemoryStream
            Do
                Dim LineBytes() As Byte = ReadUntilCRLF(Stream)

                If LineBytes.Length = 0 Then
                    MS.WriteByte(13)
                    MS.WriteByte(10)
                    Return MS.ToArray
                Else
                    MS.Write(LineBytes, 0, LineBytes.Length)
                    MS.WriteByte(13)
                    MS.WriteByte(10)
                End If
            Loop
        End Using
    End Function

    Function ReadUntilCRLF(Stream As Stream) As Byte()
        Using MS As New MemoryStream
            Do
                Dim B As Integer = Stream.ReadByte

                Do While B < 0
                    Throw New HttpTalkHeaderIsEmpty
                    B = Stream.ReadByte
                Loop

                If B <> 13 Then
                    MS.WriteByte(B)
                Else
                    Dim NextB As Byte = Stream.ReadByte

                    If NextB = 10 Then
                        Dim Ret = MS.ToArray
                        Return Ret
                    Else
                        MS.WriteByte(NextB)
                    End If
                End If
            Loop
        End Using
    End Function

    Function ParseChunkedResponse(Stream As Stream, Optional Log As Action(Of String) = Nothing) As Byte()
        Using MS As New MemoryStream

            If Log IsNot Nothing Then Log("Initializing read of response chunked")
            If Log IsNot Nothing Then Log("")

            Do
                If Log IsNot Nothing Then Log("Will read chunk size")
                Dim ChunkSizeBytes As Byte() = ReadUntilCRLF(Stream)
                Dim ChunkHexSize As String = System.Text.Encoding.ASCII.GetString(ChunkSizeBytes)
                Dim ChunkSize As Integer = Integer.Parse(ChunkHexSize, Globalization.NumberStyles.HexNumber)
                If Log IsNot Nothing Then Log("ChunkSize: " & ChunkSize)

                If ChunkSize = 0 Then
                    If Log IsNot Nothing Then Log("ChunkSize is Zero... Finished to parse chunked response")
                    Exit Do
                End If

                If Log IsNot Nothing Then Log("Calling ReadChunk to read a chunk of size: " & ChunkSize)
                Dim ChunkBytes() As Byte = ReadChunk(Stream, ChunkSize, Log)
                MS.Write(ChunkBytes, 0, ChunkBytes.Length)

                If Log IsNot Nothing Then Log("Will read and discard a CRLF")
                Dim StripCR = Stream.ReadByte
                Dim StripLF = Stream.ReadByte

                If Log IsNot Nothing Then Log("")
            Loop

            Return MS.ToArray
        End Using
    End Function

    Function ReadChunk(Stream As Stream, ChunkSize As Integer, Optional Log As Action(Of String) = Nothing) As Byte()
        Dim BuffSize As Integer = ChunkSize
        Dim Buff(BuffSize - 1) As Byte
        Dim DownloadedBytes As Integer
        Dim BytesRead As Integer

        Dim AmountDataToRead As Integer = BuffSize

        Using MS As New MemoryStream
            Do Until DownloadedBytes = ChunkSize
                Log("Will read from stream " & AmountDataToRead & " bytes")
                BytesRead = Stream.Read(Buff, 0, AmountDataToRead)
                MS.Write(Buff, 0, BytesRead)

                DownloadedBytes += BytesRead

                AmountDataToRead = AmountDataToRead - BytesRead

                If AmountDataToRead > 0 Then
                    Log("Read " & BytesRead & " bytes, missing " & AmountDataToRead & " bytes")
                Else
                    Log("Read " & BytesRead & ", chunk read is completed.")
                End If

                'Log("DATA RECEIVED:")
                'Log(System.Text.Encoding.ASCII.GetString(MS.ToArray, 0, MS.Length))

                Log("")
                Log("")
                Log("")
                Log("")
                Log("")
                Log("")
            Loop

            Return MS.ToArray
        End Using

        Log("Finished reading this chunk")
    End Function

    Function ReadXBytes(Stream As Stream, X As Integer) As Byte()
        Dim BuffSize As Integer = 65536
        Dim Buff(BuffSize - 1) As Byte
        Dim DownloadedBytes As Integer
        Dim BytesRead As Integer

        Using MS As New MemoryStream
            Do Until DownloadedBytes = X
                BytesRead = Stream.Read(Buff, 0, BuffSize)
                MS.Write(Buff, 0, BytesRead)

                DownloadedBytes += BytesRead
            Loop

            Return MS.ToArray
        End Using
    End Function

    Function Resolve(URI As Uri, Optional RecursionNo As Integer = 1) As String
        Dim P As New Process
        P.StartInfo = New ProcessStartInfo()
        P.StartInfo.RedirectStandardOutput = True
        P.StartInfo.UseShellExecute = False
        P.StartInfo.WindowStyle = ProcessWindowStyle.Hidden
        P.StartInfo.CreateNoWindow = True
        P.StartInfo.FileName = "c:\windows\system32\nslookup.exe"
        P.StartInfo.Arguments = URI.Host
        P.Start()

        Dim Result As String = P.StandardOutput.ReadToEnd
        'C:\Users\Fernando>nslookup ferna
        'Servidor:  PowerBox.home 
        'Address:  192.168.25.1
        '
        'Não é resposta autoritativa:
        'Nome:    username.wix.com
        'Address:  216.185.152.146
        'Aliases:  fernandobhz8.wix.com

        Dim ResultLines() As String = Result.Replace(vbCrLf, vbCr).Split(vbCr)

        Dim AddressLines As New List(Of String)

        For i = 4 To ResultLines.Count - 1
            AddressLines.Add(ResultLines(i))
        Next

        If AddressLines.Count = 0 Then
            If RecursionNo = 3 Then
                'Debug.Assert(False)
                Throw New Exception("Could not determine ip address of " & URI.ToString)
            End If

            Return Resolve(URI, RecursionNo + 1)
        End If


        Dim IP As String = String.Empty

        For Each L In AddressLines
            If L.Contains(".") Then
                Dim Parts() As String = L.Split(":")

                If Parts.Count > 1 Then
                    IP = Parts(1).Trim
                    Exit For
                Else
                    IP = L.Trim
                    Exit For
                End If
            End If
        Next

        If Not SeemsToBeIp(IP) Then
            If RecursionNo = 3 Then
                Debug.Assert(False)
                Throw New Exception("Could not determine ip address of " & URI.ToString)
            End If

            Return Resolve(URI, RecursionNo + 1)
        End If

        If Not ((IP.StartsWith("1")) Or
            (IP.StartsWith("2")) Or
            (IP.StartsWith("3")) Or
            (IP.StartsWith("4")) Or
            (IP.StartsWith("5")) Or
            (IP.StartsWith("6")) Or
            (IP.StartsWith("7")) Or
            (IP.StartsWith("8")) Or
            (IP.StartsWith("9")) Or
            (IP.StartsWith("0"))) Then

            Debug.Assert(False)
        End If

        Return IP
    End Function

    Function SeemsToBeIp(s As String) As Boolean
        If s.Count(Function(x) x = ".") = 3 Then
            Return True
        Else
            Return False
        End If
    End Function

End Module


Class HttpTalk
    Property Header As New HttpHeader
    Property Body As Byte()

    Function ResponseAsUTF8() As String
        If Body IsNot Nothing Then
            Return System.Text.Encoding.UTF8.GetString(Body)
        Else
            Return Nothing
        End If
    End Function

    Function ResponseAsASCII() As String
        If Body IsNot Nothing Then
            Return System.Text.Encoding.ASCII.GetString(Body)
        Else
            Return Nothing
        End If
    End Function

    Function ResponseAsISO88591() As String
        If Body IsNot Nothing Then
            Return System.Text.Encoding.GetEncoding("ISO-8859-1").GetString(Body)
        Else
            Return Nothing
        End If
    End Function

    Function FullTalkBytes() As Byte()
        Using MS As New MemoryStream
            Dim HeaderBytes As Byte() = Header
            MS.Write(HeaderBytes, 0, HeaderBytes.Length)
            If Body IsNot Nothing Then
                MS.Write(Body, 0, Body.Length)
            End If
            Return MS.ToArray
        End Using
    End Function

    Sub WriteToStream(Stream As Stream)
        Dim Buff() As Byte = FullTalkBytes()
        Stream.Write(Buff, 0, Buff.Length)
    End Sub

End Class

Class HttpHeader

    Property Items As New List(Of String)

    Function GetHeaderValue(HeaderName As String) As String
        Dim Header As String = Items.FirstOrDefault(Function(x) x.ToLower.StartsWith(HeaderName.ToLower))

        If String.IsNullOrEmpty(Header) Then
            Return Nothing
        End If

        Dim P As Integer = Header.IndexOf(":")

        If P <= 0 Then
            Throw New ArgumentException("Header don't have a : separator")
        Else
            P += 2
        End If

        Dim Value As String = Header.Substring(P)

        Return Value
    End Function

    Sub New()

    End Sub

    Sub New(HeaderText As String)
        Items = New List(Of String)(HeaderText.Replace(vbCrLf, vbCr).Split(vbCr))
    End Sub

    Sub New(HeaderLines As List(Of String))
        Items = HeaderLines
    End Sub

    Sub New(HeaderBytes As Byte())
        Dim HeaderText As String = System.Text.Encoding.ASCII.GetString(HeaderBytes)
        Items = New List(Of String)(HeaderText.Replace(vbCrLf, vbCr).Split(vbCr))
    End Sub

    Shared Widening Operator CType(HeaderText As String) As HttpHeader
        Return New HttpHeader(HeaderText)
    End Operator

    Shared Widening Operator CType(HeaderLines As List(Of String)) As HttpHeader
        Return New HttpHeader(HeaderLines)
    End Operator

    Shared Widening Operator CType(HeaderBytes As Byte()) As HttpHeader
        Return New HttpHeader(HeaderBytes)
    End Operator


    Shared Widening Operator CType(HttpHeader As HttpHeader) As String
        Return HttpHeader.ToString()
    End Operator

    Shared Widening Operator CType(HttpHeader As HttpHeader) As List(Of String)
        Return HttpHeader.Items
    End Operator

    Shared Widening Operator CType(HttpHeader As HttpHeader) As Byte()
        Return System.Text.Encoding.ASCII.GetBytes(HttpHeader.ToString)
    End Operator

    Public Overrides Function ToString() As String
        Return String.Join(vbCrLf, Items.ToArray)
    End Function

    Function URLID(TcpClient As TcpClient, Stream As Stream)
        Dim ID As String = FullURL(Stream).Replace("http://", "http_").Replace("https://", "secure-http_")
        ID = ID.Replace("/", "_").Replace("\", "_").Replace(":", "_").Replace("?", "_").Replace("=", "_").Replace("+", "_").Replace("&", "_").Replace("%", "_").Replace("*", "_") & "." & CType(TcpClient.Client.RemoteEndPoint, Net.IPEndPoint).Port
        Return ID
    End Function

    Function FullURL(Stream As Stream) As String
        Dim URL As String

        Dim Protocol As String

        If Stream IsNot Nothing Then
            If Stream.GetType = GetType(SslStream) Then
                Protocol = "https://"
            Else
                Protocol = "http://"
            End If
        Else
            Protocol = "http://"
        End If


        If RequestResource.StartsWith("/") Then 'That means the request is made via hosts files, so must build the url with host + resource
            If Host.EndsWith("/") Then
                URL = Protocol & Host & RequestResource.Substring(1)
            Else
                URL = Protocol & Host & "/" & RequestResource.Substring(1)
            End If
        Else 'Here, the request was made by browser to proxy, because the resource contains full url (maybe don't have the protocol http:// or https://)
            If (Not RequestResource.StartsWith("http://")) And (Not RequestResource.StartsWith("https://")) Then
                If RequestResource.EndsWith(":443") Then
                    URL = "https://" & RequestResource
                Else
                    URL = "http://" & RequestResource
                End If
            Else
                URL = RequestResource
            End If
        End If

        Return URL
    End Function

    Function IsEmpty() As Boolean
        If String.Join(vbCrLf, Items).Replace(vbCrLf, "").Trim.Length = 0 Then
            Return True
        Else
            Return False
        End If
    End Function

    ReadOnly Property FirstLine As String
        Get
            If Items.Count = 0 Then
                Throw New HttpTalkHeaderIsEmpty
            End If

            Return Items.Item(0)
        End Get
    End Property

    ReadOnly Property Type As HttpTalkType
        Get
            Dim Parts = FirstLine.Split(" ")

            If Parts(0) = "HTTP/1.1" Then
                Return HttpTalkType.Response
            Else
                Return HttpTalkType.Request
            End If
        End Get
    End Property

    ReadOnly Property ResponseCode As Integer
        Get
            If Type = HttpTalkType.Request Then
                Throw New ArgumentException("HttpTalkType is request, don't have reponse code")
            End If

            Return FirstLine.Split(" ")(1)
        End Get
    End Property

    ReadOnly Property RequestResource As String
        Get
            If Type = HttpTalkType.Response Then
                Throw New ArgumentException("HttpTalkType is response, don't have request resource")
            End If

            Return FirstLine.Split(" ")(1)
        End Get
    End Property

    ReadOnly Property Host As String
        Get
            Return GetHeaderValue("Host")
        End Get
    End Property

    ReadOnly Property CurrentDate As Date
        Get
            Return GetHeaderValue("Current-Date")
        End Get
    End Property

    ReadOnly Property LastModified As Date
        Get
            Return GetHeaderValue("Last-Modified")
        End Get
    End Property

    ReadOnly Property Server As String
        Get
            Return GetHeaderValue("Server")
        End Get
    End Property

    ReadOnly Property IsChunkedResponse As Boolean
        Get
            Return IIf(GetHeaderValue("Transfer-Encoding: chunked") Is Nothing, False, True)
        End Get
    End Property

    ReadOnly Property ContentLength As Integer
        Get
            Return GetHeaderValue("Content-Length")
        End Get
    End Property

    ReadOnly Property ContentType As String
        Get
            Return GetHeaderValue("Content-Type")
        End Get
    End Property

    ReadOnly Property Location As String
        Get
            Return GetHeaderValue("Location")
        End Get
    End Property

    ReadOnly Property Expires As Date
        Get
            Return GetHeaderValue("Expires")
        End Get
    End Property

    ReadOnly Property SetCookie As String
        Get
            Return GetHeaderValue("Set-Cookie")
        End Get
    End Property

    ReadOnly Property Cookie As String
        Get
            Dim Sc As String = SetCookie

            Dim p As Integer = Sc.IndexOf(";")

            If p = 0 Then
                Return Sc
            Else
                Return Sc.Substring(0, p)
            End If

        End Get
    End Property

    ReadOnly Property CacheControl As String
        Get
            Return GetHeaderValue("Cache-Control")
        End Get
    End Property

    Function IsKeepAlive() As Boolean
        Return IIf(GetHeaderValue("Connection") = "keep-alive", True, False)
    End Function

End Class

Enum HttpTalkType
    Request = 1
    Response = 2
End Enum

Class HttpTalkHeaderIsEmpty
    Inherits Exception

End Class