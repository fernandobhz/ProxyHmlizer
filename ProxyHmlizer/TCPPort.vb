Imports System.Net
Imports System.Net.Sockets

Class TCPPort

    Shared Function KillProcessUsingPort(ByVal Port As UShort) As Boolean

        'Microsoft Windows [Version 6.3.9600]
        '(c) 2013 Microsoft Corporation. Todos os direitos reservados.

        'C:\Users\Nando>netstat -o

        '        Active Connections

        '  Proto  Local Address          Foreign Address        State           PID
        '  TCP    127.0.0.1:51849        Nandissimo:51850       ESTABLISHED     5116
        '  TCP    127.0.0.1:51850        Nandissimo:51849       ESTABLISHED     5116

        Dim P As New Process
        P.StartInfo = New ProcessStartInfo(IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netstat.exe"), "-o")
        P.StartInfo.UseShellExecute = False
        P.StartInfo.CreateNoWindow = True
        P.StartInfo.RedirectStandardOutput = True
        P.Start()

        Dim Response As String = P.StandardOutput.ReadToEnd

        For Each Line In Split(Response, vbCrLf)

            Line = Line.Trim

            If Line.StartsWith("TCP") Then

                Dim pi As Integer = Line.IndexOf(":") + 1
                Dim pf As Integer = Line.IndexOf(" ", pi)
                Dim c As Integer = pf - pi

                Dim UsingPort As Integer = Line.Substring(pi, c)
                Dim PID As Integer = Line.Substring(69)

                If UsingPort = Port Then
                    Try
                        Dim PKill As Process = Process.GetProcessById(PID)
                        PKill.Kill()
                    Catch ex As Exception When Not Debugger.IsAttached
                        'Maybe the current(default) user don't have permission to kill the process
                        Return False
                    End Try

                End If

            End If

        Next

        Return True

    End Function

    Shared Function GetFreePort() As UShort
        Dim TcpListener As New TcpListener(IPAddress.Any, 0)
        TcpListener.Start()

        Dim IPEndPoint As IPEndPoint = TcpListener.LocalEndpoint
        Dim Port As UShort = IPEndPoint.Port

        TcpListener.Stop()

        Return Port
    End Function

    Shared Function IsFreePort(Port As UShort) As Boolean
        Try
            Dim TcpListener As New TcpListener(IPAddress.Any, Port)
            TcpListener.Start()
            TcpListener.Stop()
        Catch ex As Exception When Not Debugger.IsAttached
            Return False
        End Try

        Return True
    End Function

End Class
