function Invoke-Socks {
    <#

    .SYNOPSIS
        Invoke-Socks is a PowerShell module that allows you to create a quick SOCKS proxy server.

    .DESCRIPTION
        Invoke-Socks is a PowerShell module that allows you to create a quick SOCKS proxy server. 
        This module is useful for penetration testing and red teaming engagements. Where you need 
        to pivot through a compromised host to access further network endpoints.

    .PARAMETER Port
        The port number to listen on for incoming SOCKS connections.

    .EXAMPLE
        PS C:\> Invoke-Socks -Port 1080

    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [Parameter(Mandatory = $false)]
        [string]$Ip = "0.0.0.0"
    )

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($Ip), $Port)
    $listener.Start()

    Write-Host "SOCKS5 proxy server started on ${Ip}:${Port}..."

    while ($true) {
        $client = $listener.AcceptTcpClient()
        Write-Host "Client connected from $($client.Client.RemoteEndPoint)"

        Start-ThreadJob -ScriptBlock {
            param($client)
            try {
                $clientStream = $client.GetStream()

                $buffer = New-Object byte[] 1024
                $bytesRead = $clientStream.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -eq 0) {
                    Write-Host "Handshake failed: No data received."
                    return
                }

                $clientVersion = $buffer[0]
                if ($clientVersion -ne 0x05) {
                    Write-Host "Unsupported SOCKS version: $clientVersion"
                    return
                }

                Write-Host  "SOCKS version: $clientVersion"

                $clientStream.WriteByte(0x05)
                $clientStream.WriteByte(0x00)

                $bytesRead = $clientStream.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -eq 0) {
                    Write-Host "Request parsing failed: No data received."
                    return
                }

                $cmd = $buffer[1]
                if ($cmd -ne 0x01) {
                    Write-Host "Unsupported command: $cmd"
                    $clientStream.Write(@(0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), 0, 10)
                    return
                }

                $addrType = $buffer[3]
                $destinationHost = ""
                $destinationPort = 0

                Write-Host "Command (cmd): $cmd"
                Write-Host "Address type (addrType): $addrType"
                Write-Host "Destination host: $destinationHost"
                Write-Host "Destination port: $destinationPort"

                if ($addrType -eq 0x01) {
                    # IPv4 Address
                    $destinationHost = "$($buffer[4]).$($buffer[5]).$($buffer[6]).$($buffer[7])"
                    $destinationPort = ($buffer[8] -shl 8) -bor $buffer[9]
                }
                elseif ($addrType -eq 0x03) {
                    # Domain Name
                    $domainLength = $buffer[4]
                    $destinationHost = [System.Text.Encoding]::ASCII.GetString($buffer, 5, $domainLength)
                    $destinationPort = ($buffer[5 + $domainLength] -shl 8) -bor $buffer[6 + $domainLength]
                }
                else {
                    Write-Host "Unsupported address type: $addrType"
                    return
                }

                Write-Host "Request to connect to ${destinationHost}:${destinationPort}"

                $destinationClient = New-Object System.Net.Sockets.TcpClient
                $destinationClient.Connect($destinationHost, $destinationPort)
                $destinationStream = $destinationClient.GetStream()

                $response = @(
                    0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                )
                $clientStream.Write($response, 0, $response.Length)

                $bufferSize = 8192

                while ($true) {
                    $buffer = New-Object byte[] $bufferSize
                    try {
                        if ($clientStream.DataAvailable) {
                            $clientBytes = $clientStream.Read($buffer, 0, $bufferSize)
                            if ($clientBytes -le 0) { break }
                            $destinationStream.Write($buffer, 0, $clientBytes)
                        }

                        if ($destinationStream.DataAvailable) {
                            $serverBytes = $destinationStream.Read($buffer, 0, $bufferSize)
                            if ($serverBytes -le 0) { break }
                            $clientStream.Write($buffer, 0, $serverBytes)
                        }
                    }
                    catch {
                        Write-Host "Error during data relay: $_"
                        break
                    }
                }
            }
            catch {
                Write-Host "Error: $_"
            }
            finally {
                $client.Close()
            }
        } -ArgumentList $client | Out-Null
    }
}
