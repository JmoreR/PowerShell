
    function BorrarCertificado {
        [CmdletBinding()]
        param (
            [string]$Ruta,
            [string]$Thumprint
        )

        
        
        begin {
            $Certs = Get-ChildItem $Ruta -Recurse
        }
        
        process {
            Foreach($Cert in $Certs) {

                If($Cert.NotAfter -lt (Get-Date) -And $Cert.Thumbprint -like $Thumprint)
                {
                    $Cert | Remove-Item -Force
                }
            }
            
        }
        
    }
    BorrarCertificado -Ruta "Cert:\LocalMachine\Root" -Thumprint 'Thumprintdelcertificadoaborrar' #Especificar un certificado a borrar
    BorrarCertificado -Ruta "Cert:\LocalMachine\My" -Thumprint "*" #Todos los certificados
