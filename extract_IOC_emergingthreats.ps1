# URL do site
$url = @(
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
)

# Inicializar uma lista para armazenar os IPs
$ips = @()

# Iterar sobre cada URL e baixar o conteúdo do site
foreach ($url in $URL) {
    # Baixar o conteúdo do site
    $content = Invoke-WebRequest -Uri $url

    # Dividir o conteúdo em linhas
    $lines = $content.Content.Split("`n")

    # Extrair os endereços IP usando uma expressão regular
    foreach ($line in $lines) {
        if ($line -match '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b') {
            $ips += $matches[0].Trim() # Adiciona IP com remoção de espaços extras
        }
    }
}

# Remover duplicatas usando o cmdlet Select-Object -Unique
$uniqueIps = $ips | Select-Object -Unique

# Salvar os IPs em um arquivo CSV
$uniqueIps | Out-File -FilePath "emergingthreats.csv" -Encoding utf8

# Verificar se o arquivo foi criado corretamente
if (Test-Path "emergingthreats.csv") {
    Write-Output "Arquivo emergingthreats.csv criado com sucesso!"
} else {
    Write-Output "Erro ao criar o arquivo emergingthreats.csv"
}