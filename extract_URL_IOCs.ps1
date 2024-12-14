#Este script realiza a extração destas 2 URLs abaixo, retornando a saida em um arquivo .csv sem endereços duplicados.

# URLs dos sites
$urls = @(
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://danger.rulez.sk/projects/bruteforceblocker/blist.php"
)

# Inicializar uma lista para armazenar os IPs
$ips = @()

# Iterar sobre cada URL e baixar o conteúdo do site
foreach ($url in $urls) {
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
$uniqueIps | Out-File -FilePath "ips.csv" -Encoding utf8

# Verificar se o arquivo foi criado corretamente
if (Test-Path "ips.csv") {
    Write-Output "Arquivo ips.csv criado com sucesso!"
} else {
    Write-Output "Erro ao criar o arquivo ips.csv."
}
