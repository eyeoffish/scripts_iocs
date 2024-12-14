# Função para listar as GPOs ativas e salvar em CSV
function Export-ActiveGPOs {
    # Verifica se o módulo GroupPolicy esta disponível
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Host "O modulo GroupPolicy nao esta instalado. Por favor, instale o RSAT antes de continuar." -ForegroundColor Red
        return
    }

    # Importa o módulo GroupPolicy
    Import-Module GroupPolicy

    # Obtém todas as GPOs e filtra apenas as ativas
    $activeGPOs = Get-GPO -All | Where-Object { $_.GpoStatus -ne 'AllSettingsDisabled' }

    # Verifica se há GPOs ativas no ambiente
    if ($activeGPOs.Count -eq 0) {
        Write-Host "Nenhuma GPO ativa encontrada no ambiente." -ForegroundColor Yellow
        return
    }

    # Define o caminho para salvar o arquivo CSV
    $outputPath = "C:\Temp\GPOsAtivas.csv"

    # Exporta as GPOs ativas para um arquivo CSV
    $activeGPOs | Select-Object DisplayName, GpoStatus, Id | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    # Exibe uma mensagem ao usuário
    Write-Host "Relatorio de GPOs ativas exportado para: $outputPath" -ForegroundColor Green
}

# Função para listar os usuarios que alteraram a senha nos últimos 30 dias e salvar em CSV
function Export-UsersPasswordChanged {
    # Obtém os usuários que alteraram a senha nos últimos 30 dias
    $users = Get-ADUser -Filter * -Properties PasswordLastSet |
        Where-Object { ($_.PasswordLastSet -ne $null) -and ($_.PasswordLastSet -gt (Get-Date).AddDays(-30)) }

    # Verifica se há usuários encontrados
    if ($users.Count -eq 0) {
        Write-Host "Nenhum usuario alterou a senha nos ultimos 30 dias." -ForegroundColor Yellow
        return
    }

    # Define o caminho para salvar o arquivo CSV
    $outputPath = "C:\Temp\UsuariosSenhaAlterada.csv"

    # Exporta os dados dos usuários para um arquivo CSV
    $users | Select-Object Name, SamAccountName, PasswordLastSet | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    # Exibe uma mensagem ao usuário
    Write-Host "Relatorio de usuarios que alteraram a senha nos ultimos 30 dias exportado para: $outputPath" -ForegroundColor Green
}

# Exibe o menu para o usuário
function Show-Menu {
    Clear-Host
    Write-Host "Escolha uma alternativa:" -ForegroundColor Cyan
    Write-Host "1. Listar as GPOs ativas"
    Write-Host "2. Listar usuarios que alteraram a senha nos ultimos 30 dias"
    Write-Host "0. Sair"
}

# Função principal para controle do menu
function Main {
    do {
        Show-Menu
        $choice = Read-Host "Digite o numero da alternativa desejada"

        switch ($choice) {
            1 {
                Export-ActiveGPOs
                break
            }
            2 {
                Export-UsersPasswordChanged
                break
            }
            0 {
                Write-Host "Saindo..." -ForegroundColor Green
                break
            }
            default {
                Write-Host "alternativa invalida, por favor escolha novamente." -ForegroundColor Red
                break
            }
        }

        # Espera o usuário pressionar uma tecla para voltar ao menu
        if ($choice -ne 0) {
            Read-Host "Pressione qualquer tecla para voltar ao menu"
        }

    } while ($choice -ne 0)
}

# Chama a função principal
Main
