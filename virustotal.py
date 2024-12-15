import argparse
import requests
import time
import csv

# Função para buscar a quantidade de detecções para um endereço IP
def get_detection_count(api_key, ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        'x-apikey': api_key
    }
    response = requests.get(url, headers=headers)
    data = response.json()
    # Verifica se o campo 'data' e 'attributes' existem
    detection_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
    return detection_count

# Função para salvar resultados em um arquivo CSV
def save_results_to_csv(results, filename, api_key):
    with open(filename, 'w', newline='') as csv_file:
        fieldnames = ['IP', 'OrgAbuseEmail', 'OrgName', 'Quantidade de Detecções']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for ip_info in results:
            detection_count = get_detection_count(api_key, ip_info["IP"])
            writer.writerow({
                'IP': ip_info['IP'],
                'OrgAbuseEmail': ip_info['OrgAbuseEmail'],
                'OrgName': ip_info['OrgName'],
                'Quantidade de Detecções': detection_count
            })

def main():
    parser = argparse.ArgumentParser(description='Verifique endereços IP no VirusTotal e salve os resultados em arquivos CSV.')
    parser.add_argument('-api', required=True, help="Sua chave de API do VirusTotal")
    parser.add_argument('-l', required=False, help="Nome do arquivo que contém a lista de IPs")
    parser.add_argument('-i', required=False, help="Verificar um único endereço IP")
    args = parser.parse_args()

    api_key = args.api

    # Verificar qual argumento foi passado para a lista de IPs
    if args.i:
        ips = [args.i]
    elif args.l:
        try:
            with open(args.l, 'r') as file:
                ips = file.read().splitlines()
        except FileNotFoundError:
            print(f"O arquivo {args.l} não foi encontrado.")
            return
    else:
        print("Você deve especificar um arquivo de lista de IPs ou usar a opção -i para verificar um único endereço IP.")
        return

    # URL base sem o IP
    base_url = "https://www.virustotal.com/api/v3/ip_addresses/{}/historical_whois?limit=10"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    processed_ips = set()  # Conjunto para armazenar os IPs já processados
    ips_with_orgabuse = []  # Lista de IPs com valor no campo "OrgAbuseEmail"
    ips_without_orgabuse = []  # Lista de IPs sem valor no campo "OrgAbuseEmail"

    # Loop para processar 4 IPs a cada 75 segundos
    for i in range(0, len(ips), 4):
        batch_ips = ips[i:i+4]

        for ip in batch_ips:
            if ip in processed_ips:
                # IP já foi processado, pule para o próximo
                continue

            # Substitua o IP na URL
            url = base_url.format(ip)

            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()

                # Inicialize variáveis para armazenar informações
                ip_info = {"IP": ip, "OrgAbuseEmail": None, "OrgName": None}

                for item in data.get('data', []):
                    attributes = item.get("attributes", {}).get("whois_map", {})
                    org_abuse_email = attributes.get("OrgAbuseEmail")
                    org_name = attributes.get("OrgName")

                    if org_abuse_email:
                        ip_info["OrgAbuseEmail"] = org_abuse_email
                    if org_name:
                        ip_info["OrgName"] = org_name

                # Obtenha a quantidade de detecções
                detection_count = get_detection_count(api_key, ip)

                # Se o campo "OrgAbuseEmail" contém valor, adicione à lista de IPs com valor
                if ip_info["OrgAbuseEmail"]:
                    ips_with_orgabuse.append(ip_info)
                else:
                    ips_without_orgabuse.append(ip_info)

                # Adicione o IP ao conjunto de IPs processados
                processed_ips.add(ip)
                
            elif response.status_code == 204:
                print("Limite de taxa de solicitação excedido")
                break
           
            else:
                print(f"Erro ao consultar o VirusTotal para o IP {ip}: {response.status_code}")
                break

            # Aguarde 2 segundos antes de continuar para o próximo lote de IPs
            time.sleep(2)

    # Salve os resultados em arquivos CSV
    save_results_to_csv(ips_with_orgabuse, 'ips_com_orgabuse.csv', api_key)
    save_results_to_csv(ips_without_orgabuse, 'ips_sem_orgabuse.csv', api_key)

    # Imprimir os resultados no console
    print("\nEndereços IP com valor no campo 'AbuseEmail':")
    for ip_info in ips_with_orgabuse:
        detection_count = get_detection_count(api_key, ip_info["IP"])
        print(f"IP: {ip_info['IP']}, AbuseEmail: {ip_info['OrgAbuseEmail']}, ISP: {ip_info['OrgName']}, Quantidade de Detecções: {detection_count}")
    print("\nEndereços IP sem valor no campo 'AbuseEmail':")
    for ip_info in ips_without_orgabuse:
        detection_count = get_detection_count(api_key, ip_info["IP"])
        print(f"IP: {ip_info['IP']}, AbuseEmail: {ip_info['OrgAbuseEmail']}, ISP: {ip_info['OrgName']}, Quantidade de Detecções: {detection_count}")

if __name__ == '__main__':
    main()
