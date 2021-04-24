#!/usr/bin/python
# -*- codificação: utf-8 -*-
#                               __         __
#                              /__)_   '_/(  _ _
#                             / ( (//)/(/__)( (//) 2.0
#                                  /
#
# Autor : Shankar Narayana Damodaran
# Ferramenta : RapidScan
# Uso : ./rapidscan.py example.com (ou) rapidsan.py example.com python
# Descrição: Este scanner automatiza o processo de varredura de segurança usando um
# multitude de ferramentas de segurança linux disponíveis e alguns scripts personalizados.
#

Importando as bibliotecas
importação sys
 tomada de importação
 subprocesso de importação
importar os
 tempo de importação
 sinal de importação
importação aleatória
 corda de importação
importação rosca
importação re
de urlparse importação urlsplit



# Scan Time Desapeser
Intervalos = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(segundos, granularidade=3):
    resultado = []
    segundos = segundos + 1
    para nome, contagem em intervalos:
        valor = segundos // contagem
        se valor:
            segundos -= valor * contagem
            resultado. apêndice("{}{}". formato(valor, nome))
    retorno '. unir(resultado[:granularidade])


def url_maker(url):
	se não re. match(r'http(s?) \:', url):
		url = 'https://' + url
	parsed = urlsplit(url)
	host = parsed. netloc
	se hospedar. startswith('www.'):
		host = host[4:]
	anfitrião de retorno 

def check_internet():
    os. sistema('ping -c1 github.com > rs_net 2>&1')
    se "0% de perda de pacote" em aberto('rs_net'). ler():
        val = 1
    outra coisa:
        val = 0
    os. sistema('rm rs_net > /dev/null 2>&1')
    retorno val


# Inicializando a classe do módulo de cores
classe bcolors:
    CABEÇALHO = \033[95m'
    OKBLUE = \033[94m'
    OKGREEN = \\033[92m'
    AVISO = \033[93m'
    BADFAIL = \\033[91m'
    ENDC = \033[0m'
    BOLD = \033[1m'
    SUBLINHADO = \033[4m'

    BG_ERR_TXT = \033[41m' # Para erros e acidentes críticos
    BG_HEAD_TXT = \033[100m'
    BG_ENDL_TXT = \033[46m'
    BG_CRIT_TXT = \033[45m'
    BG_HIGH_TXT = \033[41m'
    BG_MED_TXT = \033[43m'
    BG_LOW_TXT = \033[44m'
    BG_INFO_TXT = \033[42m'


Classifica a Gravidade da Vulnerabilidade
def vul_info(val):
	resultado =''
	se val == 'c':
		resultado = bcolores. BG_CRIT_TXT+" crítico"+bcolors. ENDC
	elif val == 'h':
		resultado = bcolores. BG_HIGH_TXT+" alto"+bcolors. ENDC
	elif val == 'm':
		resultado = bcolores. BG_MED_TXT+" médio"+bcolors. ENDC
	elif val == 'l':
		resultado = bcolores. BG_LOW_TXT+"baixo "+bcolors. ENDC
	outra coisa:
		resultado = bcolores. BG_INFO_TXT+" info"+bcolors. ENDC
	 resultado de retorno

# Lendas
proc_alta = bcolores. BADFAIL + "?" + bcolors. ENDC
proc_media = bcolors. AVISO + "?" + bcolors. ENDC
proc_baixa = bcolors. OKGREEN + "?" + bcolors. ENDC

# Vincula a vulnerabilidade com o nível de ameaça e o banco de dados de remediação
def vul_remed_info(v1,v2,v3):
	imprimir bcolors. BOLD+"Nível de Ameaça de Vulnerabilidade"+bcolors. ENDC
	imprimir "\t"+vul_info(v2)+" +bcolors. AVISO+str(tool_resp[v1][0])+bcolors. ENDC
	imprimir bcolors. NEGRITO+"Definição de Vulnerabilidade"+bcolors. ENDC
	imprimir "\t"+bcolors. BADFAIL+str(tools_fix[v3-1][1])+bcolors. ENDC
	imprimir bcolors. NEGRITO+"Remediação de Vulnerabilidade"+bcolors. ENDC
	imprimir "\t"+bcolors. OKGREEN+str(tools_fix[v3-1][2])+bcolors. ENDC


# RapidScan Help Context
ajudante de def ():
        imprimir bcolors. OKBLUE+"Informações:"+bcolors. ENDC
        imprimir "------------"
        imprimir "\t./rapidscan.py example.com: Escaneia o domínio example.com"
        imprimir "\t./rapidscan.py --update : Atualiza o scanner para a versão mais recente."
        imprimir "\t./rapidscan.py --ajuda : Exibe este contexto de ajuda."
        imprimir bcolors. OKBLUE+"Interativo:"+bcolors. ENDC
        imprimir "------------"
        imprimir "\tCtrl+C: Ignora o teste atual."
        imprimir "\tCtrl+Z: Quits RapidScan."
        imprimir bcolors. OKBLUE+"Legends:"+bcolors. ENDC
        imprimir "--------"
        imprimir "\t["+proc_high+"]: O processo de varredura pode levar mais tempo (não previsível)."
        imprimir "\t["+proc_med+"]: O processo de varredura pode levar menos de 10 minutos."
        imprimir "\t["+proc_low+"]: O processo de varredura pode levar menos de um minuto ou dois."
        imprimir bcolors. OKBLUE+"Informações de Vulnerabilidade:"+bcolors. ENDC
        imprimir "--------------------------"
        imprimir "\t"+vul_info('c')+": Requer atenção imediata, pois pode levar a compromisso ou indisponibilidade de serviço."
        imprimir "\t"+vul_info('h')+" : Pode não levar a umcompromisso imediato, mas há altas chances de probabilidade."
        imprimir "\t"+vul_info('m')+" : O invasor pode correlacionar múltiplas vulnerabilidades deste tipo para lançar um ataque sofisticado."
        imprimir "\t"+vul_info('l')+" : Não é umproblema sério, mas é recomendado para atender ao achado."
        imprimir "\t"+vul_info('i')+" : Não classificado comouma vulnerabilidade, simplesmente um alerta informativo útil a ser considerado. \n"


Linha Desomes
def claro():
        sys. stdout. escrever("\033[F")
        sys. stdout. escrever("\033[K")

# Logotipo rapidscan
logotipo def ():
	imprimir bcolors. AVISO
        imprimir("""\
                                  __         __
                                 /__)_  """+bcolors. BADFAIL+" ?" +bcolors. AVISO+"""_/(  _ _
                                / ( (//)/(/__)( (//) 2.0
                                     /
                     """+bcolors. ENDC+""(O scanner de vulnerabilidade da Web multi-ferramentas)
                            """)
        imprimir bcolors. ENDC

# Iniciando a classe de carregador/rotador ocioso
classe Spinner:
    ocupado = Falso
    atraso = 0,05

    @estatística
    def spinning_cursor():
        enquanto 1:
            para cursor em '|/\\': cursor de rendimento #????
            cursor #for em '????': cursor de rendimento
    def __init__(self, delay=Nenhum):
        auto. spinner_generator = self. spinning_cursor()
        se atraso e flutuar(atraso): self. atraso = atraso

    def spinner_task(self):
        tente:
            enquanto eu. ocupado:
                #sys.stdout.write (próximo (self.spinner_generator))
                imprimir bcolors. BG_ERR_TXT+próximo(eu. spinner_generator)+bcolors. ENDC,
                sys. stdout. flush()
                tempo. sono(eu. atraso)
                sys. stdout. escrever(\b')
                sys. stdout. flush()
        exceto (KeyboardInterrupt, SystemExit):
            #clear
            imprimir "\n\t" + bcolors. BG_ERR_TXT+"RapidScan recebeu uma série de acessos ctrl+C. Saindo..." +bcolors. ENDC
            sys. saída(1)

    def start(self):
        auto. ocupado = Verdadeiro
        rosca. Rosca(alvo=auto. spinner_task). começar()

    def stop(self):
        tente:
            auto. ocupado = Falso
            tempo. sono(eu. atraso)
        exceto (KeyboardInterrupt, SystemExit):
            #clear
            imprimir "\n\t" + bcolors. BG_ERR_TXT+"RapidScan recebeu uma série de acessos ctrl+C. Saindo..." +bcolors. ENDC
            sys. saída(1)
# Fim da classe de carregador/rotador

# Instanciando a classe spinner/carregador
spinner = Spinner()



# Scanners que serão usados e rotação de nomes de arquivos (padrão: ativado (1))
tool_names = [
                ["host","Host - Verifica a existência de endereço IPV6.","host",1],
                ["aspnet_config_err","ASP.Net Misconfiguração - Verificações de ASP.Net Desconfiguração.","wget",1],
                ["wp_check","WordPress Checker - Verifica para instalação do WordPress.","wget",1],
                ["drp_check", "Drupal Checker - Verifica para instalação drupal.","wget",1],
                ["joom_check", "Joomla Checker - Verifica para instalação joomla.","wget",1],
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],
                ["wafw00f","Wafw00f - Verificações para Firewalls de Aplicativos.","wafw00f",1],
                ["nmap","Nmap - Varredura Rápida [Apenas poucas verificações de porta]","nmap",1],
                ["TheHarvester","The Harvester - Scans for emails using The Google's passive search.","theHarvester",1],
                ["dnsrecon","DNSRecon - Tentativas de transferências múltiplas de zona em nameservers.","dnsrecon",1],
                #["feroz","Feroz - Tentativas de Transferência de Zona [Sem Força Bruta]", "feroz",1],
                ["dnswalk","DNSWalk - Trys Zone Transfer.","dnswalk",1],
                ["whois","WHOis - Verificações para informações de contato do administrador.","whois",1],
                ["nmap_header","Nmap [XSS Filter Check] - Verifica se o cabeçalho de proteção XSS está presente.","nmap",1],
                ["nmap_sloris","Nmap [Slowloris DoS] - Verificações para a Vulnerabilidade de Negação de Serviço Slowloris.","nmap",1],
                ["sslyze_hbleed","SSLyze - Verifica apenas para vulnerabilidade cardíaca.","sslyze",1],
                ["nmap_hbleed","Nmap [Heartbleed] - Verifica apenas para vulnerabilidade cardíaca.","nmap",1],
                ["nmap_poodle","Nmap [POODLE] - Verifica apenas a vulnerabilidade do Poodle.","nmap",1],
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Verifica apenas para injeção de CCS.","nmap",1],
                ["nmap_freak","Nmap [FREAK] - Verifica apenas a vulnerabilidade freak.","nmap",1],
                ["nmap_logjam","Nmap [LOGJAM] - Verifica a vulnerabilidade do LOGJAM.","nmap",1],
                ["sslyze_ocsp","SSLyze - Verificações para OCSP Stapling.","sslyze",1],
                ["sslyze_zlib","SSLyze - Verifica para ZLib Deflate Compression.","sslyze",1],
                ["sslyze_reneg","SSLyze - Verificações para suporte de renegociação segura e renegociação de clientes.","sslyze",1],
                ["sslyze_resum","SSLyze - Verifica para suporte de retomada da sessão com [Ingressos de IDs/TLS].","sslyze",1],
                ["lbd","LBD - Verificações para Balanceadores de Carga DNS/HTTP.","lbd",1],
                ["golismero_dns_malware","Golismero - Verifica se o domínio é falsificado ou sequestrado.","golismero",1],
                ["golismero_heartbleed","Golismero - Verifica apenas para vulnerabilidade cardíaca.","golismero",1],
                ["golismero_brute_url_predictables","Golismero - Forças Brutas para certos arquivos no Domínio.","golismero",1],
                ["golismero_brute_directories","Golismero - Forças Brutas para certos diretórios no Domínio.","golismero",1],
                ["golismero_sqlmap","Golismero - SQLMap [Recupera apenas a Bandeira DB]","golismero",1],
                ["dirb","DirB - Brutos o alvo para diretórios abertos.","dirb",1],
                ["xsser","XSSer - Verifica para ataques de scripting cross-site [XSS].","xsser",1],
                ["golismero_ssl_scan","Golismero SSL Scans - Realiza Varreduras relacionadas à SSL.","golismero",1],
                ["golismero_zone_transfer","Transferência da Zona golismero - Tentativa de Transferência de Zona.","golismero",1],
                ["golismero_nikto","Golismero Nikto Scans - Usa Nikto Plugin para detectar vulnerabilidades.","golismero",1],
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Descoberta subdomínia das Forças Brutas.","golismero",1],
                ["dnsenum_zone_transfer","DNSEnum - Tentativa de Transferência de Zona.","dnsenum",1],
                ["fierce_brute_subdomains","Feroz subdomínios Bruter - Descoberta subdomínia das Forças Brutas.","feroz",1],
                ["dmitry_email","DMitry - Passivamente Colhe e-mails do domínio.","dmitry",1],
                ["dmitry_subdomains","DMitry - Passivamente Colhe Subdomínios do Domínio.","dmitry",1],
                ["nmap_telnet","Nmap [TELNET] - Verifica se o serviço TELNET está em execução.","nmap",1],
                ["nmap_ftp","Nmap [FTP] - Verifica se o serviço FTP está em execução.","nmap",1],
                ["nmap_stuxnet","Nmap [STUXNET] - Verifica se o host é afetado pelo Worm STUXNET.","nmap",1],
                ["webdav","WebDAV - Verifica se o WEBDAV ativado no diretório home.","davtest",1],
                ["golismero_finger","Golismero - Faz uma impressão digital no Domínio.","golismero",1],
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],
                ["uniscan_dirbrute", "Diretórios Uniscan - Brutos no Domínio.","uniscan",1],
                ["uniscan_ministresser", "Uniscan - Stress Tests the Domain.","uniscan",1],
                ["uniscan_rfi","Uniscan - Checks for LFI, RFI e RCE.","uniscan",1],#50
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],
                ["nikto_xss","Nikto - Cheques para Apache Expect XSS Header.","nikto",1],
                ["nikto_subrute","Nikto - Brutos Subdomains.","nikto",1],
                ["nikto_shellshock","Nikto - Cheques para Shellshock Bug.","nikto",1],
                ["nikto_internalip","Nikto - Verificações para vazamento interno de IP.","nikto",1],
                ["nikto_putdel","Nikto - Cheques para HTTP PUT DEL.","nikto",1],
                ["nikto_headers","Nikto - Verifica os Cabeçalhos de Domínio.","nikto",1],
                ["nikto_ms01070","Nikto - Verificação da Vulnerabilidade MS10-070.","nikto",1],
                ["nikto_servermsgs","Nikto - Verificações para Problemas de Servidor.","nikto",1],
                ["nikto_outdated","Nikto - Verifica se o servidor está desatualizado.","nikto",1],
                ["nikto_httpoptions","Nikto - Verificações para opções HTTP no Domínio.","nikto",1],
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],
                ["nikto_ssl","Nikto - Realiza SSL Checks.","nikto",1],
                ["nikto_sitefiles","Nikto - Verifica quaisquer arquivos interessantes no Domínio.","nikto",1],
                ["nikto_paths","Nikto - Verifica por Caminhos Injetáveis.","nikto",1],
                ["dnsmap_brute","DNSMap - Subdomínios brutos.","dnsmap",1],
                ["nmap_sqlserver","Nmap - Verificações para MS-SQL Server DB","nmap",1],
                ["nmap_mysql", "Nmap - Verificações para MySQL DB","nmap",1],
                ["nmap_oracle", "Nmap - Verificações para ORACLE DB","nmap",1],
                ["nmap_rdp_udp","Nmap - Verifica para serviço de desktop remoto sobre UDP","nmap",1],
                ["nmap_rdp_tcp","Nmap - Verifica para serviço de desktop remoto sobre TCP","nmap",1],
                ["nmap_full_ps_tcp","Nmap - Realiza uma Varredura completa da porta TCP","nmap",1],
                ["nmap_full_ps_udp","Nmap - Realiza uma Varredura completa da porta UDP","nmap",1],
                ["nmap_snmp","Nmap - Verificações para o Serviço SNMP","nmap",1],
                ["aspnet_elmah_axd","Cheques para ASP.net Elmah Logger","wget",1],
                ["nmap_tcp_smb","Verificações para serviço SMB sobre TCP","nmap",1],
                ["nmap_udp_smb","Verificações para serviço SMB sobre UDP","nmap",1],
                ["wapiti","Wapiti - Verificações para SQLi, RCE, XSS e outras vulnerabilidades","wapiti",1],
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1],
                ["amass","AMass - Domínio bruto para Subdomínios","amass",1]
                ["burpsuite","burpsuite e uma proxy","amass",1]
                ["wireshark","um proxy mas para internet nao de alterar dados de sites","amass",1]
                
            ]


# Comando que é usado para iniciar a ferramenta (com parâmetros e params extras)
tool_cmd   = [
                ["anfitrião",""],
                ["wget -O temp_aspnet_config_err --tries=1","/%7C~.aspx"],
                ["wget -O temp_wp_check --tries=1","/wp-admin"],
                ["wget -O temp_drp_check --tries=1","/user"],
                ["wget -O temp_joom_check --tries=1","/administrador"],
                ["uniscan -e-u",""],
                ["wafw00f",""],
                ["nmap -F --aberto -Pn",""],
                ["TheHarvester -l 50 -b google -d",""
                ["dnsrecon-d",""],
                #["fierce -wordlist xxx -dns ","],
                ["dnswalk-d","."
                ["Whois",""],
                ["nmap -p80 -script http-security-headers -Pn",""
                ["nmap -p80.443 -script http-slowloris --max-paralelismo 500 -Pn ",""],
                ["sslyze - coração",""],
                ["nmap -p443 -script ssl-heartbleed -Pn",""
                ["nmap -p443 -script ssl-poodle -Pn","]
                ["nmap -p443 -script ssl-ccs-injection -Pn","]
                ["nmap -p443 -script ssl-enum-cifras -Pn",""
                ["nmap -p443 -script ssl-dh-params -Pn",""
                ["sslyze --certinfo=básico",""],
                ["sslyze --compressão",""],
                ["sslyze --reneg",""],
                ["sslyze --resum",""],
                ["lbd",""],
                ["golismero -e dns_malware scan",""],
                ["golismero -e escaneamento de coração",""],
                ["golismero -e brute_url_predictables scan","],
                ["golismero -e brute_directories scan",""],
                ["golismero -e sqlmap scan",""],
                ["dirb https://","-fi"]
                ["xsser --all=http://",""],
                ["golismero -e sslscan scan",""],
                ["golismero -e zone_transfer scan",""],
                ["golismero -e nikto scan",""],
                ["golismero -e brute_dns scan",""],
                ["dnsenum",""],
                ["feroz --domínio",""],
                ["dmitry -e",""],
                ["dmitry-s",""],
                ["nmap -p23 --aberto -Pn",""
                ["nmap -p21 --aberto -Pn",""
                ["nmap -script stuxnet-detect -p445 -Pn","]
                ["davtest -url https://",""],
                ["golismero -e fingerprint_web scan",""],
                ["uniscan -w -u",""],
                ["uniscan -q -u",""]
                ["uniscan -r -u",""],
                ["uniscan -s -u",""],
                ["uniscan -d -u",""],
                ["nikto -Plugins 'apache_expect_xss' -host","]
                ["nikto -Plugins 'subdomínio' -host",""
                ["nikto -Plugins 'shellshock' -host",""
                ["nikto -Plugins 'cookies' -host",""
                ["nikto -Plugins 'put_del_test' -host","]
                ["nikto -Plugins 'headers' -host",""
                ["nikto -Plugins 'ms10-070' -host",""],
                ["nikto -Plugins 'msgs' -host",""
                ["nikto -Plugins 'ultrapassado' -host ",""
                ["nikto -Plugins 'httpoptions' -host ",""
                ["nikto -Plugins 'cgi' -host",", "]
                ["nikto -Plugins 'ssl' -host",""
                ["nikto -Plugins 'sitefiles' -host","]
                ["nikto -Plugins 'paths' -host",", "]
                ["dnsmap",""],
                ["nmap -p1433 --open -Pn ",""],
                ["nmap -p3306 --open -Pn ",""],
                ["nmap -p1521 --open -Pn ",""],
                ["nmap -p3389 --aberto -sU -Pn ",""
                ["nmap -p3389 --aberto -sT-Pn ",""
                ["nmap -p1-65535 --aberto -Pn",""
                ["nmap -p1-65535 -sU --aberto -Pn",""],
                ["nmap -p161 -sU --aberto -Pn",""
                ["wget -O temp_aspnet_elmah_axd --tries=1","/elmah.axd"],
                ["nmap -p445.137-139 -aberto -Pn",""
                ["nmap -p137.138 --aberto -Pn",""
                ["wapiti","f txt-o temp_wapiti"],
                ["nmap -p80 -script=http-iis-webdav-vuln -Pn",""
                ["whatweb","a 1"],
                ["amasse enum -d",""]
		["burpsuite -bs",""]
		["wireshark -wk",""]
            ]


# Respostas da Ferramenta (Começa) [Respostas + Gravidade (c - crítica | h - alta | m - mídia | l - baixa | i - informação) + Referência para Definição e Remediação vuln]
tool_resp   = [
                ["Não tem um endereço IPv6. É bom ter um.","i",1],
                ["ASP.Net está mal configurado para jogar erros de pilha de servidor na tela.","m",2],
                ["WordPress Installation Found. Verifique se as vulnerabilidades correspondem a essa versão.","i",3],
                ["Instalação drupal encontrada. Verifique se as vulnerabilidades correspondem a essa versão.","i",4],
                ["Joomla Installation Found. Verifique se as vulnerabilidades correspondem a essa versão.","i",5],
                ["robôs.txt/sitemap.xml encontrados. Verifique se há informações sobre esses arquivos.","i",6],
                ["Sem firewall de aplicativos da Web detectado","m",7],
                ["Alguns portos estão abertos. Realize uma varredura completa manualmente.","l",8],
                ["Endereços de e-mail encontrados.","l",9],
                ["Transferência de zona bem sucedida usando dNSRecon. Reconfigure o DNS imediatamente.","h",10],
                #["Transferência de zona bem sucedida usando feroz. Reconfigure o DNS imediatamente.,""h",10],
                ["Transferência de zona bem sucedida usando dnswalk. Reconfigure o DNS imediatamente.","h",10],
                ["Whois Information Publicly Available.","i",11],
                ["Filtro de proteção XSS é desativado.","m",12],
                ["Vulnerável à Negação de Serviço Slowloris.","c",13],
                ["Vulnerabilidade HEARTBLEED Encontrada com SSLyze.","h",14],
                ["Vulnerabilidade HEARTBLEED Encontrada com Nmap.","h",14],
                ["Vulnerabilidade POODLE Detectada.","h",15],
                ["OpenSSL CCS Injection Detectado.","h",16],
                ["VULNERABILIDADE FREAK Detectada.","h",17],
                ["Vulnerabilidade LOGJAM Detectada.","h",18],
                ["Resposta OCSP mal sucedida.","m",19],
                ["Servidor suporta Desinflar a compressão.","m",20],
                ["Renegociação Segura não tem suporte.","m",21],
                ["Secure Retomada sem suporte com (Sessions IDs/TLS Tickets).","m",22],
                ["Sem balanceadores de carga baseados em DNS/HTTP encontrados.","l",23],
                ["O domínio é falsificado/sequestrado.","h",24],
                ["Vulnerabilidade HEARTBLEED Encontrada com Golismero.","h",14],
                ["Arquivos Abertos Encontrados com Golismero BruteForce.","m",25],
                ["Diretórios Abertos Encontrados com Golismero BruteForce.","m",26],
                ["DB Banner recuperado com SQLMap.","l",27],
                ["Diretórios Abertos Encontrados com DirB.","m",26],
                ["XSSer encontrou vulnerabilidades XSS.","c",28],
                ["Encontrei vulnerabilidades relacionadas à SSL com Golismero.","m",29],
                ["Transferência de zona bem sucedida com Golismero. Reconfigure o DNS imediatamente.","h",10],
                ["Golismero Nikto Plugin encontrou vulnerabilidades.","m",30],
                ["Encontrados Subdomínios com Golismero.","m",31],
                ["Transferência de zona bem sucedida usando dNSEnum. Reconfigure o DNS imediatamente.","h",10],
                ["Encontrados Subdomínios com Ferozes.","m",31],
                ["Endereços de e-mail descobertos com DMitry.","l",9],
                ["Subdomínios descobertos com DMitry.","m",31],
                ["Telnet Service Detectado.","h",32],
                ["Serviço FTP Detectado.","c",33],
                ["Vulnerável ao STUXNET.","c",34],
                ["WebDAV Ativado.","m",35],
                ["Encontrei algumas informações através de Impressões Digitais.","l",36],
                ["Arquivos Abertos Encontrados com Uniscan.","m",25],
                ["Diretórios Abertos Encontrados com a Uniscan.","m",26],
                ["Vulnerável a Testes de Estresse.","h",37],
                ["Uniscan detectou possível LFI, RFI ou RCE.","h",38],
                ["Uniscan detectou possíveis XSS, SQLi, BSQLi.","h",39],
                ["Apache Expect XSS Header não está presente.","m",12],
                ["Encontrados Subdomínios com Nikto.","m",31],
                ["Servidor web vulnerável ao Shellshock Bug.","c",40],
                ["Webserver vaza IP Interno.","l",41],
                ["HTTP PUT DEL Métodos Ativados.","m",42],
                ["Alguns cabeçalhos vulneráveis expostos.","m",43],
                ["Servidor web vulnerável ao MS10-070.","h",44],
                ["Alguns problemas encontrados no Webserver.","m",30],
                ["Webserver está desatualizado.","h",45],
                ["Alguns problemas encontrados com opções HTTP.","l",42],
                ["Diretórios CGI Enumerados.","l",26],
                ["Vulnerabilidades relatadas em SSL Scans.","m",29],
                ["Arquivos Interessantes Detectados.","m",25],
                ["Caminhos Injetáveis Detectados.","l",46],
                ["Found Subdomains with DNSMap.","m",31],
                ["MS-SQL DB Service Detected.","l",47],
                ["MySQL DB Service Detected.","l",47],
                ["ORACLE DB Service Detected.","l",47],
                ["RDP Server Detected over UDP.","h",48],
                ["RDP Server Detected over TCP.","h",48],
                ["TCP Ports are Open","l",8],
                ["UDP Ports are Open","l",8],
                ["SNMP Service Detected.","m",49],
                ["Elmah is Configured.","m",50],
                ["SMB Ports are Open over TCP","m",51],
                ["SMB Ports are Open over UDP","m",51],
                ["Wapiti discovered a range of vulnerabilities","h",30],
                ["IIS WebDAV is Enabled","m",35],
                ["X-XSS Protection is not Present","m",12],
                ["Found Subdomains with AMass","m",31]
				["burpsuite proxy VPN","l",30],



            ]

# Tool Responses (Ends)



# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
tool_status = [
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],
                #["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]],
                ["No names were discovered",1,proc_med," < 15m","amass",["The system was unable to build the pool of resolvers"]]



            ]

# Vulnerabilities and Remediation
tools_fix = [
					[1, "Not a vulnerability, just an informational alert. The host does not have IPv6 support. IPv6 provides more security as IPSec (responsible for CIA - Confidentiality, Integrity and Availablity) is incorporated into this model. So it is good to have IPv6 Support.",
							"It is recommended to implement IPv6. More information on how to implement IPv6 can be found from this resource. https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
					[2, "Sensitive Information Leakage Detected. The ASP.Net application does not filter out illegal characters in the URL. The attacker injects a special character (%7C~.aspx) to make the application spit sensitive information about the server stack.",
							"It is recommended to filter out special charaters in the URL and set a custom error page on such situations instead of showing default error messages. This resource helps you in setting up a custom error page on a Microsoft .Net Application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
					[3, "It is not bad to have a CMS in WordPress. There are chances that the version may contain vulnerabilities or any third party scripts associated with it may possess vulnerabilities",
							"Recomenda-se ocultar a versão do WordPress. Este recurso contém mais informações sobre como proteger seu Blog WordPress. https://codex.wordpress.org/Hardening_WordPress"],
					[4, "Não é ruim ter um CMS em Drupal. Há chances de que a versão possa conter vulnerabilidades ou quaisquer scripts de terceiros associados a ela possam possuir vulnerabilidades",
							"Recomenda-se ocultar a versão do Drupal. Este recurso contém mais informações sobre como proteger seu Blog Drupal. https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
					[5, "Não é ruim ter um CMS em Joomla. Há chances de que a versão possa conter vulnerabilidades ou quaisquer scripts de terceiros associados a ela possam possuir vulnerabilidades",
							"Recomenda-se esconder a versão de Joomla. Este recurso contém mais informações sobre como proteger seu Blog Joomla. https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
					[6, "Às vezes, robôs.txt ou sitemap.xml podem conter regras de tal forma que certos links que não deveriam ser acessados/indexados por rastreadores e mecanismos de busca. Os mecanismos de busca podem pular esses links, mas os atacantes poderão acessá-los diretamente."
							"É uma boa prática não incluir links confidenciais nos robôs ou arquivos do sitemap."],
					[7, "Sem um Firewall de aplicativos da Web, um invasor pode tentar injetar vários padrões de ataque manualmente ou usando scanners automatizados. Um scanner automatizado pode enviar hordas de vetores de ataque e padrões para validar um ataque, também há chances de o aplicativo obter DoS'ed (Negação de Serviço)",
							"Os Firewalls de aplicativos da Web oferecem grande proteção contra ataques comuns da Web, como XSS, SQLi, etc. Eles também fornecem uma linha adicional de defesa à sua infraestrutura de segurança. Este recurso contém informações sobre firewalls de aplicativos web que podem se adequar ao seu aplicativo. https://www.gartner.com/reviews/market/web-application-firewall"],
					[8, "Portas Abertas dão aos atacantes uma dica para explorar os serviços. Os atacantes tentam recuperar informações de banner através das portas e entender que tipo de serviço o host está executando",
							"Recomenda-se fechar as portas de serviços não utilizados e usar um firewall para filtrar as portas sempre que necessário. Esse recurso pode dar mais insights. https://security.stackexchange.com/a/145781/6137"],
					[9, "As chances são muito menores de comprometer um alvo com endereços de e-mail. No entanto, os atacantes usam isso como um dado de suporte para coletar informações em torno do alvo. Um invasor pode fazer uso do nome de usuário no endereço de e-mail e realizar ataques de força bruta não apenas em servidores de e-mail, mas também em outros painéis legítimos como SSH, CMS, etc com uma lista de senhas, pois eles têm um nome legítimo. No entanto, isso é um tiro no cenário escuro, o atacante pode ou não ser bem sucedido dependendo do nível de interesse",
							"Uma vez que as chances de exploração são fracas, não há necessidade de agir. A remediação perfeita seria escolher diferentes nomes de usuário para diferentes serviços será mais atencioso."
					[10, "A Transferência de Zona revela informações topológicas críticas sobre o alvo. O invasor poderá consultar todos os registros e terá mais ou menos conhecimento completo sobre seu host."
							"A boa prática é restringir a Transferência de Zona, dizendo ao Mestre quais são os IPs dos escravos que podem ter acesso à consulta. Este recurso SANS fornece mais informações. https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
					[11, "O endereço de e-mail do administrador e outras informações (endereço, telefone, etc) está disponível publicamente. Um invasor pode usar essas informações para alavancar um ataque. Isso pode não ser usado para realizar um ataque direto, pois isso não é uma vulnerabilidade. No entanto, um invasor faz uso desses dados para construir informações sobre o alvo."
							"Alguns administradores intencionalmente teriam tornado essas informações públicas, neste caso podem ser ignoradas. Caso não, recomenda-se mascarar as informações. Este recurso fornece informações sobre esta correção. http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
					[12, "Como o alvo está faltando este cabeçalho, os navegadores mais antigos estarão propensos a ataques XSS refletidos."
							"Os navegadores modernos não enfrentam problemas com essa vulnerabilidade (cabeçalhos ausentes). No entanto, navegadores mais antigos são fortemente recomendados para serem atualizados."
					[13, "Este ataque funciona abrindo várias conexões simultâneas ao servidor web e as mantém vivas o máximo possível, enviando continuamente solicitações HTTP parciais, que nunca são concluídas. Eles facilmente deslizam pelo IDS enviando solicitações parciais."
							"Se você estiver usando o Módulo Apache, 'mod_antiloris' ajudaria. Para outra configuração, você pode encontrar uma correção mais detalhada sobre este recurso. https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
					[14, "Essa vulnerabilidade vaza seriamente informações privadas do seu host. Um invasor pode manter a conexão TLS viva e pode recuperar um máximo de 64K de dados por batimento cardíaco."
							"O PFS (Perfect Forward Secrecy) pode ser implementado para dificultar a descriptografia. A remediação completa e as informações de recursos estão disponíveis aqui. http://heartbleed.com/"],
					[15, "Ao explorar essa vulnerabilidade, um invasor poderá obter acesso a dados confidenciais em uma sessão n criptografada, como ids de sessão, cookies e com esses dados obtidos, poderá se passar por esse usuário em particular."
							"Isso é uma falha no Protocolo SSL 3.0. Uma melhor remediação seria desativar usando o protocolo SSL 3.0. Para obter mais informações, verifique este recurso. https://www.us-cert.gov/ncas/alerts/TA14-290A"],
					[16, "Esses ataques ocorrem na Negociação SSL (Aperto de Mão), o que faz com que o cliente desconheça o ataque. Alterando com sucesso o aperto de mão, o invasor será capaz de intrometer todas as informações que são enviadas do cliente para o servidor e vice-versa",
							"Atualizar o OpenSSL para versões mais recentes irá mitigar esse problema. Esse recurso fornece mais informações sobre a vulnerabilidade e a remediação associada. http://ccsinjection.lepidum.co.jp/"],
					[17, "Com essa vulnerabilidade, o invasor poderá realizar um ataque MiTM e, assim, comprometer o fator de confidencialidade."
							"Atualizar o OpenSSL para a versão mais recente irá mitigar esse problema. Versões anteriores ao 1.1.0 são propensas a essa vulnerabilidade. Mais informações podem ser encontradas neste recurso. https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
					[18, "Com o ataque LogJam, o invasor será capaz de rebaixar a conexão TLS que permite ao invasor ler e modificar quaisquer dados passados sobre a conexão."
							"Certifique-se de que todas as bibliotecas TLS que você usa estejam atualizadas, que os servidores que você mantém usem primes de 2048 ou maiores, e que os clientes que você mantém rejeitem as primes Diffie-Hellman menores que 1024 bits. Mais informações podem ser encontradas neste recurso. https://weakdh.org/"],
					[19, "Permite que invasores remotos causem uma negação de serviço (acidente) e possivelmente obtenham informações confidenciais em aplicativos que usam o OpenSSL, através de uma mensagem de aperto de mão clienteHello malformada que desencadeia um acesso de memória fora dos limites."
							" As versões OpenSSL 0.9.8h até 0.9.8q e 1.0.0 a 1.0c são vulneráveis. Recomenda-se atualizar a versão OpenSSL. Mais recursos e informações podem ser encontrados aqui. https://www.openssl.org/news/secadv/20110208.txt"],
					[20, "Caso contrário, denominado como BREACH atack, explora a compressão no protocolo HTTP subjacente. Um invasor poderá obter endereços de e-mail, tokens de sessão, etc. do tráfego web criptografado TLS."
							"Desligar a compactação TLS não atenua essa vulnerabilidade. O primeiro passo para a mitigação é desativar a compressão Zlib seguida de outras medidas mencionadas neste recurso. http://breachattack.com/"],
					[21, "Caso contrário, denominado como ataque de injeção de texto simples, que permite que os invasores do MiTM insiram dados em sessões HTTPS e possivelmente outros tipos de sessões protegidas por TLS ou SSL, enviando uma solicitação não autenticada que é processada retroativamente por um servidor em um contexto pós-renegociação."
							"Etapas detalhadas de remediação podem ser encontradas a partir desses recursos. https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011-06-03-ssl-renego/ "],
					[22, "Essa vulnerabilidade permite que os invasores roubem sessões TLS existentes dos usuários."
							"Melhor conselho é desativar a retomada da sessão. Para endurecer a retomada da sessão, siga esse recurso que tem algumas informações consideráveis. https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
					[23, "Isso não tem nada a ver com riscos de segurança, no entanto, os atacantes podem usar essa indisponibilidade de balanceadores de carga como uma vantagem para alavancar um ataque de negação de serviço em determinados serviços ou em todo o aplicativo em si."
							"Os Balanceadores de carga são altamente encorajados para qualquer aplicação web. Eles melhoram os tempos de desempenho, bem como a disponibilidade de dados durante os momentos de paralisação do servidor. Para saber mais informações sobre balanceadores de carga e configuração, verifique este recurso. https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
					[24, "Um invasor pode encaminhar solicitações que vêm para a URL legítima ou aplicativo web para um endereço de terceiros ou para a localização do invasor que pode servir malware e afetar a máquina do usuário final."
							"É altamente recomendável implantar o DNSSec no alvo do host. A implantação completa do DNSSEC garantirá que o usuário final esteja se conectando ao site real ou a outro serviço correspondente a um nome de domínio específico. Para obter mais informações, verifique este recurso. https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
					[25, "Os atacantes podem encontrar uma quantidade considerável de informações desses arquivos. Há até chances de os atacantes obterem acesso a informações críticas desses arquivos."
							"Recomenda-se bloquear ou restringir o acesso a esses arquivos, a menos que seja necessário."
					[26, "Os atacantes podem encontrar uma quantidade considerável de informações desses diretórios. Há até chances de os atacantes obterem acesso a informações críticas desses diretórios."
							"Recomenda-se bloquear ou restringir o acesso a esses diretórios, a menos que seja necessário."
					[27, "Pode não ser SQLi vulnerável. Um atacante poderá saber que o host está usando um backend para operação."
							"Banner Grabbing deve ser restrito e o acesso aos serviços de fora deve ser mínimo."
					[28, "Um invasor será capaz de roubar cookies, desfigurar o aplicativo da Web ou redirecionar para qualquer endereço de terceiros que possa servir malware."
							"A validação de entrada e a higienização da saída podem impedir completamente os ataques de Scripting (XSS) do Cross Site. Os ataques XSS podem ser mitigados no futuro seguindo corretamente uma metodologia de codificação segura. O recurso abrangente a seguir fornece informações detalhadas sobre a correção dessa vulnerabilidade. https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
					[29, "As vulnerabilidades relacionadas à SSL quebram o fator de confidencialidade. Um atacante pode realizar um ataque MiTM, intrepret e escutar a comunicação."
							"A implementação adequada e a versão atualizada das bibliotecas SSL e TLS são muito críticas quando se trata de bloquear vulnerabilidades relacionadas ao SSL."
					[30, "O Scanner Particular encontrou várias vulnerabilidades que um invasor pode tentar explorar o alvo."
							"Consulte rs-vulnerability-report para visualizar as informações completas da vulnerabilidade, uma vez que a varredura seja concluída."
					[31, "Os atacantes podem coletar mais informações de subdomínios relacionados ao domínio pai. Os atacantes podem até encontrar outros serviços dos subdomínios e tentar aprender a arquitetura do alvo. Há até chances de o atacante encontrar vulnerabilidades à medida que a superfície de ataque fica maior com mais subdomínios descobertos."
							"Às vezes é sábio bloquear sub domínios como desenvolvimento, encenação para o mundo exterior, pois dá mais informações ao atacante sobre a pilha de tecnologia. Práticas complexas de nomeação também ajudam na redução da superfície de ataque, pois os atacantes têm dificuldade em realizar o brutal por meio de dicionários e listas de palavras."
					[32, "Através deste protocolo preterido, um invasor pode ser capaz de realizar MiTM e outros ataques complicados."
							"É altamente recomendável parar de usar esse serviço e ele está muito desatualizado. O SSH pode ser usado para substituir o TELNET. Para obter mais informações, verifique este recurso https://www.ssh.com/ssh/telnet"],
					[33, "Este protocolo não suporta comunicação segura e há provavelmente altas chances de o atacante espionar a comunicação. Além disso, muitos programas FTP têm explorações disponíveis na web de tal forma que um invasor pode travar diretamente o aplicativo ou obter um acesso SHELL a esse alvo."
							"A correção sugerida adequada é usar um protocolo SSH em vez de FTP. Ele suporta comunicação segura e as chances de ataques MiTM são bastante raras."
					[34, "O StuxNet é um worm nível 3 que expõe informações críticas da organização alvo. Era uma arma cibernética que foi projetada para frustrar a inteligência nuclear do Irã. Seriamente me pergunto como chegou aqui? Espero que não seja um Nmap falso positivo ;)",
							"É altamente recomendável realizar uma varredura completa de rootkit no host. Para obter mais informações, consulte este recurso. https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
					[35, "O WebDAV deve conter múltiplas vulnerabilidades. Em alguns casos, um invasor pode ocultar um arquivo DLL malicioso no compartilhamento do WebDAV, no entanto, e ao convencer o usuário a abrir um arquivo perfeitamente inofensivo e legítimo, executar código sob o contexto desse usuário",
							"Recomenda-se desativar o WebDAV. Alguns recursos críticos sobre o WebDAV desembramento podem ser encontrados nesta URL. https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
					[36, "Os atacantes sempre fazem uma impressão digital de qualquer servidor antes de lançar um ataque. A impressão digital lhes dá informações sobre o tipo de servidor, conteúdo- eles estão servindo, últimas modificações vezes etc, isso dá a um invasor para aprender mais informações sobre o alvo",
							"Uma boa prática é ofuscar a informação para o mundo exterior. Fazendo isso, os atacantes terão dificuldade em entender a pilha de tecnologia do servidor e, portanto, aproveitar um ataque."
					[37, "Os atacantes tentam principalmente tornar os aplicativos da Web ou o serviço inúteis inundando o alvo, de tal forma que bloqueia o acesso a usuários legítimos. Isso pode afetar os negócios de uma empresa ou organização, bem como a reputação",
							"Ao garantir os balanceadores de carga adequados, configurando limites de taxa e múltiplas restrições de conexão, esses ataques podem ser drasticamente mitigados."
					[38, "Os intrusos poderão incluir remotamente arquivos shell e poderão acessar o sistema de arquivos principais ou poderão ler todos os arquivos também. Há ainda mais chances de o invasor executar remotamente o código no sistema de arquivos."
							"As práticas de código seguro evitarão principalmente ataques de LFI, RFI e RCE. O recurso a seguir fornece uma visão detalhada sobre práticas seguras de codificação. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
					[39, "Os hackers serão capazes de roubar dados do backend e também podem autenticar-se para o site e podem se passar por qualquer usuário, uma vez que eles têm controle total sobre o backend. Eles podem até acabar com todo o banco de dados. Os atacantes também podem roubar informações de cookies de um usuário autenticado e podem até redirecionar o alvo para qualquer endereço malicioso ou desfigurar totalmente o aplicativo."
							"A validação adequada de entrada deve ser feita antes de consultar diretamente as informações do banco de dados. Um desenvolvedor deve se lembrar de não confiar na entrada de um usuário final. Seguindo uma metodologia de codificação segura, ataca como SQLi, XSS e BSQLi. Os seguintes guias de recursos sobre como implementar uma metodologia de codificação segura no desenvolvimento de aplicativos. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
					[40, "Os atacantes exploram a vulnerabilidade no BASH para executar a execução remota de código no alvo. Um atacante experiente pode facilmente assumir o sistema de destino e acessar as fontes internas da máquina",
							"Essa vulnerabilidade pode ser atenuada corrigindo a versão do BASH. O recurso a seguir fornece uma análise indepth da vulnerabilidade e como atenuá-la. https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability"],
					[41, "Dá ao atacante uma ideia de como o esquema de endereços é feito internamente na rede organizacional. Descobrir os endereços privados usados dentro de uma organização pode ajudar os invasores na realização de ataques em camadas de rede com o objetivo de penetrar na infraestrutura interna da organização."
							"Restringir as informações da bandeira para o mundo exterior do serviço de divulgação. Mais informações sobre a mitigação dessa vulnerabilidade podem ser encontradas aqui. https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
					[42, "Há chances de um invasor manipular arquivos no servidor web."
							"Recomenda-se desativar os métodos HTTP PUT e DEL caso se você não usar nenhum Serviço de API REST. Seguir recursos ajuda a desabilitar esses métodos. http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how-to-disable-http-methods-head-put-delete-option/"],
					[43, "Os atacantes tentam aprender mais sobre o alvo a partir da quantidade de informações expostas nos cabeçalhos. Um invasor pode saber que tipo de tecnologia empilhar um aplicativo web está enfatizando e muitas outras informações."
							"Banner Grabbing deve ser restrito e o acesso aos serviços de fora deve ser mínimo."
					[44, "Um invasor que explorou com sucesso essa vulnerabilidade poderia ler dados, como o estado de exibição, que foi criptografado pelo servidor. Essa vulnerabilidade também pode ser usada para adulteração de dados, que, se explorada com sucesso, pode ser usada para descriptografar e adulterar os dados criptografados pelo servidor."
							"A Microsoft lançou um conjunto de patches em seu site para mitigar esse problema. As informações necessárias para corrigir essa vulnerabilidade podem ser inferidas a partir deste recurso. https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
					[45, "Qualquer servidor web desatualizado pode conter várias vulnerabilidades, pois seu suporte teria sido encerrado. Um atacante pode aproveitar essa oportunidade para alavancar ataques."
							"It is highly recommended to upgrade the web server to the available latest version."],
					[46, "Hackers will be able to manipulate the URLs easily through a GET/POST request. They will be able to inject multiple attack vectors in the URL with ease and able to monitor the response as well",
							"By ensuring proper sanitization techniques and employing secure coding practices it will be impossible for the attacker to penetrate through. The following resource gives a detailed insight on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
					[47, "Since the attacker has knowledge about the particular type of backend the target is running, they will be able to launch a targetted exploit for the particular version. They may also try to authenticate with default credentials to get themselves through.",
							"Timely security patches for the backend has to be installed. Default credentials has to be changed. If possible, the banner information can be changed to mislead the attacker. The following resource gives more information on how to secure your backend. http://kb.bodhost.com/secure-database-server/"],
					[48, "Attackers may launch remote exploits to either crash the service or tools like ncrack to try brute-forcing the password on the target.",
							"It is recommended to block the service to outside world and made the service accessible only through the a set of allowed IPs only really neccessary. The following resource provides insights on the risks and as well as the steps to block the service. https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
					[49, "Hackers will be able to read community strings through the service and enumerate quite a bit of information from the target. Also, there are multiple Remote Code Execution and Denial of Service vulnerabilities related to SNMP services.",
							"Use a firewall to block the ports from the outside world. The following article gives wide insight on locking down SNMP service. https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
					[50, "Attackers will be able to find the logs and error information generated by the application. They will also be able to see the status codes that was generated on the application. By combining all these information, the attacker will be able to leverage an attack.",
							"By restricting access to the logger application from the outside world will be more than enough to mitigate this weakness."],
					[51, "Cyber Criminals mainly target this service as it is very easier for them to perform a remote attack by running exploits. WannaCry Ransomware is one such example.",
							"Exposing SMB Service to the outside world is a bad idea, it is recommended to install latest patches for the service in order not to get compromised. The following resource provides a detailed information on SMB Hardening concepts. https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
			]

#vul_remed_info('c',50)
#sys.exit(1)

# Tool Set
tools_precheck = [
					["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"], ["burpsuite"], ["wireshark"]
			     ]

# Shuffling Scan Order (starts)
scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
random.shuffle(scan_shuffle)
tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
tool = 0

# Run Test
runTest = 1

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

# Total Time Elapsed
rs_total_elapsed = 0

# Tool Pre Checker
rs_avail_tools = 0

# Checks Skipped
rs_skipped_checks = 0


if len(sys.argv) == 1 :
    logo()
    helper()
else:
    target = sys.argv[1].lower()


    if target == '--update' or target == '-u' or target == '--u':
    	logo()
        print "RapidScan is updating....Please wait.\n"
        spinner.start()
        # Checking internet connectivity first...
        rs_internet_availability = check_internet()
        if rs_internet_availability == 0:
            print "\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC
            spinner.stop()
            sys.exit(1)
        cmd = 'sha1sum rapidscan.py | grep .... | cut -c 1-40'
        oldversion_hash = subprocess.check_output(cmd, shell=True)
        oldversion_hash = oldversion_hash.strip()
        os.system('wget -N  -O rapidscan.py > /dev/null 2>&1')
        newversion_hash = subprocess.check_output(cmd, shell=True)
        newversion_hash = newversion_hash.strip()
        if oldversion_hash == newversion_hash :
            clear()
            print "\t"+ bcolors.OKBLUE +"You already have the latest version of RapidScan." + bcolors.ENDC
        else:
            clear()
            print "\t"+ bcolors.OKGREEN +"RapidScan successfully updated to the latest version." +bcolors.ENDC
        spinner.stop()
        sys.exit(1)

    elif target == '--help' or target == '-h' or target == '--h':
    	logo()
        helper()
        sys.exit(1)
    else:

        target = url_maker(target)
        os. sistema('rm te* > /dev/null 2>&1' ) # Limpando arquivos de varredura anteriores
        os. sistema('claro')
        os. sistema('setterm -cursor off')
        logotipo()
        imprimir bcolors. BG_HEAD_TXT+"[Verificando a fase das ferramentas de varredura de segurança disponíveis... Iniciado. ]"+bcolors. ENDC
        unavail_tools = 0
        unavail_tools_names = lista()
        enquanto (rs_avail_tools < len(tools_precheck)::
			precmd = str(tools_precheck[rs_avail_tools][arg1])
			tente:
				p = subprocesso. Popen([precmd], stdin=subprocesso. PIPE, stdout=subprocesso. PIPE, stderr=subprocesso. PIPE,shell=True)
				saída , err = p. comunicar()
				val = saída + err
			exceto:
				imprimir "\t"+bcolors. BG_ERR_TXT+"RapidScan foi encerrado abruptamente..."+bcolors. ENDC
				sys. saída(1)
			se "não encontrado" em val:
				imprimir "\t"+bcolors. OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors. ENDC+bcolors. BADFAIL+"... indisponível. +bcolors. ENDC
				para scanner_index, scanner_val em enumerado(tool_names):
					se scanner_val==  = tools_precheck[rs_avail_tools][arg1 ]:
						scanner_val=  0 # scanner incapacitante, pois não está disponível.
						unavail_tools_names. apêndice(tools_precheck[rs_avail_tools][arg1])
						unavail_tools = unavail_tools + 1
			outra coisa:
				imprimir "\t"+bcolors. OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors. ENDC+bcolors. OKGREEN+"... disponível. +bcolors. ENDC
			rs_avail_tools = rs_avail_tools + 1
			claro()
        unavail_tools_names = lista(conjunto(unavail_tools_names))
        se unavail_tools == 0:
        	imprimir "\t"+bcolors. OKGREEN+"Todas as ferramentas de digitalização estão disponíveis. Todas as verificações de vulnerabilidade serão realizadas pelo RapidScan." +bcolors. ENDC
        outra coisa:
        	imprimir "\t"+bcolors. AVISO+"Algumas dessas ferramentas "+bcolors. BADFAIL+str(unavail_tools_names)+bcolors. ENDC+bcolors. AVISO+" nãoestão disponíveis. O RapidScan ainda pode realizar testes excluindo essas ferramentas dos testes. Por favor, instale essas ferramentas para utilizar totalmente a funcionalidade do RapidScan." +bcolors. ENDC
        imprimir bcolors. BG_ENDL_TXT+"[Verificando a fase das ferramentas de varredura de segurança disponíveis... concluído. ]"+bcolors. ENDC
        imprimir "\n"
        imprimir bcolors. BG_HEAD_TXT+"[ Fase preliminar de varredura iniciada... Carregado "+str(tool_checks)+" verificações de vulnerabilidade. ]" +bcolors. ENDC
        #while (ferramenta < 1):
        enquanto(ferramenta < len(tool_names)):
            imprimir "["+tool_status[ferramenta][arg3]+tool_status[ ferramenta ][arg4]+"] Implantando "+str(ferramenta+1)+"/"+str(tool_checks)+" |" +bcolors. OKBLUE+tool_names[ferramenta][arg2]+bcolors. ENDC,
            se tool_names[ferramenta][arg4] == 0:
            	imprimir bcolors. AVISO+"... Ferramenta de digitalização Indisponível. Teste de pular automaticamente..." +bcolors. ENDC
		rs_skipped_checks = rs_skipped_checks + 1
            	tool = tool + 1
            	continue
            spinner.start()
            scan_start = time.time()
            temp_file = "temp_"+tool_names[tool][arg1]
            cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

            try:
                subprocess.check_output(cmd, shell=True)
            except KeyboardInterrupt:
                runTest = 0
            except:
                runTest = 1

            if runTest == 1:
                    spinner. parar()
                    scan_stop = tempo. tempo()
                    decorrido = scan_stop - scan_start
                    rs_total_elapsed = rs_total_elapsed + decorrido
                    imprimir bcolors. OKBLUE+"\b...Concluído em "+display_time(int(decorrido))+bcolors. ENDC+"\n"
                    claro()
                    rs_tool_output_file = aberto(temp_file). ler()
                    se tool_status[ferramenta][arg2] == 0:
                    	se tool_status[ferramenta][arg1]. menor() em rs_tool_output_file. menor():
                        	#print vul_info "\t"+ (tool_resp[ferramenta][arg2]) + bcolors. BADFAIL +" "+ tool_resp[ferramenta][arg1] + bcolors. ENDC
                        	vul_remed_info(ferramenta,tool_resp[ferramenta],tool_resp[ferramenta][arg3])
                        	rs_vul_list. apêndice(tool_names[ ferramenta ][arg1] +"*"+tool_names[ferramenta][arg2 ])
                    outra coisa:
                    	se houver(i em rs_tool_output_file para i em tool_status[ferramenta][arg6 ]):
                    		m = 1 # Isso não faz nada.
                    	outra coisa:
                        	#print vul_info "\t"+ (tool_resp[ferramenta][arg2]) + bcolors. BADFAIL +" "+ tool_resp[ferramenta][arg1] + bcolors. ENDC
                        	vul_remed_info(ferramenta,tool_resp[ferramenta],tool_resp[ferramenta][arg3])
                        	rs_vul_list. apêndice(tool_names[ ferramenta ][arg1] +"*"+tool_names[ferramenta][arg2 ])
            outra coisa:
                    runTest = 1
                    spinner. parar()
                    scan_stop = tempo. tempo()
                    decorrido = scan_stop - scan_start
                    rs_total_elapsed = rs_total_elapsed + decorrido
                    imprimir bcolors. OKBLUE+"\b\b\b\b... Interrompido em "+display_time(int(decorrido))+bcolors. ENDC+"\n"
                    claro()
                    imprimir "\t"+bcolors. AVISO + "Teste ignorado. Se apresentando em seguida. Pressione Ctrl+Z para sair do RapidScan." + bcolors. ENDC
                    rs_skipped_checks = rs_skipped_checks + 1

            ferramenta=ferramenta+1

        imprimir bcolors. BG_ENDL_TXT+"[Fase preliminar de varredura concluída]" +bcolors. ENDC
        imprimir "\n"

        ######################### ###########################
        imprimir bcolors. BG_HEAD_TXT+"[ Fase de Geração de Relatórios Iniciada]" +bcolors. ENDC
        se len(rs_vul_list)==0:
        	imprimir "\t"+bcolors. OKGREEN+"Sem vulnerabilidades detectadas.". +bcolors. ENDC
        outra coisa:
        	com aberto("RS-Vulnerability-Report", "a") como relatório:
        		enquanto(rs_vul < len(rs_vul_list)::
        			vuln_info = rs_vul_list[rs_vul]. divisão('*')
	        		relatório. escrever(vuln_info[arg2])
	        		relatório. escrever("\n------------------------\n\n")
	        		temp_report_name = "temp_"+vuln_info[arg1]
	        		com aberto(temp_report_name, 'r' ) como temp_report:
	    				dados = temp_report. ler()
	        			relatório. gravação(dados)
	        			relatório. escrever("\n\n")
	        		temp_report. fechar()
	       			rs_vul = rs_vul + 1

	       		imprimir "\tRelatório completo de vulnerabilidade para "+bcolors. OKBLUE+alvo+bcolors. ENDC+" nomeado"+bcolors. OKGREEN+"'RS-Vulnerability-Report'"+bcolors. ENDC+"está disponível sob o mesmo diretório que o RapidScan reside."

        	relatório. fechar()
        # Escrever todos os arquivos de varredura de saída em RS-Debug-ScanLog para fins de depuração.
        para file_index, file_name em enumerado(tool_names):
        	com aberto("RS-Debug-ScanLog", "a") como relatório:
        		tente:
	        		com aberto("temp_"+file_name[arg1], 'r') como temp_report:
		    				dados = temp_report. ler()
		    				relatório. escrever(file_name[arg2])
	        				relatório. escrever("\n------------------------\n\n")
		        			relatório. gravação(dados)
		        			relatório. escrever("\n\n")
		        	temp_report. fechar()
	        	exceto:
	        		quebrar
	        relatório. fechar()

        imprimir "\tNúmero Total de Verificações de Vulnerabilidade : "+bcolors. BOLD+bcolors. OKGREEN+str(len(tool_names))+bcolors. ENDC
        imprimir "\tNúmero Total de Verificações de Vulnerabilidade Pulado: "+bcolors. BOLD+bcolors. ATENÇÃO+str(rs_skipped_checks)+bcolors. ENDC
        imprimir "\tNúmero Total de Vulnerabilidades Detectadas : "+bcolors. BOLD+bcolors. BADFAIL+str(len(rs_vul_list))+bcolors. ENDC
        imprimir "\tTempo Total Decorrido para a Varredura : "+bcolors. BOLD+bcolors. OKBLUE+display_time(int(rs_total_elapsed))+bcolors. ENDC
        imprimir "\n"
        imprimir "\tPara Fins de Depuração, você pode visualizar a saída completa gerada por todas as ferramentas denominadas "+bcolors. OKBLUE+"'RS-Debug-ScanLog'"+bcolors. ENDC+" sob omesmo diretório."
        imprimir bcolors. BG_ENDL_TXT+"[ Fase de Geração de Relatórios Concluída]" +bcolors. ENDC

        os. sistema('setterm -cursor on')
        os. sistema('rm te* > /dev/null 2>&1' ) # Limpando arquivos de varredura anteriores
