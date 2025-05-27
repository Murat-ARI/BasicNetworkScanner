import streamlit as st
import nmap
import pandas as pd
import ipaddress

st.set_page_config(
    page_title="Ağ Tarayıcı",
    layout="wide",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': None
    }
)

# Custom CSS: Sağ üst menüleri gizle, hamburger menü ve deploy'u kaldır
st.markdown("""
    <style>
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display: none !important;}
    .st-emotion-cache-1avcm0n {display: none !important;} /* Bazı deploy butonları için */
    </style>
""", unsafe_allow_html=True)

st.title("Basic Network Scanner")

# Servis açıklamaları sözlüğü
SERVICE_DESCRIPTIONS = {
    20: 'FTP veri aktarımı (şifreleme içermez).',
    21: 'FTP kontrol bağlantısı (şifreleme içermez).',
    22: 'SSH - Güvenli uzaktan bağlantı.',
    23: 'Telnet - Güvensiz uzaktan bağlantı.',
    25: 'SMTP - E-posta gönderimi.',
    53: 'DNS - Alan adı çözümleme.',
    67: 'DHCP - Sunucu tarafı IP dağıtımı.',
    68: 'DHCP - İstemci tarafı IP alımı.',
    69: 'TFTP - Basit ve güvensiz dosya aktarımı.',
    80: 'HTTP - Şifrelenmemiş web trafiği.',
    88: 'Kerberos - Kimlik doğrulama.',
    106: "Alternatif SMTP kimlik doğrulamalı e-posta gönderim portu",
    110: 'POP3 - E-postaları alma.',
    111: 'RPC - Uzak işlem çağrısı.',
    123: 'NTP - Ağ zamanı eşitleme.',
    135: 'Microsoft RPC - Uzak prosedür çağrısı.',
    139: 'NetBIOS - Dosya ve yazıcı paylaşımı.',
    143: 'IMAP - E-posta yönetimi.',
    161: 'SNMP - Ağ cihaz yönetimi.',
    162: 'SNMP Trap - Ağ cihaz bildirimi.',
    389: 'LDAP - Dizin hizmeti.',
    443: 'HTTPS - Güvenli web trafiği.',
    445: 'SMB - Dosya paylaşımı (Windows).',
    465: 'SMTPS - Güvenli e-posta gönderimi.',
    514: 'Syslog - Log toplama ve bildirimi.',
    587: 'SMTP - E-posta gönderimi (TLS destekli).',
    631: 'IPP - Ağ üzerinden yazdırma.',
    993: 'IMAPS - Güvenli IMAP erişimi.',
    995: 'POP3S - Güvenli POP3 erişimi.',
    1433: 'MSSQL - Microsoft SQL Server.',
    1521: 'Oracle - Oracle veritabanı erişimi.',
    1723: 'PPTP - VPN bağlantısı.',
    2375: 'Docker - Güvensiz API erişimi.',
    2376: 'Docker - TLS ile güvenli API.',
    27017: 'MongoDB - NoSQL veritabanı.',
    3000: 'Grafana - Gözlemleme arayüzü.',
    3306: 'MySQL - Veritabanı sunucusu.',
    3389: 'RDP - Uzak masaüstü bağlantısı.',
    5432: 'PostgreSQL - Veritabanı sunucusu.',
    5800: 'VNC web arayüzü.',
    5900: 'VNC - Uzak grafik masaüstü.',
    5901: 'VNC - Alternatif bağlantı.',
    5902: 'VNC - Alternatif bağlantı.',
    5984: 'CouchDB - REST tabanlı NoSQL veritabanı.',
    5985: 'WinRM - Windows uzaktan yönetimi.',
    5986: 'WinRM - TLS ile güvenli yönetim.',
    6379: 'Redis - Anahtar-değer önbellekleme sistemi.',
    6443: 'Kubernetes API sunucusu.',
    8000: 'HTTP alternatifi (test/geliştirme).',
    8080: 'HTTP alternatifi (test/geliştirme).',
    8443: 'HTTPS alternatifi (test/geliştirme).',
    8888: 'Jupyter / HTTP alternatif servisi.',
    9200: 'Elasticsearch - Veri arama ve indeksleme.',
    9999: 'Genel test / özel servis portu.',
    8009: 'AJP - Apache JServ Protocol (Tomcat bağlantısı için kullanılır).',
    49152: 'Dinamik/Geçici port aralığı başlangıcı (Windows RPC Dynamic).',
    49153: 'Windows RPC Dynamic portu.',
    49154: 'Windows RPC Dynamic portu.',
    49155: 'Windows RPC Dynamic portu.',
    49156: 'Windows RPC Dynamic portu.',
    49157: 'Windows RPC Dynamic portu.',
    
}



# Hızlı ağ tarama fonksiyonu (tek seferde, hızlı parametrelerle)
def fast_scan_network(target, timing):
    nm = nmap.PortScanner()
    try:
        # timing: T1-T5 arası kullanıcıdan alınacak (örn. 'T1')
        arguments = f'-{timing} -F -O'
        nm.scan(hosts=target, arguments=arguments)
    except Exception as e:
        st.error(f"Nmap taraması sırasında hata oluştu: {e}")
        return []
    results = []
    hosts = nm.all_hosts()
    progress = st.progress(0, text="Sonuçlar işleniyor...")
    total = len(hosts)
    for idx, host in enumerate(hosts):
        hostnames = nm[host].get('hostnames', [])
        hostname = hostnames[0]['name'] if hostnames and hostnames[0]['name'] else ''
        os_name = ''
        if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
            os_name = nm[host]['osmatch'][0]['name']
        # Cihaz adı mantığı: hostname > os_name > ip
        device_name = hostname if hostname else (os_name if os_name else host)
        host_info = {
            'ip': host,
            'mac': nm[host]['addresses'].get('mac', ''),
            'hostname': hostname,
            'os': os_name,
            'device_name': device_name,
            'ports': []
        }
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                port_info = nm[host][proto][port]
                service_name = port_info.get('name', '')
                # Hem port numarası hem de servis adı ile açıklama bul
                service_desc = SERVICE_DESCRIPTIONS.get(port, SERVICE_DESCRIPTIONS.get(service_name, 'Açıklama yok.'))
                host_info['ports'].append({
                    'port': port,
                    'state': port_info['state'],
                    'name': service_name,
                    'protocol': proto.upper(),
                    'desc': service_desc
                })
        results.append(host_info)
        progress.progress((idx+1)/total, text=f"{device_name} işlendi ({idx+1}/{total})")
    progress.empty()
    return results

# Kullanıcıdan IP aralığı ve tarama hızı al
st.sidebar.header("Ayarlar")
target = st.sidebar.text_input("Taramak istediğiniz IP aralığı (örn: 192.168.1.0/24)", "192.168.1.0/24")
timing = st.sidebar.selectbox(
    "Tarama Hızı (Timing)",
    options=[
        ("T1 (En Yavaş - Stealth)", "T1"),
        ("T2", "T2"),
        ("T3 (Varsayılan)", "T3"),
        ("T4 (Hızlı)", "T4"),
        ("T5 (En Hızlı)", "T5"),
    ],
    index=4,
    format_func=lambda x: x[0]
)[1]

# Tarama sırasında animasyon ve yazı sadece tarama süresince gösterilecek
results = None
show_wifi = False
if st.sidebar.button("Ağı Tara"):
    show_wifi = True
    wifi_svg = '''
    <div style="display: flex; flex-direction: column; align-items: center; margin-top: 40px;">
      <svg width="80" height="80" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <g>
          <circle cx="12" cy="20" r="1.5" fill="#4FC3F7">
            <animate attributeName="opacity" values="1;0.2;1" dur="1.2s" repeatCount="indefinite"/>
          </circle>
          <path d="M9 16.5C10.3333 15.5 13.6667 15.5 15 16.5" stroke="#4FC3F7" stroke-width="2" stroke-linecap="round">
            <animate attributeName="opacity" values="1;0.2;1" dur="1.2s" begin="0.2s" repeatCount="indefinite"/>
          </path>
          <path d="M6 13C9 11 15 11 18 13" stroke="#4FC3F7" stroke-width="2" stroke-linecap="round">
            <animate attributeName="opacity" values="1;0.2;1" dur="1.2s" begin="0.4s" repeatCount="indefinite"/>
          </path>
          <path d="M3 9C8 5 16 5 21 9" stroke="#4FC3F7" stroke-width="2" stroke-linecap="round">
            <animate attributeName="opacity" values="1;0.2;1" dur="1.2s" begin="0.6s" repeatCount="indefinite"/>
          </path>
        </g>
      </svg>
      <div style="margin-top: 16px; font-size: 1.2rem; color: #4FC3F7; font-weight: bold;">Ağ taranıyor, lütfen bekleyiniz...</div>
    </div>
    '''
    wifi_placeholder = st.empty()
    wifi_placeholder.markdown(wifi_svg, unsafe_allow_html=True)
    results = fast_scan_network(target, timing)
    wifi_placeholder.empty()  # Tarama bitince animasyonu kaldır
if results is not None:
    if not results:
        st.warning("Hiçbir cihaz bulunamadı veya tarama başarısız oldu.")
    else:
        st.success(f"{len(results)} cihaz bulundu!")
        for device in results:
            with st.expander(f"{device['device_name']} ({device['ip']})"):
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("IP Adresi", device['ip'])
                c2.metric("MAC Adresi", device['mac'])
                c3.metric("İşletim Sistemi", device['os'] if device['os'] else 'Bilinmiyor')
                c4.metric("Cihaz Adı", device['device_name'])
                st.markdown("**Açık Portlar:**")
                if device['ports']:
                    df = pd.DataFrame(device['ports'])
                    df = df[['port', 'protocol', 'state', 'name', 'desc']]
                    df.columns = ['Port', 'Protokol', 'Durum', 'Servis', 'Servis Açıklaması']
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("Açık port bulunamadı.")

st.sidebar.markdown("---")
# st.sidebar.info("Geliştirici: Basic Network Scanner | Python, Nmap, Streamlit")  # KALDIRILDI 