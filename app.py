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
                host_info['ports'].append({
                    'port': port,
                    'state': port_info['state'],
                    'name': port_info.get('name', ''),
                    'protocol': proto.upper()
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
                    df = df[['port', 'protocol', 'state', 'name']]
                    df.columns = ['Port', 'Protokol', 'Durum', 'Servis']
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("Açık port bulunamadı.")

st.sidebar.markdown("---")
# st.sidebar.info("Geliştirici: Basic Network Scanner | Python, Nmap, Streamlit")  # KALDIRILDI 