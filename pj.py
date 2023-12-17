from scapy.all import sniff
from scapy.arch import get_if_list

# Ağ trafiğini dosyaya yazmak için bir fonksiyon
def paketleri_yaz(paket):
    with open("ag_trafigi.txt", "a") as dosya:  # "a" ile dosyayı eklemeye aç
        dosya.write(str(paket.summary()) + "\n")  # Paket özetini dosyaya yaz

# Önce ağ arayüzlerini listeleyelim
print(get_if_list())

# Belirli bir arayüzdeki ("wlan0") ağ trafiğini dinle ve dosyaya yaz
dinleyici = sniff(iface="wlan0", prn=paketleri_yaz, count=10)  # İlk 10 paketi dinle
