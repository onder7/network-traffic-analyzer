

# Ağ Trafiği Analizi Aracı

Bu uygulama, ağ trafiğini izlemek ve analiz etmek için geliştirilmiş bir GUI (Grafiksel Kullanıcı Arayüzü) uygulamasıdır. Python ve `scapy` kütüphanesi kullanılarak geliştirilmiştir. Uygulama, ağ paketlerini yakalama, filtreleme, netstat çıktısını görüntüleme, ping atma ve MTU değerlerini görüntüleme gibi özellikler sunar.
![Uygulamayı indir](https://drive.google.com/file/d/1y-lvoveF79W4KuZhYKQQyUaMsAGrbFB3/view?usp=drive_link)

https://drive.google.com/file/d/1y-lvoveF79W4KuZhYKQQyUaMsAGrbFB3/view?usp=drive_link

![Ağ Trafiği Analizi Aracı](https://i.imgur.com/uSMJo4Z.jpg)

---

## Özellikler

- **Paket Yakalama**: Belirli bir ağ arayüzünden paketleri yakalar ve bu paketleri analiz eder.
- **Filtreleme**: TCP, UDP, ARP, ICMP, DNS gibi protokollere göre paketleri filtreler.
- **Netstat Çıktısı**: Ağ bağlantılarını görüntülemek için `netstat` komutunu çalıştırır ve çıktısını gösterir.
- **Ping Aracı**: Belirli bir IP adresi veya domain adresine ping atar ve sonuçları gösterir.
- **MTU Değerleri**: Ağ arayüzlerinin MTU (Maximum Transmission Unit) değerlerini görüntüler.

---

## Kurulum

### Gereksinimler

- Python 3.x
- `scapy` kütüphanesi
- `tkinter` (genellikle Python ile birlikte gelir)
- `pandas` (Excel kaydetme özelliği için, ancak bu özellik kaldırıldı)

### Kurulum Adımları

1. **Python'u Yükleyin**: Eğer bilgisayarınızda Python yüklü değilse, [Python'un resmi sitesinden](https://www.python.org/downloads/) indirip yükleyin.

2. **Gerekli Kütüphaneleri Yükleyin**:
   ```bash
   pip install scapy pandas
   ```

3. **Uygulamayı Çalıştırın**:
   ```bash
   python main.py
   ```

---

## Kullanım

### Arayüz Adı ve Filtreleme

- **Arayüz Adı**: Paket yakalamak istediğiniz ağ arayüzünün adını girin (örneğin, `eth0`, `wlan0`).
- **Filtre**: Listbox'tan protokolleri seçin (TCP, UDP, ARP, ICMP, DNS). Hiçbir şey seçilmezse tüm protokoller görüntülenir.
- **Yenileme Aralığı**: Paket yakalama işleminin kaç saniyede bir yenileneceğini belirtin.
- **Paket Sayısı**: Yakalanacak paket sayısını girin.

### Netstat Penceresi

- **Netstat Parametreleri**: Netstat komutuna eklemek istediğiniz parametreleri seçin (örneğin, `-a`, `-n`, `-o`).
- **Findstr Filtresi**: Netstat çıktısını belirli bir değere göre filtrelemek için kullanın (örneğin, `3389`).

### Ping Aracı

- **Ping Hedefi**: Ping atmak istediğiniz IP adresi veya domain adresini girin.
- **Ping Sayısı**: Kaç kez ping atılacağını belirtin (varsayılan: 4).
- **Paket Boyutu**: Ping paketlerinin boyutunu belirtin (varsayılan: 32 byte).

### MTU Değerleri

- **MTU Değerlerini Görüntüle**: Ağ arayüzlerinin MTU değerlerini görüntülemek için butona tıklayın.

---

## Ekran Görüntüleri

### Ana Pencere
[Imgur](https://i.imgur.com/Dxdn8mM.jpg)

### Netstat Penceresi
[Imgur](https://i.imgur.com/fExJa19.jpg)

### Ping Aracı
[Imgur](https://i.imgur.com/ngamgC8.jpg)
---
[Imgur](https://i.imgur.com/uSMJo4Z.jpg)
## Katkıda Bulunma

Eğer bu projeye katkıda bulunmak isterseniz, lütfen bir "Pull Request" açın. Katkılarınızı bekliyoruz!

---

## Lisans

Bu proje MIT Lisansı altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

---

## İletişim

- **Yazar**: Önder Aköz
- **E-posta**: onder7@gmail.com
- **GitHub**: [github.com/onder7](https://github.com/onder7)


