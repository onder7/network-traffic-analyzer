import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, Listbox, MULTIPLE, Toplevel, Entry, Label, Button
from scapy.all import sniff, ARP, Ether, TCP, UDP, IP, wrpcap, ICMP, DNS
import threading
import subprocess
import time
import os

# Global değişkenler
sniffing = False
sniff_thread = None
netstat_running = False
netstat_process = None

# Paket yakalama fonksiyonu
def start_sniffing():
    global sniffing, sniff_thread

    if sniffing:
        messagebox.showinfo("Bilgi", "Paket yakalama zaten başlatıldı.")
        return

    def sniff_packets():
        global sniffing
        try:
            interface = entry_interface.get()
            refresh_interval = int(entry_refresh.get())
            packet_count = int(entry_packet_count.get())  # Kullanıcıdan paket sayısını al
            if not interface:
                messagebox.showerror("Hata", "Arayüz adı girin!")
                return

            sniffing = True
            while sniffing:
                # Seçilen protokolleri al
                selected_protocols = listbox_protocols.curselection()
                filter_expression = " or ".join([listbox_protocols.get(i) for i in selected_protocols]) if selected_protocols else ""

                # Paket yakalama işlemi
                packets = sniff(iface=interface, prn=process_packet, count=packet_count, filter=filter_expression, timeout=10)  # 10 saniye zaman aşımı
                text_output.insert(tk.END, "Paket yakalama tamamlandı.\n")
                time.sleep(refresh_interval)  # Belirli bir süre bekleyerek yenile
        except Exception as e:
            messagebox.showerror("Hata", f"Paket yakalama sırasında bir hata oluştu: {e}")
        finally:
            sniffing = False

    # Paket yakalamayı ayrı bir thread'de başlat
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True  # Arka planda çalıştır
    sniff_thread.start()

# Paket yakalamayı durdurma fonksiyonu
def stop_sniffing():
    global sniffing
    sniffing = False
    messagebox.showinfo("Bilgi", "Paket yakalama durduruldu.")

# Paket işleme fonksiyonu
def process_packet(packet):
    if packet.haslayer(ARP):
        text_output.insert(tk.END, f"ARP Paketi: {packet.summary()}\n")
    elif packet.haslayer(Ether):
        if packet.haslayer(TCP):
            text_output.insert(tk.END, f"TCP Paketi: {packet.summary()}\n")
        elif packet.haslayer(UDP):
            text_output.insert(tk.END, f"UDP Paketi: {packet.summary()}\n")
        elif packet.haslayer(ICMP):
            text_output.insert(tk.END, f"ICMP Paketi: {packet.summary()}\n")
        elif packet.haslayer(DNS):
            text_output.insert(tk.END, f"DNS Paketi: {packet.summary()}\n")
        else:
            text_output.insert(tk.END, f"Ethernet Paketi: {packet.summary()}\n")
    text_output.see(tk.END)  # Otomatik kaydırma

# Netstat için ayrı pencere açma fonksiyonu
def open_netstat_window():
    netstat_window = Toplevel(root)
    netstat_window.title("Netstat Çıktısı")
    netstat_window.geometry("600x400")

    # Netstat parametreleri için Listbox
    label_netstat_params = Label(netstat_window, text="Netstat Parametreleri:")
    label_netstat_params.pack(pady=5)
    listbox_netstat_params = Listbox(netstat_window, selectmode=MULTIPLE, width=30, height=5)
    listbox_netstat_params.pack(pady=5)
    for param in ["-a", "-n", "-o", "-b", "-e"]:
        listbox_netstat_params.insert(tk.END, param)

    # Findstr filtresi için giriş alanı
    label_findstr = Label(netstat_window, text="Findstr Filtresi (örneğin, 3389):")
    label_findstr.pack(pady=5)
    entry_findstr = Entry(netstat_window, width=30)
    entry_findstr.pack(pady=5)

    # Netstat çıktısını göstermek için ScrolledText
    netstat_output = scrolledtext.ScrolledText(netstat_window, width=80, height=20)
    netstat_output.pack(padx=10, pady=10)

    # Netstat'ı başlatma fonksiyonu
    def start_netstat():
        global netstat_running, netstat_process
        if netstat_running:
            messagebox.showinfo("Bilgi", "Netstat zaten çalışıyor.")
            return

        try:
            # Seçilen parametreleri al
            selected_params = listbox_netstat_params.curselection()
            params = " ".join([listbox_netstat_params.get(i) for i in selected_params])

            # Findstr filtresini al
            findstr_filter = entry_findstr.get()

            # Netstat komutunu oluştur
            command = ["netstat"] + params.split()
            if findstr_filter:
                command += ["|", "findstr", findstr_filter]

            # Komutu çalıştır ve çıktıyı al
            netstat_process = subprocess.Popen(" ".join(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
            netstat_running = True

            # Çıktıyı okuma ve gösterme
            def read_netstat_output():
                while netstat_running:
                    output = netstat_process.stdout.readline()
                    if output:
                        netstat_output.insert(tk.END, output)
                        netstat_output.see(tk.END)
                    else:
                        break

            # Netstat çıktısını okumak için ayrı bir thread
            threading.Thread(target=read_netstat_output, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Hata", f"Netstat komutu çalıştırılırken bir hata oluştu: {e}")

    # Netstat'ı durdurma fonksiyonu
    def stop_netstat():
        global netstat_running, netstat_process
        if netstat_process:
            netstat_process.terminate()
            netstat_running = False
            messagebox.showinfo("Bilgi", "Netstat durduruldu.")

    # Netstat'ı başlat butonu
    button_start_netstat = Button(netstat_window, text="Netstat Başlat", command=start_netstat)
    button_start_netstat.pack(pady=5)

    # Netstat'ı durdur butonu
    button_stop_netstat = Button(netstat_window, text="Netstat Durdur", command=stop_netstat)
    button_stop_netstat.pack(pady=5)

    # Pencere kapatıldığında thread'i durdur
    def on_closing():
        global netstat_running
        netstat_running = False
        if netstat_process:
            netstat_process.terminate()
        netstat_window.destroy()

    netstat_window.protocol("WM_DELETE_WINDOW", on_closing)

# Ping aracı için ayrı pencere açma fonksiyonu
def open_ping_window():
    ping_window = Toplevel(root)
    ping_window.title("Ping Aracı")
    ping_window.geometry("400x300")

    # Ping hedefi için giriş alanı
    label_ping_target = Label(ping_window, text="Ping Hedefi (IP veya Domain):")
    label_ping_target.pack(pady=5)
    entry_ping_target = Entry(ping_window, width=30)
    entry_ping_target.pack(pady=5)

    # Ping sayısı için giriş alanı
    label_ping_count = Label(ping_window, text="Ping Sayısı (varsayılan: 4):")
    label_ping_count.pack(pady=5)
    entry_ping_count = Entry(ping_window, width=30)
    entry_ping_count.pack(pady=5)

    # Paket boyutu için giriş alanı
    label_packet_size = Label(ping_window, text="Paket Boyutu (varsayılan: 32):")
    label_packet_size.pack(pady=5)
    entry_packet_size = Entry(ping_window, width=30)
    entry_packet_size.pack(pady=5)

    # Ping çıktısını göstermek için ScrolledText
    ping_output = scrolledtext.ScrolledText(ping_window, width=50, height=10)
    ping_output.pack(padx=10, pady=10)

    # Ping işlemini başlatma fonksiyonu
    def start_ping():
        target = entry_ping_target.get()
        if not target:
            messagebox.showerror("Hata", "Ping hedefi girin!")
            return

        # Ping sayısı ve paket boyutu
        ping_count = entry_ping_count.get() or "4"
        packet_size = entry_packet_size.get() or "32"

        try:
            # Ping komutunu çalıştır
            command = ["ping", target, "-n", ping_count, "-l", packet_size]
            result = subprocess.run(command, capture_output=True, text=True)
            ping_output.insert(tk.END, result.stdout)
            ping_output.see(tk.END)  # Otomatik kaydırma
        except Exception as e:
            messagebox.showerror("Hata", f"Ping işlemi sırasında bir hata oluştu: {e}")

    # Ping başlat butonu
    button_start_ping = Button(ping_window, text="Ping Başlat", command=start_ping)
    button_start_ping.pack(pady=5)

# MTU değerlerini görüntüleme fonksiyonu
def show_mtu():
    try:
        # MTU değerlerini almak için komut çalıştır
        result = subprocess.run(["netsh", "interface", "ipv4", "show", "interfaces"], capture_output=True, text=True)
        messagebox.showinfo("MTU Değerleri", result.stdout)
    except Exception as e:
        messagebox.showerror("Hata", f"MTU değerleri alınırken bir hata oluştu: {e}")

# Hakkında penceresi
def show_about():
    about_text = """
    Ağ Trafiği Analizi Aracı

    Yazar: Önder Aköz
    E-posta: onder7@gmail.com
    GitHub: github.com/onder7

    Bu uygulama, ağ trafiğini izlemek ve analiz etmek için geliştirilmiştir.
    """
    messagebox.showinfo("Hakkında", about_text)

# Yardım penceresi
def show_help():
    help_text = """
    Ağ Trafiği Analizi Aracı Kullanım Kılavuzu

    1. Arayüz Adı: Paket yakalamak istediğiniz ağ arayüzünün adını girin (örneğin, eth0, wlan0).
    2. Filtre: Listbox'tan protokolleri seçin (TCP, UDP, ARP, ICMP, DNS). Hiçbir şey seçilmezse tüm protokoller görüntülenir.
    3. Yenileme Aralığı: Paket yakalama işleminin kaç saniyede bir yenileneceğini belirtin.
    4. Paket Sayısı: Yakalanacak paket sayısını girin.
    5. Paket Yakala: Belirtilen arayüzdeki ağ trafiğini yakalamaya başlar.
    6. Paket Yakalamayı Durdur: Paket yakalamayı durdurur.
    7. Çıktı: Yakalanan paketler bu alanda gösterilir.
    8. Netstat Penceresi: Ağ bağlantılarını görüntülemek için netstat komutunu çalıştırın.
    9. Ping Aracı: Bir IP veya domain adresine ping atın.
    10. MTU Değerleri: Ağ arayüzlerinin MTU değerlerini görüntüleyin.
    """
    messagebox.showinfo("Yardım", help_text)

# GUI oluştur
root = tk.Tk()
root.title("Ağ Trafiği Analizi Aracı")
root.geometry("800x600")

# Menü çubuğu oluştur
menu_bar = tk.Menu(root)

# Yardım menüsü
help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="Yardım", command=show_help)
help_menu.add_command(label="Hakkında", command=show_about)
menu_bar.add_cascade(label="Yardım", menu=help_menu)

# Menü çubuğunu pencereye ekle
root.config(menu=menu_bar)

# Butonları üst kısma taşıma
button_frame = tk.Frame(root)
button_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

# Paket Yakala Butonu
button_start = tk.Button(button_frame, text="Paket Yakala", command=start_sniffing)
button_start.pack(side=tk.LEFT, padx=5)

# Paket Yakalamayı Durdur Butonu
button_stop = tk.Button(button_frame, text="Paket Yakalamayı Durdur", command=stop_sniffing)
button_stop.pack(side=tk.LEFT, padx=5)

# Netstat Penceresini Aç Butonu
button_netstat = tk.Button(button_frame, text="Netstat Penceresi", command=open_netstat_window)
button_netstat.pack(side=tk.LEFT, padx=5)

# Ping Aracı Butonu
button_ping = tk.Button(button_frame, text="Ping Aracı", command=open_ping_window)
button_ping.pack(side=tk.LEFT, padx=5)

# MTU Değerlerini Görüntüle Butonu
button_mtu = tk.Button(button_frame, text="MTU Değerleri", command=show_mtu)
button_mtu.pack(side=tk.LEFT, padx=5)

# Arayüz Adı Girişi
label_interface = tk.Label(root, text="Arayüz Adı:")
label_interface.grid(row=1, column=0, padx=10, pady=10, sticky="w")
entry_interface = tk.Entry(root, width=30)
entry_interface.grid(row=1, column=1, padx=10, pady=10, sticky="w")

# Filtre Listbox
label_filter = tk.Label(root, text="Filtre (Protokoller):")
label_filter.grid(row=2, column=0, padx=10, pady=10, sticky="w")
listbox_protocols = Listbox(root, selectmode=MULTIPLE, width=30, height=10)
listbox_protocols.grid(row=2, column=1, padx=10, pady=10, sticky="w")
for protocol in ["tcp", "udp", "arp", "icmp", "dns", "http", "https"]:
    listbox_protocols.insert(tk.END, protocol)

# Yenileme Aralığı Girişi
label_refresh = tk.Label(root, text="Yenileme Aralığı (saniye):")
label_refresh.grid(row=3, column=0, padx=10, pady=10, sticky="w")
entry_refresh = tk.Entry(root, width=30)
entry_refresh.grid(row=3, column=1, padx=10, pady=10, sticky="w")

# Paket Sayısı Girişi
label_packet_count = tk.Label(root, text="Paket Sayısı:")
label_packet_count.grid(row=4, column=0, padx=10, pady=10, sticky="w")
entry_packet_count = tk.Entry(root, width=30)
entry_packet_count.grid(row=4, column=1, padx=10, pady=10, sticky="w")

# Çıktı Alanı
text_output = scrolledtext.ScrolledText(root, width=90, height=20)
text_output.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

# Uygulamayı çalıştır
root.mainloop()