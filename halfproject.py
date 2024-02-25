import subprocess
import platform
import re
import socket
import sys
import time
import requests
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def ping(host, count=4):
    if platform.system().lower() == "windows":
        ping_cmd = ["ping", "-n", str(count), host]
    else:
        ping_cmd = ["ping", "-c", str(count), host]
    
    try:
        output = subprocess.check_output(ping_cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        return output, "Başarılı"
    except subprocess.CalledProcessError as e:
        return e.output, "Hata"

def validate_ip(ip):
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(ip_regex, ip) is not None

def scan_ports(host):
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        115: "SFTP",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",      
        8080: "HTTP-Alt", 
        3306: "MySQL",    
        5432: "PostgreSQL",  
        5900: "VNC",      
        5901: "VNC-Alt",  
        6379: "Redis",    
        27017: "MongoDB", 
        1521: "Oracle",   
        3300: "RetroShare"
    }
    
    open_ports = []
    for port, service in services.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((host, port))
                open_ports.append((port, service))
        except (socket.timeout, ConnectionRefusedError):
            pass
    
    if open_ports:
        return open_ports, "Başarılı"
    else:
        return [], "Başarılı"

def detect_waf(url):
    try:
        response = requests.get(url)
        
        headers = response.headers
        if 'Server' in headers:
            server_header = headers['Server']
            if 'WAF' in server_header:
                print("WAF tespit edildi!")
                print(f"WAF türü: {server_header}")
                return "WAF tespit edildi! WAF türü: {server_header}", "Başarılı"
        
        if response.status_code == 403:
            print("WAF tespit edildi!")
            print("WAF türü: ModSecurity")
            return "WAF tespit edildi! WAF türü: ModSecurity", "Başarılı"
        
        if 'Cloudflare' in response.text:
            print("WAF tespit edildi!")
            print("WAF türü: Cloudflare")
            return "WAF tespit edildi! WAF türü: Cloudflare", "Başarılı"
        
        return "WAF algılanamadı.", "Başarılı"
    except Exception as e:
        return f"Bir hata oluştu: {e}", "Hata"

def check_ssl_tls(url):
    try:
        
        host = url.split("://")[1].split("/")[0]
        port = 443  

        
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                
                cert = ssock.getpeercert(binary_form=True)

        
        cert_obj = x509.load_der_x509_certificate(cert, default_backend())

        
        subject = cert_obj.subject.rfc4514_string()
        issuer = cert_obj.issuer.rfc4514_string()
        signature_algorithm = cert_obj.signature_algorithm_oid._name
        not_before = cert_obj.not_valid_before
        not_after = cert_obj.not_valid_after

        
        result = (
            f"Bu web sitesinde SSL/TLS sertifikası bulunuyor.\n"
            f"Sertifika bilgileri:\n"
            f"Konu (Subject): {subject}\n"
            f"Düzenleyen (Issuer): {issuer}\n"
            f"İmza Hash Algoritması: {signature_algorithm}\n"
            f"Geçerlilik Başlangıcı (Valid From): {not_before}\n"
            f"Geçerlilik Bitişi (Valid Until): {not_after}"
        )
        return result, "Başarılı"

    except Exception as e:
        return f"Bir hata oluştu: {e}", "Hata"

def log_activity(activity, status, details=""):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with open("activity_log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] {activity}: {status}\n{details}\n")

if __name__ == "__main__":
    while True:
        start_time = time.time()  
        
        print(r'''
                                                                                                             
88888888ba     ,ad8888ba,   888888888888             ad888888b,     ,a8888a,      ad888888b,          ,d8    
88      "8b   d8"'    `"8b       88                 d8"     "88   ,8P"'  `"Y8,   d8"     "88        ,d888    
88      ,8P  d8'                 88                         a8P  ,8P        Y8,          a8P      ,d8" 88    
88aaaaaa8P'  88                  88                      ,d8P"   88          88       ,d8P"     ,d8"   88    
88""""""8b,  88      88888       88       aaaaaaaa     a8P"      88          88     a8P"      ,d8"     88    
88      `8b  Y8,        88       88       """"""""   a8P'        `8b        d8'   a8P'        8888888888888  
88      a8P   Y8a.    .a88       88                 d8"           `8ba,  ,ad8'   d8"                   88    
88888888P"     `"Y88888P"        88                 88888888888     "Y8888P"     88888888888           88    
                                                                                                                                                                                                                                                                                                     
''')
        print("Hazırlayan: Muhammed Enes YAZICI\nÖğrenci No: 2240011016\n")
        print("1. Ping atma")
        print("2. Port tarama")
        print("3. IP adresi öğrenme")
        print("4. WAF Türü öğrenme")
        print("5. SSL/TLS sertifikası kontrolü")
        print("6. Çıkış")
        choice = input("Lütfen bir seçenek seçin (1/2/3/4/5/6): ")

        if choice == "1":
            host = input("Ping atmak istediğiniz IP adresini veya alan adını girin: ")
            if not validate_ip(host):
                print("Geçersiz IP adresi veya alan adı.")
                continue
            result, status = ping(host)
            print(result)
            log_activity("Ping işlemi başlatıldı", status, f"Hedef: {host}, Paket Sayısı: 4")
            log_activity("Ping işlemi tamamlandı", status, result)
        elif choice == "2":
            host = input("Port taraması yapmak istediğiniz IP adresini veya alan adını girin: ")
            if not validate_ip(host):
                print("Geçersiz IP adresi veya alan adı.")
                continue
            open_ports, status = scan_ports(host)
            if open_ports:
                print("Açık portlar:")
                for port, service in open_ports:
                    print(f"{port} portu açık, {service} hizmeti çalışıyor.")
                    log_activity("Açık port bulundu", status, f"Hedef: {host}, Port: {port}, Servis: {service}")
            else:
                print("Belirtilen port aralığında açık port bulunamadı.")
            log_activity("Port taraması başlatıldı", status, f"Hedef: {host}")
        elif choice == "3":
            hostname = input("IP adresini öğrenmek istediğiniz hostun adını girin: ")
            ip_address = socket.gethostbyname(hostname)
            print(f"{hostname} hostunun IP adresi: {ip_address}")
            log_activity("IP adresi öğrenme işlemi başlatıldı", "Başarılı", f"Hedef: {hostname}")
            log_activity("IP adresi öğrenme işlemi tamamlandı", "Başarılı", f"IP adresi: {ip_address}")
        elif choice == "4":
            target_url = input("WAF varlığını kontrol etmek istediğiniz web sitesinin URL'sini girin: ")
            result, status = detect_waf(target_url)
            print(result)
            log_activity("WAF Türü öğrenme işlemi başlatıldı", status, f"URL: {target_url}")
            log_activity("WAF Türü öğrenme işlemi tamamlandı", status, result)
        elif choice == "5":
            website_url = input("SSL/TLS sertifikasını kontrol etmek istediğiniz web sitesinin URL'sini girin: ")
            result, status = check_ssl_tls(website_url)
            print(result)
            log_activity("SSL/TLS sertifikası kontrolü başlatıldı", status, f"URL: {website_url}")
            log_activity("SSL/TLS sertifikası kontrolü tamamlandı", status, result)
        elif choice == "6":
            print("Programdan çıkılıyor...")
            log_activity("Program sonlandırıldı", "Başarılı")
            break
        else:
            print("Geçersiz seçenek.")
        
        end_time = time.time()  
        elapsed_time = end_time - start_time  
        print(f"\nKod çalışma süresi: {elapsed_time:.2f} saniye")
